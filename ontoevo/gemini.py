# -*- coding: utf-8 -*-
"""
gemini.py - adaptador unico para a API Gemini (SDK oficial google-genai, Interactions API).

Documentacao seguida (consultada em 2026-11-03):
  * Interactions API e a interface recomendada; generateContent e legado.
  * Saida estruturada: response_format={"type": "text", "mime_type": "application/json", "schema": ...}.
    So um subconjunto do JSON Schema e suportado; minLength/maxLength/uniqueItems... sao descartados
    sem aviso -> o esquema enviado e "limpo" (to_gemini_schema) e a resposta e SEMPRE validada
    localmente com o modelo Pydantic completo (padroes CVE/CWE/ATT&CK, limites, enums).
  * Function calling: declaracoes {"type": "function", name, description, parameters}; o modelo nao
    executa nada - a aplicacao executa e devolve {"type": "function_result", call_id, result} com
    previous_interaction_id. Modos de tool_choice: auto, any, none, validated. 10-20 ferramentas no maximo.
  * As "thought signatures" sao tratadas pelo SDK quando se encadeia por previous_interaction_id.

Reprodutibilidade: cada pedido e identificado pelo SHA-256 do JSON canonico do pedido; a resposta
normalizada fica em cache/gemini/<sha>.json e cada chamada e registada em cache/gemini/calls.jsonl.
Modos:  live    chama sempre a API e regrava a cache
        cached  usa a cache se existir; senao chama a API (padrao)
        replay  so cache; falta de cache -> GeminiUnavailable (testes e CI sem rede nem chave)

Seguranca: o texto que chega ao modelo (descricoes de CVE, notas do KEV, avisos) e dado nao confiavel.
As ferramentas expostas ao modelo sao de LEITURA; nenhuma escreve na ontologia. As alteracoes saem
como propostas JSON que passam pelo compilador, pelo portao e por aprovacao humana.
"""
import copy
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field

from pydantic import BaseModel, ValidationError

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(HERE, "cache", "gemini")
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")


class GeminiError(RuntimeError):
    pass


class GeminiUnavailable(GeminiError):
    """Sem chave/SDK (modo live/cached) ou sem a resposta em cache (modo replay)."""


@dataclass
class Turn:
    """Resposta normalizada (independente da versao do SDK)."""
    interaction_id: str
    output_text: str = None
    function_calls: list = field(default_factory=list)   # [{"id", "name", "arguments"}]
    model: str = None
    usage: dict = None


# ------------------------------------------------------------------ esquema
_DROP = {"pattern", "minLength", "maxLength", "minProperties", "maxProperties", "uniqueItems", "contains",
         "minContains", "maxContains", "default", "examples", "const", "exclusiveMinimum", "exclusiveMaximum",
         "multipleOf", "discriminator"}
_FORMATS = {"date-time", "date", "time"}


def to_gemini_schema(schema):
    """JSON Schema do Pydantic -> subconjunto aceite pelo Gemini: resolve $ref/$defs em linha (os
    nossos modelos nao sao recursivos), retira palavras-chave nao suportadas e formatos fora de
    date-time/date/time, e converte anyOf [X, null] em type [..., "null"]. A validacao completa
    continua a ser feita localmente pelo Pydantic."""
    defs = schema.get("$defs", {})

    def walk(node, depth=0):
        if depth > 40:
            raise GeminiError("esquema demasiado profundo (referencia circular?)")
        if isinstance(node, list):
            return [walk(x, depth + 1) for x in node]
        if not isinstance(node, dict):
            return node
        if "$ref" in node:
            name = node["$ref"].split("/")[-1]
            merged = dict(defs[name])
            merged.update({k: v for k, v in node.items() if k != "$ref"})
            return walk(merged, depth + 1)
        out = {}
        for k, v in node.items():
            if k in _DROP or k == "$defs" or k == "title":
                continue
            if k == "format" and v not in _FORMATS:
                continue
            out[k] = walk(v, depth + 1)
        any_of = out.get("anyOf")
        if any_of and len(any_of) == 2 and {"type": "null"} in any_of:
            other = next(x for x in any_of if x != {"type": "null"})
            if "type" in other and isinstance(other["type"], str):
                out.pop("anyOf")
                merged = dict(other)
                merged["type"] = [other["type"], "null"]
                merged.update({k: v for k, v in out.items() if k not in merged})
                out = merged
        return out

    return walk(copy.deepcopy(schema))


# ------------------------------------------------------------------ transportes
class LiveTransport:
    """Chamada real a API. A chave vem de GEMINI_API_KEY (ou GOOGLE_API_KEY)."""

    def __init__(self, api_key=None):
        key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            raise GeminiUnavailable("GEMINI_API_KEY nao definida")
        try:
            from google import genai
        except ImportError as e:  # pragma: no cover
            raise GeminiUnavailable("pacote google-genai nao instalado (pip install google-genai)") from e
        self.client = genai.Client(api_key=key)

    @staticmethod
    def normalize(it, model=None):
        calls = [{"id": s.id, "name": s.name, "arguments": dict(s.arguments or {})}
                 for s in (it.steps or []) if getattr(s, "type", None) == "function_call"]
        usage = it.usage.model_dump(exclude_none=True) if getattr(it, "usage", None) is not None else None
        return Turn(interaction_id=it.id or "", output_text=it.output_text, function_calls=calls,
                    model=str(getattr(it, "model", None) or model), usage=usage)

    def create(self, request):
        from google.genai import errors
        last = None
        for attempt in range(4):
            try:
                return self.normalize(self.client.interactions.create(**request), request.get("model"))
            except errors.APIError as e:
                last = e
                if getattr(e, "code", None) in (429, 500, 503) and attempt < 3:
                    time.sleep(2 ** attempt * 5)
                    continue
                raise GeminiError("Gemini API %s: %s" % (getattr(e, "code", "?"), e)) from e
        raise GeminiError(str(last))


class ScriptedTransport:
    """Respostas pre-definidas (testes): devolve os Turn pela ordem e guarda os pedidos recebidos."""

    def __init__(self, turns):
        self.turns = [t if isinstance(t, Turn) else Turn(**t) for t in turns]
        self.requests = []

    def create(self, request):
        self.requests.append(copy.deepcopy(request))
        if not self.turns:
            raise GeminiError("ScriptedTransport sem mais respostas")
        return self.turns.pop(0)


# ------------------------------------------------------------------ ferramentas
@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    fn: object

    def declaration(self):
        return {"type": "function", "name": self.name, "description": self.description,
                "parameters": self.parameters}


# ------------------------------------------------------------------ cliente
class GeminiClient:
    def __init__(self, model=None, mode=None, cache_dir=None, transport=None, temperature=0.0, seed=7,
                 api_key=None):
        self.model = model or DEFAULT_MODEL
        self.mode = mode or os.environ.get("ONTOCSIRT_GEMINI_MODE", "cached")
        if self.mode not in ("live", "cached", "replay"):
            raise ValueError("modo invalido: %s" % self.mode)
        self.cache_dir = cache_dir or CACHE_DIR
        self.temperature, self.seed = temperature, seed
        self._transport, self._api_key = transport, api_key
        self.calls = []                                    # registo desta sessao

    # -- transporte e cache
    def transport(self):
        if self._transport is None:
            self._transport = LiveTransport(self._api_key)
        return self._transport

    @staticmethod
    def key(request):
        return hashlib.sha256(json.dumps(request, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

    def _call(self, request, purpose):
        k = self.key(request)
        path = os.path.join(self.cache_dir, k + ".json")
        hit = False
        if self.mode != "live" and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                turn = Turn(**json.load(f)["response"])
            hit = True
        elif self.mode == "replay":
            raise GeminiUnavailable("replay: resposta ausente da cache (%s, %s)" % (purpose, k[:12]))
        else:
            t0 = time.time()
            turn = self.transport().create(request)
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"key": k, "purpose": purpose, "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                           "seconds": round(time.time() - t0, 2), "request": request, "response": asdict(turn)},
                          f, ensure_ascii=False, indent=1)
        entry = {"key": k, "purpose": purpose, "model": request.get("model"), "mode": self.mode, "cache_hit": hit,
                 "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "usage": turn.usage}
        self.calls.append(entry)
        if not hit:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(os.path.join(self.cache_dir, "calls.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return turn

    def _gen_config(self, **extra):
        cfg = {"temperature": self.temperature, "seed": self.seed}
        cfg.update(extra)
        return cfg

    @staticmethod
    def _response_format(schema_model):
        return {"type": "text", "mime_type": "application/json",
                "schema": to_gemini_schema(schema_model.model_json_schema())}

    def _parse(self, turn, schema_model):
        if not turn.output_text:
            raise ValueError("resposta sem texto")
        return schema_model.model_validate_json(turn.output_text)

    def _with_repair(self, turn, schema_model, base_request, purpose):
        """Valida a resposta; se falhar, devolve o erro ao modelo UMA vez (mesma interacao) e revalida."""
        try:
            return self._parse(turn, schema_model), turn
        except (ValidationError, ValueError) as e:
            err = str(e)[:2000]
        req = {k: v for k, v in base_request.items() if k not in ("input", "system_instruction")}
        req["previous_interaction_id"] = turn.interaction_id
        req["input"] = ("A resposta anterior nao valida o esquema exigido. Erros:\n%s\n"
                        "Responda de novo apenas com o JSON corrigido." % err)
        turn2 = self._call(req, purpose + ":repair")
        try:
            return self._parse(turn2, schema_model), turn2
        except (ValidationError, ValueError) as e:
            raise GeminiError("resposta invalida apos uma correcao: %s" % str(e)[:500]) from e

    # -- API publica
    def generate_json(self, prompt, schema_model, system=None, purpose="generate_json"):
        """Saida estruturada numa so chamada. Devolve (instancia Pydantic validada, metadados)."""
        if not (isinstance(schema_model, type) and issubclass(schema_model, BaseModel)):
            raise TypeError("schema_model deve ser uma classe Pydantic")
        request = {"model": self.model, "input": prompt, "response_format": self._response_format(schema_model),
                   "generation_config": self._gen_config()}
        if system:
            request["system_instruction"] = system
        turn = self._call(request, purpose)
        obj, last = self._with_repair(turn, schema_model, request, purpose)
        return obj, {"model": last.model or self.model, "interaction_id": last.interaction_id,
                     "cache_key": self.calls[-1]["key"], "calls": len(self.calls)}

    def run_tools(self, prompt, tools, final_schema, system=None, max_steps=8, purpose="run_tools",
                  tool_choice="auto"):
        """Ciclo de function calling: o modelo pede ferramentas (so leitura), a aplicacao executa e
        devolve os resultados; no fim pede-se a resposta final no esquema final_schema.
        Devolve (instancia validada, trace) - o trace guarda cada chamada de ferramenta e o resultado."""
        registry = {t.name: t for t in tools}
        decls = [t.declaration() for t in tools]
        request = {"model": self.model, "input": prompt, "tools": decls,
                   "generation_config": self._gen_config(tool_choice=tool_choice)}
        if system:
            request["system_instruction"] = system
        turn = self._call(request, purpose + ":step0")
        trace = []
        for step in range(1, max_steps + 1):
            if not turn.function_calls:
                break
            results = []
            for fc in turn.function_calls:
                tool = registry.get(fc["name"])
                if tool is None:
                    out, is_err = {"error": "ferramenta desconhecida: %s" % fc["name"]}, True
                else:
                    try:
                        out, is_err = tool.fn(**(fc.get("arguments") or {})), False
                    except Exception as e:  # noqa: BLE001  (o erro volta ao modelo, nao derruba o ciclo)
                        out, is_err = {"error": "%s: %s" % (type(e).__name__, e)}, True
                text = json.dumps(out, ensure_ascii=False, default=str)
                if len(text) > 30000:
                    text = text[:30000] + "...(truncado)"
                trace.append({"step": step, "tool": fc["name"], "arguments": fc.get("arguments"), "is_error": is_err,
                              "result_preview": text[:500]})
                results.append({"type": "function_result", "name": fc["name"], "call_id": fc["id"],
                                "result": [{"type": "text", "text": text}], "is_error": is_err})
            req = {"model": self.model, "input": results, "tools": decls,
                   "previous_interaction_id": turn.interaction_id,
                   "generation_config": self._gen_config(tool_choice=tool_choice)}
            turn = self._call(req, purpose + ":step%d" % step)
        else:
            if turn.function_calls:
                raise GeminiError("limite de %d passos de ferramentas atingido" % max_steps)
        final = {"model": self.model, "previous_interaction_id": turn.interaction_id, "tools": decls,
                 "input": "Com base no que consultou, responda agora apenas com o JSON final no esquema pedido.",
                 "response_format": self._response_format(final_schema),
                 "generation_config": self._gen_config(tool_choice="none")}
        fturn = self._call(final, purpose + ":final")
        obj, last = self._with_repair(fturn, final_schema, final, purpose + ":final")
        return obj, {"model": last.model or self.model, "trace": trace, "interaction_id": last.interaction_id,
                     "cache_keys": [c["key"] for c in self.calls]}
