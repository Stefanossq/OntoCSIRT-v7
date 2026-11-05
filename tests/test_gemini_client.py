"""Etapa 2: adaptador Gemini. Sem rede: respostas pre-definidas (ScriptedTransport) e modo replay."""
import json
from typing import List, Literal, Optional

import pytest
from pydantic import BaseModel, Field

from ontoevo import gemini as gm


class Item(BaseModel):
    cwe: str = Field(pattern=r"^CWE-\d+$")
    note: Optional[str] = None


class Answer(BaseModel):
    kind: Literal["a", "b"]
    items: List[Item] = Field(min_length=1, max_length=3)
    rationale: str = Field(min_length=5)


GOOD = json.dumps({"kind": "a", "items": [{"cwe": "CWE-79"}], "rationale": "porque sim"})


def client(tmp_path, turns, mode="cached"):
    return gm.GeminiClient(model="gemini-test", mode=mode, cache_dir=str(tmp_path / "gem"),
                           transport=gm.ScriptedTransport(turns))


def test_schema_is_reduced_to_gemini_subset():
    s = gm.to_gemini_schema(Answer.model_json_schema())
    text = json.dumps(s)
    assert "$ref" not in text and "$defs" not in text and "pattern" not in text and "minLength" not in text
    assert s["properties"]["kind"]["enum"] == ["a", "b"]
    assert s["properties"]["items"]["minItems"] == 1 and s["properties"]["items"]["maxItems"] == 3  # aplicados
    assert s["properties"]["items"]["items"]["properties"]["note"]["type"] == ["string", "null"]
    assert set(s["required"]) == {"kind", "items", "rationale"}


def test_generate_json_validates_and_caches(tmp_path):
    c = client(tmp_path, [{"interaction_id": "i1", "output_text": GOOD}])
    obj, meta = c.generate_json("pergunta", Answer, system="sistema")
    assert obj.items[0].cwe == "CWE-79"
    req = c.transport().requests[0]
    assert req["response_format"]["mime_type"] == "application/json" and req["system_instruction"] == "sistema"
    assert req["generation_config"]["temperature"] == 0.0
    # replay: mesma pergunta sem transporte nem rede
    r = gm.GeminiClient(model="gemini-test", mode="replay", cache_dir=str(tmp_path / "gem"))
    obj2, _ = r.generate_json("pergunta", Answer, system="sistema")
    assert obj2 == obj and r.calls[0]["cache_hit"]
    with pytest.raises(gm.GeminiUnavailable):
        r.generate_json("outra pergunta", Answer)


def test_local_validation_catches_what_gemini_strips_and_repairs_once(tmp_path):
    bad = json.dumps({"kind": "a", "items": [{"cwe": "79"}], "rationale": "porque sim"})   # padrao CWE violado
    c = client(tmp_path, [{"interaction_id": "i1", "output_text": bad}, {"interaction_id": "i2", "output_text": GOOD}])
    obj, _ = c.generate_json("p", Answer)
    rep = c.transport().requests[1]
    assert rep["previous_interaction_id"] == "i1" and "CWE" in rep["input"]
    assert obj.items[0].cwe == "CWE-79"
    c2 = client(tmp_path, [{"interaction_id": "j1", "output_text": bad}, {"interaction_id": "j2", "output_text": bad}])
    with pytest.raises(gm.GeminiError):
        c2.generate_json("p2", Answer)


def test_tool_loop_executes_only_declared_tools(tmp_path):
    seen = []

    def lookup(cwe_id):
        seen.append(cwe_id)
        return {"cwe": cwe_id, "name": "Improper Neutralization"}

    tools = [gm.Tool("lookup_cwe", "Le uma CWE do catalogo.", {"type": "object", "properties": {"cwe_id": {"type": "string"}},
                                                             "required": ["cwe_id"]}, lookup)]
    turns = [
        {"interaction_id": "t0", "function_calls": [{"id": "c1", "name": "lookup_cwe", "arguments": {"cwe_id": "CWE-79"}},
                                                    {"id": "c2", "name": "delete_everything", "arguments": {}}]},
        {"interaction_id": "t1", "output_text": "ok"},
        {"interaction_id": "t2", "output_text": GOOD},
    ]
    c = client(tmp_path, turns)
    obj, meta = c.run_tools("analise", tools, Answer, system="s")
    assert seen == ["CWE-79"] and obj.kind == "a"
    reqs = c.transport().requests
    assert reqs[0]["tools"][0]["name"] == "lookup_cwe" and reqs[0]["tools"][0]["type"] == "function"
    results = reqs[1]["input"]
    assert reqs[1]["previous_interaction_id"] == "t0"
    assert [r["call_id"] for r in results] == ["c1", "c2"]
    assert results[1]["is_error"] and "desconhecida" in results[1]["result"][0]["text"]
    assert reqs[2]["generation_config"]["tool_choice"] == "none" and "response_format" in reqs[2]
    assert [t["tool"] for t in meta["trace"]] == ["lookup_cwe", "delete_everything"]


def test_requests_match_sdk_request_types(tmp_path):
    """Os pedidos montados pelo adaptador validam contra os tipos do SDK (nomes e formas dos campos)."""
    from google.genai._gaos.types.interactions.createmodelinteraction import CreateModelInteraction
    tools = [gm.Tool("lookup_cwe", "Le uma CWE.", {"type": "object", "properties": {"cwe_id": {"type": "string"}}},
                     lambda cwe_id: {})]
    turns = [{"interaction_id": "t0", "function_calls": [{"id": "c1", "name": "lookup_cwe", "arguments": {"cwe_id": "CWE-1"}}]},
             {"interaction_id": "t1", "output_text": "ok"}, {"interaction_id": "t2", "output_text": GOOD}]
    c = client(tmp_path, turns)
    c.run_tools("p", tools, Answer, system="s")
    c2 = client(tmp_path, [{"interaction_id": "g", "output_text": GOOD}])
    c2.generate_json("q", Answer)
    for req in c.transport().requests + c2.transport().requests:
        m = CreateModelInteraction.model_validate(req)
        assert m.model == "gemini-test"
    final = CreateModelInteraction.model_validate(c.transport().requests[-1])
    assert final.response_format is not None and final.previous_interaction_id == "t1"


def test_tool_loop_step_limit(tmp_path):
    loop = {"interaction_id": "x", "function_calls": [{"id": "c", "name": "t", "arguments": {}}]}
    tools = [gm.Tool("t", "d", {"type": "object", "properties": {}}, lambda: {})]
    c = client(tmp_path, [dict(loop) for _ in range(5)])
    with pytest.raises(gm.GeminiError):
        c.run_tools("p", tools, Answer, max_steps=3)


def test_live_transport_requires_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(gm.GeminiUnavailable):
        gm.LiveTransport()


def test_normalize_real_sdk_interaction_object():
    """A normalizacao le os tipos reais do SDK google-genai (nao so dicionarios dos testes)."""
    from google.genai._gaos.types.interactions.interaction import Interaction
    it = Interaction.model_validate({"id": "int_1", "status": "completed", "usage": {"total_tokens": 10},
                                     "steps": [{"type": "thought", "signature": "abc"},
                                               {"type": "function_call", "id": "c1", "name": "get_x", "arguments": {"a": 1}}]})
    t = gm.LiveTransport.normalize(it, "m")
    assert t.function_calls == [{"id": "c1", "name": "get_x", "arguments": {"a": 1}}] and t.usage == {"total_tokens": 10}
    it2 = Interaction.model_validate({"id": "int_2", "status": "completed",
                                      "steps": [{"type": "model_output", "content": [{"type": "text", "text": GOOD}]}]})
    assert gm.LiveTransport.normalize(it2).output_text == GOOD
