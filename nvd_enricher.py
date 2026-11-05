#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
nvd_enricher.py - enriquecimento em tempo real: CVE ausente da ontologia -> NVD API 2.0 -> ramo OWL
(Vulnerability + Weakness/CWE) validado e gravado no ficheiro de dados.

Usado pelo soar_webhook.py (POST /alert com "cve" desconhecida) e utilizavel sozinho:
    python nvd_enricher.py CVE-2025-6558 --kb OntoCSIRT_v7_real.ttl --out OntoCSIRT_v7_acquired.ttl

Ramo criado (vocabulario existente do v7 + extensao; nada de novo na TBox):
    :Vuln_CVE_x a :Vulnerability ; :cveId ; :cvssBaseScore (NVD, nunca inventado) ; :cvssSource ;
                :confidentialityImpact ; :hasWeakness :CWE_n ; dcterms:source ; :cweSource ; :verificationNote
    :CWE_n a <categoria>  (so se a CWE ainda nao existir; categoria lida da ontologia/evolucao, como na ingestao)
Antes de gravar: SHACL (shapes_v7.ttl + shapes_ingest.ttl + shapes_evo.ttl) e HermiT sobre o grafo COMPOSTO
(base + extensao + evolucao + dados + ramo novo). O Pellet (risco R1, R5/R6) corre depois, no fluxo do alerta.
O OntoCSIRT_v7.ttl do artigo nunca e escrito: o ramo vai para o ficheiro de dados (onto_path).

Rede e limites da API publica do NIST:
  * rate limit: 5 pedidos / 30 s sem chave, 50 / 30 s com chave (NVD_API_KEY) - janela deslizante
    partilhada por todas as threads do processo;
  * orcamento de tempo max_wait (35 s) para o passo NVD inteiro - esperas do limite, pedidos e novas
    tentativas; o timeout de cada pedido e reduzido ao que resta; esgotado -> NVDUnavailable;
  * cache local cache/nvd_<CVE>.json com validade de 24 h (registos encontrados) e 1 h ("nao encontrada",
    para uma CVE ainda nao publicada voltar a ser procurada cedo); ficheiro corrompido = cache ignorada;
  * timeout (ligacao 5 s, leitura 20 s), 403/429/503 com nova tentativa e espera crescente; API fora do ar
    ou sem rede -> NVDUnavailable; 404 ou totalResults 0 -> CVENotFound.
Este produto usa dados da API do NVD, mas nao e endossado nem certificado pelo NVD.
"""
import argparse
import json
import logging
import os
import re
import tempfile
import threading
import time
from collections import deque

import requests
from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import RDF, RDFS, XSD

import ingest_real_cases as ing
import ontocsirt_v7 as v7
import validar_ingestao as val

log = logging.getLogger("ontocsirt.nvd")
OC = v7.OC
DCT = Namespace("http://purl.org/dc/terms/")
HERE = v7.HERE
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.join(HERE, "cache")
CVE_RX = re.compile(r"^CVE-\d{4}-\d{4,}$")
WINDOW = 30.0
UA = {"User-Agent": "OntoCSIRT-nvd-enricher/1.0 (research prototype)"}


# ------------------------------------------------------------------ erros
class NVDError(Exception):
    """Base: o enriquecimento nao foi feito (o webhook responde com o fallback de revisao manual)."""
    kind = "nvd_error"


class NVDUnavailable(NVDError):
    """Timeout, sem rede, API fora do ar (5xx) ou limite de pedidos que exigiria esperar demais."""
    kind = "nvd_unavailable"


class CVENotFound(NVDError):
    """A API respondeu, mas a CVE nao existe (ou ainda nao foi publicada) no NVD."""
    kind = "cve_not_found"


class EnrichmentRejected(NVDError):
    """Registo NVD sem o necessario (CVSS 3.x/4.0, CWE) ou ramo bloqueado pelo SHACL/HermiT."""
    kind = "enrichment_rejected"


# ------------------------------------------------------------------ limite de pedidos
class RateLimiter:
    """Janela deslizante de WINDOW segundos, segura para threads. clock/sleep injetaveis (testes)."""

    def __init__(self, limit, window=WINDOW, clock=time.monotonic, sleep=time.sleep):
        self.limit, self.window, self.clock, self.sleep = limit, window, clock, sleep
        self.calls = deque()
        self.lock = threading.Lock()

    def acquire(self, max_wait):
        """Reserva um pedido; devolve os segundos esperados. NVDUnavailable se tivesse de esperar > max_wait."""
        waited = 0.0
        while True:
            with self.lock:
                now = self.clock()
                while self.calls and now - self.calls[0] >= self.window:
                    self.calls.popleft()
                if len(self.calls) < self.limit:
                    self.calls.append(now)
                    return waited
                wait = self.calls[0] + self.window - now
            if waited + wait > max_wait:
                raise NVDUnavailable("limite do NVD (%d pedidos/%ds) exigiria esperar %.0f s (maximo %.0f s)"
                                     % (self.limit, self.window, waited + wait, max_wait))
            self.sleep(wait)
            waited += wait


_LIMITERS, _LIMITERS_LOCK = {}, threading.Lock()


def shared_limiter(with_key):
    """Um limitador por tipo de acesso, partilhado no processo (todas as threads do webhook)."""
    limit = 50 if with_key else 5
    with _LIMITERS_LOCK:
        if limit not in _LIMITERS:
            _LIMITERS[limit] = RateLimiter(limit)
        return _LIMITERS[limit]


# ------------------------------------------------------------------ cache
class NVDCache:
    """cache/nvd_<CVE>.json = {"cve_id", "fetched_at" (epoch), "found", "record"}."""

    def __init__(self, directory=CACHE_DIR, ttl=24 * 3600, negative_ttl=3600, clock=time.time):
        self.dir, self.ttl, self.negative_ttl, self.clock = directory, ttl, negative_ttl, clock

    def path(self, cve):
        return os.path.join(self.dir, "nvd_%s.json" % cve)

    def get(self, cve):
        """(acerto, registo|None, idade_s). Registo None num acerto = CVE "nao encontrada" em cache."""
        p = self.path(cve)
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            age = self.clock() - float(d["fetched_at"])
            limit = self.ttl if d.get("found") else self.negative_ttl
            if 0 <= age < limit:
                return True, d.get("record"), age
        except FileNotFoundError:
            pass
        except (ValueError, KeyError, TypeError, OSError) as e:
            log.warning("cache NVD ilegivel (%s): %s - ignorada", p, e)
        return False, None, None

    def put(self, cve, record):
        os.makedirs(self.dir, exist_ok=True)
        _atomic_write(self.path(cve), json.dumps({"cve_id": cve, "fetched_at": self.clock(), "found": record is not None,
                                                  "record": record}, ensure_ascii=False))


def _atomic_write(path, text):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp_", suffix=os.path.splitext(path)[1])
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    # o mkstemp cria o ficheiro com modo 600: mantem o modo do ficheiro substituido (ou 644 se e novo),
    # senao um volume ou bind mount do contentor ficaria ilegivel para outros leitores
    try:
        os.chmod(tmp, os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o644)
    except OSError:
        pass
    os.replace(tmp, path)


_WRITE_LOCKS, _WRITE_LOCKS_LOCK = {}, threading.Lock()


def _write_lock(path):
    with _WRITE_LOCKS_LOCK:
        return _WRITE_LOCKS.setdefault(os.path.abspath(path), threading.Lock())


# ------------------------------------------------------------------ enriquecedor
class NVDEnricher:
    def __init__(self, kb_path=None, api_key=None, cache_dir=CACHE_DIR, ttl=24 * 3600, negative_ttl=3600,
                 timeout=(5, 20), max_wait=35.0, retries=3, session=None, limiter=None, use_hermit=True,
                 clock=time.time, sleep=time.sleep):
        self.kb_path = kb_path
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self.cache = NVDCache(cache_dir, ttl, negative_ttl, clock)
        self.timeout, self.max_wait, self.retries = timeout, max_wait, retries
        self.session = session or requests.Session()
        self.limiter = limiter or shared_limiter(bool(self.api_key))
        self.use_hermit, self.sleep, self.clock = use_hermit, sleep, clock
        self.last_result, self.last_error = None, None
        self.http_calls = 0

    # -------------------------------------------------------------- 1. consulta
    def fetch(self, cve):
        """Registo NVD da CVE (cache de 24 h primeiro). Levanta CVENotFound / NVDUnavailable."""
        hit, rec, age = self.cache.get(cve)
        if hit:
            if rec is None:
                raise CVENotFound("%s nao existe no NVD (resposta em cache ha %.0f min)" % (cve, age / 60))
            return rec, {"source": "cache", "age_seconds": round(age)}
        headers = dict(UA, **({"apiKey": self.api_key} if self.api_key else {}))
        # max_wait e o orcamento do passo NVD INTEIRO (esperas do limite, pedidos e novas tentativas): o
        # timeout de cada pedido e reduzido ao que resta, para o alerta nunca ficar mais do que isto a espera
        start = self.clock()
        remaining = lambda: self.max_wait - (self.clock() - start)  # noqa: E731
        last, waited = None, 0.0
        for attempt in range(1, self.retries + 1):
            if remaining() < 1.0:
                last = last or NVDUnavailable("tempo maximo do passo NVD (%.0f s) esgotado" % self.max_wait)
                break
            waited += self.limiter.acquire(max(0.0, remaining()))
            rem = max(1.0, remaining())
            timeout = (min(self.timeout[0], rem), min(self.timeout[1], rem))
            try:
                self.http_calls += 1
                r = self.session.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=timeout)
            except requests.Timeout as e:
                last = NVDUnavailable("timeout ao consultar o NVD (%s)" % type(e).__name__)
            except requests.ConnectionError as e:
                last = NVDUnavailable("NVD inacessivel (sem rede ou API fora do ar): %s" % type(e).__name__)
            else:
                if r.status_code == 200:
                    try:
                        vulns = r.json().get("vulnerabilities", [])
                    except ValueError:
                        last = NVDUnavailable("resposta do NVD nao e JSON valido")
                    else:
                        rec = vulns[0]["cve"] if vulns else None
                        self.cache.put(cve, rec)
                        if rec is None:
                            raise CVENotFound("%s nao existe no NVD (ou ainda nao foi publicada)" % cve)
                        return rec, {"source": "api", "attempts": attempt, "rate_limit_wait_seconds": round(waited, 1)}
                elif r.status_code == 404:
                    self.cache.put(cve, None)
                    raise CVENotFound("%s nao existe no NVD (HTTP 404)" % cve)
                elif r.status_code in (403, 429, 500, 502, 503, 504):
                    # 403/429: limite excedido (o NVD usa 403); 5xx: indisponivel - nova tentativa
                    last = NVDUnavailable("NVD respondeu HTTP %d" % r.status_code)
                else:
                    raise NVDUnavailable("NVD respondeu HTTP %d inesperado" % r.status_code)
            if attempt < self.retries:
                backoff = 6.0 * attempt
                if backoff + 1.0 > remaining():
                    break
                self.sleep(backoff)
                waited += backoff
        raise last or NVDUnavailable("NVD indisponivel")

    # -------------------------------------------------------------- 2. ramo OWL
    def build_branch(self, cve, rec, ref, fallback_cwe=None):
        """Triplas do ramo (Vulnerability + CWE). ref = grafo composto (TBox + dados) para a categoria."""
        cvss = ing.pick_cvss(rec)
        if cvss is None:
            raise EnrichmentRejected("%s sem CVSS 3.x/4.0 no NVD (vulnStatus=%s); o CVSS nunca e inventado"
                                     % (cve, rec.get("vulnStatus")))
        from ontoevo.enrich import nvd_cwes
        cwes, cwe_source = nvd_cwes(rec), "nvd"
        if not cwes and fallback_cwe:
            cwes, cwe_source = [fallback_cwe], "alerta (o NVD nao atribui CWE)"
        if not cwes:
            raise EnrichmentRejected("%s sem CWE no NVD (NVD-CWE-noinfo/Other) e o alerta nao indica uma" % cve)
        cwe = cwes[0]
        g = Graph()
        W = OC["CWE_" + cwe.split("-")[1]]
        cat = ing.cwe_category(cwe, ref)
        if (W, OC.cweId, None) not in ref:
            g.add((W, RDF.type, OC[cat]))
            g.add((W, OC.cweId, Literal(cwe)))
            g.add((W, RDFS.label, ing.lit(self._cwe_label(cwe))))
        V = OC["Vuln_" + ing.slug(cve)]
        g.add((V, RDF.type, OC.Vulnerability))
        g.add((V, OC.cveId, Literal(cve)))
        g.add((V, OC.hasWeakness, W))
        if len(cwes) > 1:
            g.add((V, OC.otherCweIds, Literal(" ".join(cwes[1:]))))
        g.add((V, OC.cvssBaseScore, Literal(str(cvss["score"]), datatype=XSD.decimal)))
        g.add((V, OC.cvssSource, ing.lit("NVD API 2.0 CVSS %s %s" % (cvss["version"], cvss["type"]))))
        if cvss["C"] in ("HIGH", "LOW", "NONE"):
            g.add((V, OC.confidentialityImpact, Literal(cvss["C"])))
        g.add((V, DCT.source, URIRef("https://nvd.nist.gov/vuln/detail/" + cve)))
        g.add((V, OC.cweSource, ing.lit(cwe_source)))
        g.add((V, OC.verificationNote, ing.lit("Consultado no NVD em tempo real em %s (vulnStatus %s)"
                                               % (time.strftime("%Y-%m-%d"), rec.get("vulnStatus", "?")))))
        g.add((V, OC.acquisitionRun, Literal("nvd_enricher %s" % time.strftime("%Y-%m-%dT%H:%M:%S"))))
        return g, {"vulnerability": v7.short(V), "cwe": cwe, "category": cat, "cwe_source": cwe_source,
                   "cvss": cvss["score"], "cvss_version": cvss["version"], "vuln_status": rec.get("vulnStatus")}

    @staticmethod
    def _cwe_label(cwe):
        try:
            from ontoevo.catalogs import Catalogs
            e = Catalogs().cwe_entry(cwe)
            return "%s %s" % (cwe, e["name"]) if e else cwe
        except Exception:  # noqa: BLE001  (catalogo opcional)
            return cwe

    # -------------------------------------------------------------- 3. composicao, validacao e gravacao
    def compose(self, onto_path):
        g = Graph()
        if self.kb_path:
            g.parse(self.kb_path, format="turtle")
        g = val.with_tbox(g)
        if onto_path and os.path.exists(onto_path) and os.path.abspath(onto_path) != os.path.abspath(self.kb_path or ""):
            g.parse(onto_path, format="turtle")
        ing.remove_all_different(g)
        ing.add_all_different(g)
        return g

    @staticmethod
    def cve_exists(g, cve):
        return bool(g.query(v7.PFX + 'ASK { ?v :cveId ?id . FILTER(STR(?id) = "%s") }' % cve).askAnswer)

    def enrich_detailed(self, cve_id, onto_path, fallback_cwe=None):
        """Enriquece e devolve o relatorio; levanta NVDError (ou ValueError para CVE mal formada)."""
        cve = (cve_id or "").strip().upper()
        if not CVE_RX.match(cve):
            raise ValueError("identificador CVE mal formado: %r" % cve_id)
        if os.path.abspath(onto_path) == os.path.abspath(v7.TTL):
            raise ValueError("o OntoCSIRT_v7.ttl do artigo e congelado; use um ficheiro de dados")
        t0 = time.time()
        with _write_lock(onto_path):
            g = self.compose(onto_path)
            if self.cve_exists(g, cve):
                self.last_result = {"cve": cve, "status": "present", "seconds": round(time.time() - t0, 2)}
                return self.last_result
            rec, origin = self.fetch(cve)
            branch, summary = self.build_branch(cve, rec, g, fallback_cwe)
            for t in branch:
                g.add(t)
            rep = val.validate(g, use_hermit=self.use_hermit)
            h = rep.get("hermit", {})
            if not rep["conforms"] or (self.use_hermit and (not h["consistent"] or h["unsatisfiable_classes"])):
                raise EnrichmentRejected("ramo de %s bloqueado pelo portao: %s" % (
                    cve, "; ".join(v["message"] for v in rep["violations"][:5]) or "HermiT: inconsistente/insatisfazivel"))
            data = Graph()
            if os.path.exists(onto_path):
                data.parse(onto_path, format="turtle")
                from ontoevo import kb
                kb.backup(onto_path, "nvd_" + ing.slug(cve))
            for t in branch:
                data.add(t)
            data.bind("", OC)
            _atomic_write(onto_path, data.serialize(format="turtle"))
        self.last_result = dict(summary, cve=cve, status="written", nvd=origin, written=onto_path, triples=len(branch),
                                gate={"shacl_conforms": True, "hermit": h or None}, seconds=round(time.time() - t0, 2))
        log.info("NVD: %s gravada em %s (CVSS %s, %s)", cve, onto_path, summary["cvss"], summary["cwe"])
        return self.last_result

    def enrich(self, cve_id: str, onto_path: str) -> bool:
        """True se a CVE ficou na ontologia (ja existia ou foi gravada); False se nao foi possivel.
        O motivo fica em self.last_error (NVDError) e o relatorio em self.last_result."""
        self.last_error = None
        try:
            self.enrich_detailed(cve_id, onto_path)
            return True
        except (NVDError, ValueError) as e:
            self.last_error = e
            log.warning("enriquecimento NVD de %s falhou: %s", cve_id, e)
            return False


def main():
    ap = argparse.ArgumentParser(description="Enriquece a ontologia com uma CVE do NVD (tempo real, cache de 24 h).")
    ap.add_argument("cve", nargs="+")
    ap.add_argument("--kb", default=os.path.join(HERE, "OntoCSIRT_v7_real.ttl"), help="base (leitura)")
    ap.add_argument("--out", default=os.path.join(HERE, "OntoCSIRT_v7_acquired.ttl"), help="ficheiro de dados (escrita)")
    ap.add_argument("--no-hermit", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    e = NVDEnricher(kb_path=a.kb, use_hermit=not a.no_hermit)
    code = 0
    for cve in a.cve:
        try:
            print(json.dumps(e.enrich_detailed(cve, a.out), ensure_ascii=False, default=str))
        except (NVDError, ValueError) as err:
            print(json.dumps({"cve": cve, "status": "failed", "error": getattr(err, "kind", "invalid"), "detail": str(err)},
                             ensure_ascii=False))
            code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
