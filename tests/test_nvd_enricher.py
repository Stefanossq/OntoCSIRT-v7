"""nvd_enricher.py + integracao no POST /alert. Sem rede: sessao HTTP falsa que serve os registos NVD reais
de tests/fixtures/nvd, relogio falso para a cache de 24 h e para o limite de pedidos."""
import copy
import json
import os

import pytest
import requests
from rdflib import Graph

import nvd_enricher as ne
import ontocsirt_v7 as v7

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "nvd")
OC = v7.OC
CVE = "CVE-2025-6558"                                      # Chromium, CWE-20, CVSS 8.8 (ausente da base do artigo)


def record(cve=CVE):
    with open(os.path.join(FIX, cve + ".json"), encoding="utf-8") as f:
        return json.load(f)


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class FakeSession:
    """Cada item do guiao: Resp, excecao, ou "nvd" (devolve o registo da fixture pedido)."""

    def __init__(self, script=None, records=None):
        self.script, self.records, self.calls = list(script or []), records or {}, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        step = self.script.pop(0) if self.script else "nvd"
        if isinstance(step, Exception):
            raise step
        if step == "nvd":
            cve = params["cveId"]
            rec = self.records.get(cve) or (record(cve) if os.path.exists(os.path.join(FIX, cve + ".json")) else None)
            return Resp(200, {"totalResults": int(rec is not None), "vulnerabilities": [{"cve": rec}] if rec else []})
        return step


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def enricher(tmp_path, session, clock=None, **kw):
    clock = clock or Clock()
    return ne.NVDEnricher(kb_path=v7.TTL, api_key="", cache_dir=str(tmp_path / "cache"), session=session,
                          limiter=ne.RateLimiter(1000, clock=clock, sleep=clock.sleep), clock=clock, sleep=clock.sleep, **kw)


# ------------------------------------------------------------------ cache, limite, erros
def test_cache_24h_then_refetch(tmp_path):
    clock, s = Clock(), FakeSession()
    e = enricher(tmp_path, s, clock)
    assert e.fetch(CVE)[1]["source"] == "api"
    assert os.path.exists(tmp_path / "cache" / ("nvd_%s.json" % CVE))     # cache/nvd_{cve_id}.json
    clock.t += 23 * 3600
    assert e.fetch(CVE)[1]["source"] == "cache" and len(s.calls) == 1
    clock.t += 2 * 3600                                                    # 25 h: expirou
    assert e.fetch(CVE)[1]["source"] == "api" and len(s.calls) == 2


def test_not_found_is_cached_for_one_hour(tmp_path):
    clock, s = Clock(), FakeSession()
    e = enricher(tmp_path, s, clock)
    with pytest.raises(ne.CVENotFound):
        e.fetch("CVE-2099-0001")
    clock.t += 1800
    with pytest.raises(ne.CVENotFound):
        e.fetch("CVE-2099-0001")
    assert len(s.calls) == 1
    clock.t += 3600
    with pytest.raises(ne.CVENotFound):
        e.fetch("CVE-2099-0001")
    assert len(s.calls) == 2


def test_corrupt_cache_is_ignored(tmp_path):
    s = FakeSession()
    e = enricher(tmp_path, s)
    os.makedirs(tmp_path / "cache")
    (tmp_path / "cache" / ("nvd_%s.json" % CVE)).write_text("{nao e json", encoding="utf-8")
    assert e.fetch(CVE)[1]["source"] == "api"


def test_rate_limit_5_per_30s_without_key_and_50_with_key():
    clock = Clock()
    rl = ne.RateLimiter(5, clock=clock, sleep=clock.sleep)
    assert [rl.acquire(60) for _ in range(5)] == [0.0] * 5
    assert rl.acquire(60) == pytest.approx(30.0)                           # 6.o pedido espera a janela
    clock2 = Clock()
    rl2 = ne.RateLimiter(5, clock=clock2, sleep=clock2.sleep)
    for _ in range(5):
        rl2.acquire(60)
    with pytest.raises(ne.NVDUnavailable):
        rl2.acquire(10)                                                    # esperar 30 s > maximo 10 s
    assert ne.shared_limiter(False).limit == 5 and ne.shared_limiter(True).limit == 50
    assert ne.shared_limiter(False) is ne.shared_limiter(False)            # partilhado entre threads/instancias


def test_api_key_header_sent(tmp_path):
    s = FakeSession()
    e = enricher(tmp_path, s)
    e.api_key = "segredo"
    e.fetch(CVE)
    assert s.calls[0]["headers"]["apiKey"] == "segredo" and s.calls[0]["timeout"] == (5, 20)


@pytest.mark.parametrize("exc", [requests.Timeout("t"), requests.ConnectionError("offline")])
def test_timeout_and_offline_are_unavailable_after_retries(tmp_path, exc):
    s = FakeSession([exc, exc, exc])
    e = enricher(tmp_path, s)
    with pytest.raises(ne.NVDUnavailable):
        e.fetch(CVE)
    assert len(s.calls) == 3


class SlowTimeoutSession(FakeSession):
    """Cada pedido consome o timeout de leitura no relogio falso e acaba em Timeout (NVD lento)."""

    def __init__(self, clock):
        super().__init__()
        self.clock = clock

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"timeout": timeout})
        self.clock.t += timeout[1]
        raise requests.Timeout("lento")


def test_total_time_budget_bounds_the_nvd_step(tmp_path):
    """--nvd-max-wait limita o passo inteiro (pedidos incluidos), nao so as esperas: com pedidos de 20 s,
    3 tentativas e esperas de 6 s e 12 s dariam 78 s; o orcamento de 35 s corta antes."""
    clock = Clock()
    s = SlowTimeoutSession(clock)
    e = enricher(tmp_path, s, clock)
    t0 = clock.t
    with pytest.raises(ne.NVDUnavailable):
        e.fetch(CVE)
    assert clock.t - t0 <= e.max_wait
    assert s.calls[0]["timeout"] == (5, 20) and len(s.calls) == 2
    assert s.calls[1]["timeout"][1] <= e.max_wait - 26            # 2.o pedido so com o que restava


@pytest.mark.skipif(os.name == "nt", reason="modos POSIX (corre no contentor Linux)")
def test_written_files_are_not_owner_only(tmp_path):
    out = str(tmp_path / "acquired.ttl")
    e = enricher(tmp_path, FakeSession())
    assert e.enrich(CVE, out)
    assert os.stat(out).st_mode & 0o044 == 0o044                  # legivel por grupo e outros (644)
    assert os.stat(e.cache.path(CVE)).st_mode & 0o044 == 0o044


def test_503_then_success_and_404(tmp_path):
    s = FakeSession([Resp(503), "nvd"])
    rec, origin = enricher(tmp_path, s).fetch(CVE)
    assert rec["id"] == CVE and origin["attempts"] == 2
    with pytest.raises(ne.CVENotFound):
        enricher(tmp_path, FakeSession([Resp(404)])).fetch("CVE-2025-0000")


# ------------------------------------------------------------------ enrich()
def test_enrich_writes_valid_branch_and_is_idempotent(tmp_path):
    out = str(tmp_path / "acquired.ttl")
    s = FakeSession()
    e = enricher(tmp_path, s)
    assert e.enrich(CVE, out) is True
    r = e.last_result
    assert r["status"] == "written" and r["cvss"] == 8.8 and r["cwe"] == "CWE-20"
    assert r["gate"]["shacl_conforms"] and r["gate"]["hermit"]["consistent"]
    g = Graph().parse(out, format="turtle")
    V = OC.Vuln_CVE_2025_6558
    assert str(g.value(V, OC.cveId)) == CVE and str(g.value(V, OC.cvssBaseScore)) == "8.8"
    assert g.value(V, OC.hasWeakness) == OC.CWE_20 and (OC.CWE_20, v7.RDF.type, OC.OtherWeakness) in g
    assert str(g.value(V, OC.cweSource)) == "nvd"
    assert e.enrich(CVE, out) is True and e.last_result["status"] == "present" and len(s.calls) == 1


def test_enrich_refuses_frozen_ontology_and_bad_ids(tmp_path):
    e = enricher(tmp_path, FakeSession())
    assert e.enrich(CVE, v7.TTL) is False and isinstance(e.last_error, ValueError)
    assert e.enrich("CVE-21-1", str(tmp_path / "x.ttl")) is False


def test_record_without_cvss_is_rejected_not_invented(tmp_path):
    rec = copy.deepcopy(record())
    rec["metrics"] = {}
    rec["vulnStatus"] = "Awaiting Analysis"
    out = str(tmp_path / "acquired.ttl")
    e = enricher(tmp_path, FakeSession(records={CVE: rec}))
    assert e.enrich(CVE, out) is False and isinstance(e.last_error, ne.EnrichmentRejected)
    assert "Awaiting Analysis" in str(e.last_error) and not os.path.exists(out)


def test_alert_cwe_used_only_when_nvd_has_none(tmp_path):
    rec = copy.deepcopy(record())
    rec["weaknesses"] = []
    out = str(tmp_path / "acquired.ttl")
    r = enricher(tmp_path, FakeSession(records={CVE: rec})).enrich_detailed(CVE, out, fallback_cwe="CWE-79")
    assert r["cwe"] == "CWE-79" and r["cwe_source"].startswith("alerta")


# ------------------------------------------------------------------ POST /alert
ALERT = {"src_ip": "203.0.113.50", "attack_type": "xss", "target": "Workstation_1", "cve": CVE, "alert_id": "N-1"}


def engine(tmp_path, session, reasoner="pellet"):
    import soar_webhook as sw
    out = str(tmp_path / "acquired.ttl")
    return sw.Engine(v7.TTL, reasoner=reasoner, acquired=out, enricher=enricher(tmp_path, session)), out


def test_alert_with_new_cve_enriches_reasons_and_recommends(tmp_path):
    s = FakeSession()
    eng, out = engine(tmp_path, s)
    assert not eng.cve_in_kb(CVE)
    code, res = eng.handle(dict(ALERT))
    assert code == 200 and res["nvd_enrichment"]["status"] == "written"
    assert res["risk_level"] == "High"                                     # Pellet, R1b sobre o CVSS 8.8 do NVD
    assert res["action_iri"] and res["neighbors"] and not res.get("fallback")
    assert eng.cve_in_kb(CVE) and os.path.exists(out)                      # base recarregada e gravada em disco
    code, res2 = eng.handle(dict(ALERT, alert_id="N-2"))                   # segunda vez: ja na base, sem NVD
    assert code == 200 and res2["nvd_enrichment"] is None and len(s.calls) == 1


def test_alert_falls_back_when_nvd_is_down(tmp_path):
    err = requests.ConnectionError("offline")
    eng, out = engine(tmp_path, FakeSession([err, err, err]), reasoner="none")
    code, res = eng.handle(dict(ALERT, alert_id="N-3"))
    assert code == 200 and res["fallback"] is True
    assert res["action"] == "manual_review" and res["requires_human_approval"] is True
    assert res["reason"] == "CVE nao encontrado na base e API NVD indisponivel"
    assert res["nvd"]["error"] == "nvd_unavailable" and not os.path.exists(out)


def test_alert_with_unknown_cve_falls_back_as_not_found(tmp_path):
    eng, _ = engine(tmp_path, FakeSession(), reasoner="none")
    code, res = eng.handle(dict(ALERT, cve="CVE-2099-0001", alert_id="N-4"))
    assert code == 200 and res["action"] == "manual_review" and res["nvd"]["error"] == "cve_not_found"


def test_known_cve_never_calls_nvd(tmp_path):
    s = FakeSession()
    eng, _ = engine(tmp_path, s, reasoner="none")
    code, res = eng.handle(dict(ALERT, cve="CVE-2023-34362", attack_type="sqli", alert_id="N-5"))
    assert code == 200 and res["nvd_enrichment"] is None and s.calls == []
