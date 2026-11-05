"""Etapa 3: aquisicao de vulnerabilidades. CVE real (registos KEV e NVD reais em fixtures) -> individuos OWL.
O Gemini e simulado (ScriptedTransport): o que se testa e que SO preenche lacunas, que cada valor e
verificado nos catalogos oficiais e que nada entra na base sem passar no portao (SHACL+HermiT+Pellet)."""
import json
import os

import pytest
from rdflib import Graph

import ingest_real_cases as ing
from ontoevo import gemini as gm
from ontoevo.catalogs import Catalogs
from ontoevo.enrich import VulnAcquirer

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "nvd")
OC = ing.OC


class FixtureNVD:
    def get(self, cve):
        p = os.path.join(FIX, cve + ".json")
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)


@pytest.fixture(scope="module")
def sources():
    _, kev = ing.load_kev()
    _, ctid = ing.load_ctid()
    return kev, ctid


def answer(**over):
    a = {"cwe_id": None, "cwe_justification": "A CWE ja vem do KEV; nada a acrescentar.",
         "techniques": [{"attack_id": "T1190", "role": "exploitation",
                         "justification": "Falha num gateway VPN exposto a internet, explorada remotamente."}],
         "asset_class": "Gateway", "asset_justification": "Ivanti Connect Secure e um gateway VPN SSL.",
         "required_action": None, "evidence_quotes": ["Ivanti Connect Secure"], "confidence": 0.8}
    a.update(over)
    return {"interaction_id": "x", "output_text": json.dumps(a), "model": "gemini-test"}


def acquirer(tmp_path, sources, turns):
    kev, ctid = sources
    client = gm.GeminiClient(model="gemini-test", mode="cached", cache_dir=str(tmp_path / "gem"),
                             transport=gm.ScriptedTransport(turns))
    return VulnAcquirer(gemini=client, catalogs=Catalogs(), nvd=FixtureNVD(), kev=kev, ctid=ctid,
                        acquired_path=str(tmp_path / "acquired.ttl"))


def test_real_cve_becomes_owl_individuals(tmp_path, sources):
    acq = acquirer(tmp_path, sources, [answer()])
    res = acq.acquire("CVE-2026-111357")
    assert res["status"] == "written", res
    assert res["gaps"] == ["technique"]                       # CWE do KEV, ativo pela heuristica
    assert res["verification"]["techniques"][0]["ok"]
    for ind in ("Vuln_CVE_2026_111357", "Incident_CVE_2026_111357", "Case_CVE_2026_111357", "Act_CVE_2026_111357"):
        assert ind in res["new_individuals"]
    h = res["gate"]["hermit"]
    assert res["gate"]["conforms"] and h["consistent"] and h["unsatisfiable_classes"] == [] and res["gate"]["pellet"]["consistent"]
    g = Graph().parse(str(tmp_path / "acquired.ttl"), format="turtle")
    V = OC.Vuln_CVE_2026_111357
    assert str(g.value(V, OC.cveId)) == "CVE-2026-111357"
    assert str(g.value(V, OC.cvssBaseScore)) == "7.0"         # do NVD, nunca do modelo
    assert str(g.value(V, OC.cweSource)) == "kev"
    src = str(g.value(OC.Act_CVE_2026_111357, OC.techniqueSource))
    assert src.startswith("gemini:gemini-test") and "verificado" in src
    assert g.value(OC.Act_CVE_2026_111357, OC.instantiatesPattern) == OC.AP_T1190
    # segunda vez: recusada (duplicado), nada reescrito
    assert acquirer(tmp_path, sources, []).acquire("CVE-2026-111357")["status"] == "rejected"


def test_invented_technique_is_rejected_not_ingested(tmp_path, sources):
    bad = answer(techniques=[{"attack_id": "T9999", "role": "exploitation", "justification": "tecnica inventada pelo modelo"}])
    res = acquirer(tmp_path, sources, [bad]).acquire("CVE-2026-111357")
    assert res["status"] == "rejected" and "technique" in res["reason"]
    assert res["verification"]["techniques"][0]["ok"] is False
    assert not os.path.exists(tmp_path / "acquired.ttl")


def test_nvd_cwe_and_llm_asset_type(tmp_path, sources):
    """CVE-2026-53362: KEV sem CWE -> CWE-787 do NVD; sem CTID e com produto sem regra -> Gemini."""
    a = answer(techniques=[{"attack_id": "T1068", "role": "exploitation",
                            "justification": "Escalada de privilegios local via subsistema do kernel."}],
               asset_class="Server", asset_justification="Kernel Linux em servidores; o texto nao indica posto de trabalho.",
               evidence_quotes=["privilege escalation via IPv6 networking subsystem"])
    res = acquirer(tmp_path, sources, [a]).acquire("CVE-2026-53362")
    assert res["status"] == "written", res
    assert res["sources"]["cwe"] == "nvd" and set(res["gaps"]) == {"technique", "asset_type"}
    g = Graph().parse(str(tmp_path / "acquired.ttl"), format="turtle")
    assert g.value(OC.Vuln_CVE_2026_53362, OC.hasWeakness) == OC.CWE_787
    assert (OC.CWE_787, ing.RDF.type, OC.MemorySafetyWeakness) in g


def test_invented_cwe_is_rejected(tmp_path, sources):
    kev, ctid = sources
    kev = dict(kev)
    kev["CVE-2026-53362"] = dict(kev["CVE-2026-53362"], cwes=[])
    nvd = FixtureNVD()
    rec = nvd.get("CVE-2026-53362")
    rec["weaknesses"] = []                                    # sem CWE em nenhuma fonte

    class NoCweNVD:
        def get(self, cve):
            return rec

    for cwe, ok in (("CWE-99999", False), ("CWE-787", True)):
        client = gm.GeminiClient(model="gemini-test", mode="cached", cache_dir=str(tmp_path / ("g" + cwe)),
                                 transport=gm.ScriptedTransport([answer(cwe_id=cwe, asset_class="Server")]))
        acq = VulnAcquirer(gemini=client, catalogs=Catalogs(), nvd=NoCweNVD(), kev=kev, ctid=ctid,
                           acquired_path=str(tmp_path / ("a%s.ttl" % cwe)))
        plan = acq.analyze("CVE-2026-53362", __import__("ontoevo.kb", fromlist=["kb"]).load())
        assert plan["verification"]["cwe"]["ok"] is ok
        assert plan["status"] == ("ready" if ok else "rejected")


def test_without_gemini_gaps_are_reported(tmp_path, sources):
    kev, ctid = sources
    client = gm.GeminiClient(model="gemini-test", mode="replay", cache_dir=str(tmp_path / "empty"))
    acq = VulnAcquirer(gemini=client, catalogs=Catalogs(), nvd=FixtureNVD(), kev=kev, ctid=ctid,
                       acquired_path=str(tmp_path / "acq.ttl"))
    res = acq.acquire("CVE-2026-111357")
    assert res["status"] == "rejected" and "llm_error" in res and res["gaps"] == ["technique"]
