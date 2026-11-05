"""Etapa 4: aquisicao de casos CBR - analisar vulnerabilidade (retrieve + reuse pelo Gemini) e reter
alertas resolvidos (revise + retain pelo analista)."""
import json
import os

import pytest
from rdflib import Graph, Literal

import ingest_real_cases as ing
import ontocsirt_v7 as v7
from ontoevo import gemini as gm
from ontoevo import kb
from ontoevo.cases import CaseAcquirer
from ontoevo.catalogs import Catalogs
from ontoevo.enrich import VulnAcquirer

from test_enrich import FixtureNVD, answer

OC = v7.OC


def case_answer(solution="CoA_Patch"):
    return {"interaction_id": "c", "model": "gemini-test", "output_text": json.dumps({
        "solution": solution, "agrees_with_neighbors": False,
        "solution_rationale": "Falha de autenticacao em gateway exposto: os vizinhos com a mesma categoria rotacionam "
                              "credenciais, mas aqui a correcao do fornecedor elimina a causa.",
        "response_steps": ["Aplicar a versao corrigida do fornecedor", "Rever contas criadas no periodo de exposicao"],
        "evidence_quotes": ["Ivanti Connect Secure"], "confidence": 0.7})}


@pytest.fixture(scope="module")
def sources():
    _, kev = ing.load_kev()
    _, ctid = ing.load_ctid()
    return kev, ctid


def test_analyze_vulnerability_creates_new_cbr_case(tmp_path, sources):
    kev, ctid = sources
    acq_path = str(tmp_path / "acquired.ttl")
    client = gm.GeminiClient(model="gemini-test", mode="cached", cache_dir=str(tmp_path / "gem"),
                             transport=gm.ScriptedTransport([answer(), case_answer()]))
    va = VulnAcquirer(gemini=client, catalogs=Catalogs(), nvd=FixtureNVD(), kev=kev, ctid=ctid, acquired_path=acq_path)
    ca = CaseAcquirer(gemini=client, acquired_path=acq_path, vuln_acquirer=va, nvd=FixtureNVD())
    res = ca.analyze("CVE-2026-111357")                    # CVE ausente: adquire e depois analisa
    assert res["acquisition"]["status"] == "written"
    assert res["status"] == "written", res
    assert res["case"] == "Case_LLM_CVE_2026_111357" and len(res["neighbors"]) == 5
    assert res["gate"]["hermit"]["consistent"] and res["gate"]["pellet"]["consistent"] and res["gate"]["conforms"]
    # o prompt levou os casos recuperados (retrieve) e a lista fechada de acoes
    prompt = client.transport().requests[1]["input"]
    assert "CASOS RECUPERADOS" in prompt and res["neighbors"][0]["incident"] in prompt and "CoA_Isolate" in prompt
    g = Graph().parse(acq_path, format="turtle")
    C = OC.Case_LLM_CVE_2026_111357
    assert str(g.value(C, OC.solutionProvenance)) == "llm:case-analysis-v1"
    assert g.value(C, OC.hasSolution) == OC.CoA_Patch and g.value(C, OC.hasProblem) == OC.Incident_CVE_2026_111357
    assert len(list(g.objects(C, OC.responseStep))) == 2
    # recuperacao: a hipotese do Gemini nao substitui o rotulo da politica, fica ao lado
    F = v7.features(kb.load(acquired_path=acq_path))
    f = F["Incident_CVE_2026_111357"]
    assert f["sol"] == "CoA_RotateCredentials" and set(f["sols"]) == {"CoA_RotateCredentials", "CoA_Patch"}
    # segunda analise do mesmo incidente: recusada
    assert CaseAcquirer(gemini=client, acquired_path=acq_path).analyze("CVE-2026-111357")["status"] == "rejected"


def test_invalid_solution_from_model_is_rejected(tmp_path, sources):
    kev, ctid = sources
    acq_path = str(tmp_path / "acquired.ttl")
    bad = case_answer("CoA_FormatDisk")                    # fora da lista fechada de acoes da ontologia
    client = gm.GeminiClient(model="gemini-test", mode="cached", cache_dir=str(tmp_path / "gem"),
                             transport=gm.ScriptedTransport([answer(), bad, bad]))
    va = VulnAcquirer(gemini=client, catalogs=Catalogs(), nvd=FixtureNVD(), kev=kev, ctid=ctid, acquired_path=acq_path)
    with pytest.raises(gm.GeminiError):
        CaseAcquirer(gemini=client, acquired_path=acq_path, vuln_acquirer=va, nvd=FixtureNVD()).analyze("CVE-2026-111357")
    g = Graph().parse(acq_path, format="turtle")
    assert (OC.Case_LLM_CVE_2026_111357, None, None) not in g


def test_retain_resolved_alert_from_webhook(tmp_path):
    import soar_webhook as sw
    acq_path = str(tmp_path / "acquired.ttl")
    eng = sw.Engine(kb.REAL, reasoner="none", acquired=acq_path)
    code, res = eng.handle({"src_ip": "203.0.113.9", "attack_type": "SQLi", "target": "Database_1", "cvss": 9.1,
                            "attribute": "confidentiality", "alert_id": "A-77"})
    assert code == 200
    n0 = eng.n_incidents
    assert eng.retain({"alert_id": "A-77", "solution": "CoA_Nope", "analyst": "ana", "rationale": "x" * 20})[0] == 400
    code, body = eng.retain({"alert_id": "A-77", "solution": "CoA_Isolate", "analyst": "Analista 1",
                             "rationale": "Exfiltracao em curso: isolar antes de corrigir."})
    assert code == 200 and body["status"] == "written", body
    assert body["hermit"]["consistent"] and eng.n_incidents == n0 + 1      # base recarregada
    g = Graph().parse(acq_path, format="turtle")
    C = OC.Case_Retained_A_77
    assert str(g.value(C, OC.solutionProvenance)) == "analyst:retain" and g.value(C, OC.hasSolution) == OC.CoA_Isolate
    assert (OC.Incident_Alert_A_77, OC.hasAttribute, OC.State_Confidentiality) in g
    assert eng.retain({"alert_id": "A-77", "solution": "CoA_Isolate", "analyst": "a", "rationale": "y" * 20})[0] == 404
    # o caso retido e recuperavel e tem prioridade (desfecho observado)
    assert v7.features(kb.load(acquired_path=acq_path))["Incident_Alert_A_77"]["sol"] == "CoA_Isolate"


def test_retain_incomplete_alert_is_blocked_by_shacl(tmp_path):
    import soar_webhook as sw
    acq_path = str(tmp_path / "acquired.ttl")
    eng = sw.Engine(kb.REAL, reasoner="none", acquired=acq_path)
    eng.handle({"src_ip": "198.51.100.4", "attack_type": "xss", "target": "Workstation_1", "alert_id": "B-1"})  # sem cvss
    code, body = eng.retain({"alert_id": "B-1", "solution": "CoA_WAFRule", "analyst": "a", "rationale": "Bloquear o padrao no WAF."})
    assert code == 422 and any("CVSS" in m for m in body["violations"])
    assert not os.path.exists(acq_path)
