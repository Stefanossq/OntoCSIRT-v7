"""Testes de aceitacao (tabela pedida), num so cenario de ponta a ponta sobre o perfil REAL
(OntoCSIRT_v7_real.ttl + extensao + evolucao + dados adquiridos), com copias temporarias dos ficheiros.

| Teste                          | Resultado esperado            |
|--------------------------------|-------------------------------|
| Inserir CVE real               | Novo individuo OWL            |
| Analisar vulnerabilidade       | Novo caso CBR                 |
| Identificar conceito ausente   | Proposta de nova classe       |
| Identificar relacao ausente    | Nova Object Property          |
| Aprovar proposta               | Alteracao efetiva no OWL      |
| Executar HermiT                | Ontologia consistente         |
| Executar SHACL                 | Restricoes atendidas          |

O Gemini e simulado (ScriptedTransport) com respostas plausiveis; tudo o resto e real: registos KEV/NVD,
catalogos CWE 5.0 e ATT&CK 16.1, compilador, SHACL, HermiT, Pellet, questoes de competencia."""
import json
import shutil

import pytest
from rdflib import Graph
from rdflib.namespace import OWL, RDF, RDFS

import ingest_real_cases as ing
import ontocsirt_v7 as v7
import validar_ingestao as val
from ontoevo import agent as agent_mod
from ontoevo import gemini as gm
from ontoevo import kb, proposals, signals
from ontoevo.cases import CaseAcquirer
from ontoevo.catalogs import Catalogs
from ontoevo.enrich import VulnAcquirer

from conftest import EVO_EMPTY
from test_cases import case_answer
from test_enrich import FixtureNVD, answer

OC = v7.OC
MEMORY = ["CVE-2025-5777", "CVE-2025-27038", "CVE-2025-27363", "CVE-2025-6554"]

SECONDARY = {
    "kind": "new_object_property", "signal_id": "literal-relation:otherCweIds",
    "property_name": "hasSecondaryWeakness", "domain": "Vulnerability", "range": "Weakness",
    "label_pt": "tem fraqueza secundaria", "label_en": "has secondary weakness",
    "definition": "Fraqueza CWE adicional atribuida a vulnerabilidade pela fonte (KEV/NVD), alem da fraqueza principal "
                  "(hasWeakness). Substitui a lista textual em otherCweIds por uma relacao com o individuo Weakness.",
    "assertions": [{"subject": "Vuln_CVE_2026_111357", "object": "CWE_862"}],
    "rationale": "otherCweIds guarda identificadores de individuos Weakness como texto; a relacao fica invisivel ao "
                 "raciocinador e ao CBR. CWE-862 ja e um individuo da ontologia (AccessControlWeakness).",
    "evidence": [{"source": "ontology", "ref": "otherCweIds", "note": "anotacao textual 'CWE-862 CWE-345'"},
                 {"source": "kev", "ref": "CVE-2026-111357", "note": "KEV lista CWE-306, CWE-862, CWE-345"}],
    "confidence": 0.85,
}

BUFFER = {
    "kind": "new_class", "signal_id": "heterogeneous:MemorySafetyWeakness", "class_name": "MemoryBufferBoundsWeakness",
    "parent": "MemorySafetyWeakness", "label_pt": "Violacao dos limites de buffer de memoria",
    "label_en": "Memory buffer bounds violation",
    "definition": "Fraqueza de seguranca de memoria em que a operacao le ou escreve fora dos limites do buffer "
                  "(ramo oficial CWE-119 da vista 1000).",
    "members": [{"individual": "CWE_787", "justification": "CWE-787 ChildOf CWE-119"},
                {"individual": "CWE_125", "justification": "CWE-125 ChildOf CWE-119"},
                {"individual": "CWE_416", "justification": "CWE-416 ChildOf CWE-825 ChildOf CWE-119"}],
    "rationale": "Tres das quatro CWEs de MemorySafetyWeakness descendem de CWE-119; CWE-843 (confusao de tipos) "
                 "pertence a CWE-704.",
    "evidence": [{"source": "cwe", "ref": "CWE-119", "note": "Improper Restriction of Operations within the Bounds of a Memory Buffer"}],
    "confidence": 0.8,
}


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    d = tmp_path_factory.mktemp("acc")
    mp = pytest.MonkeyPatch()
    for name, src in (("evo", EVO_EMPTY), ("real", kb.REAL)):
        shutil.copy(src, d / ("%s.ttl" % name))
    mp.setattr(val, "EVO", str(d / "evo.ttl"))
    mp.setattr(kb, "REAL", str(d / "real.ttl"))
    mp.setitem(kb.PROFILES, "real", str(d / "real.ttl"))
    mp.setattr(kb, "BACKUPS", str(d / "backups"))
    _, kev = ing.load_kev()
    _, ctid = ing.load_ctid()
    st = {"d": d, "acq": str(d / "acquired.ttl"), "kev": kev, "ctid": ctid,
          "store": proposals.Store(directory=str(d / "proposals"), evo_path=str(d / "evo.ttl"),
                                   changelog=str(d / "CHANGELOG.json"), profile="real", acquired_path=str(d / "acquired.ttl"))}
    yield st
    mp.undo()


@pytest.fixture(autouse=True)
def _module_evo(world, monkeypatch):
    """Cada teste usa o modulo de evolucao temporario deste cenario (o conftest aponta para o vazio)."""
    monkeypatch.setattr(val, "EVO", str(world["d"] / "evo.ttl"))


def client(w, turns, name):
    return gm.GeminiClient(model="gemini-test", mode="cached", cache_dir=str(w["d"] / name),
                           transport=gm.ScriptedTransport(turns))


def test_1_insert_real_cve_creates_owl_individual(world):
    va = VulnAcquirer(gemini=client(world, [answer()], "g1"), catalogs=Catalogs(), nvd=FixtureNVD(),
                      kev=world["kev"], ctid=world["ctid"], acquired_path=world["acq"])
    r = va.acquire("CVE-2026-111357")
    assert r["status"] == "written"
    g = kb.load(acquired_path=world["acq"])
    V = OC.Vuln_CVE_2026_111357
    assert (V, RDF.type, OC.Vulnerability) in g and str(g.value(V, OC.otherCweIds)) == "CWE-862 CWE-345"
    # mais 4 CVEs reais de seguranca de memoria (CWE e tecnica nas fontes: sem Gemini)
    va2 = VulnAcquirer(catalogs=Catalogs(), nvd=FixtureNVD(), kev=world["kev"], ctid=world["ctid"],
                       acquired_path=world["acq"], use_llm=False, use_pellet=False)
    for cve in MEMORY:
        assert va2.acquire(cve)["status"] == "written"


def test_2_analyze_vulnerability_creates_cbr_case(world):
    ca = CaseAcquirer(gemini=client(world, [case_answer()], "g2"), acquired_path=world["acq"], nvd=FixtureNVD())
    r = ca.analyze("CVE-2026-111357")
    assert r["status"] == "written" and r["case"] == "Case_LLM_CVE_2026_111357"
    g = kb.load(acquired_path=world["acq"])
    assert (OC.Case_LLM_CVE_2026_111357, RDF.type, OC.Case) in g


def test_3_missing_concept_becomes_new_class_proposal(world):
    g = kb.load(acquired_path=world["acq"])
    sig = {s["id"]: s for s in signals.detect(g, Catalogs())}
    assert "heterogeneous:MemorySafetyWeakness" in sig
    turns = [{"interaction_id": "e0", "function_calls": [{"id": "1", "name": "lookup_cwe", "arguments": {"cwe_id": "CWE-787"}}]},
             {"interaction_id": "e1", "output_text": "ok"},
             {"interaction_id": "e2", "model": "gemini-test", "output_text": json.dumps({"proposals": [BUFFER]})}]
    ag = agent_mod.EvolutionAgent(gemini=client(world, turns, "g3"), profile="real", acquired_path=world["acq"])
    batch, meta = ag.propose(sig["heterogeneous:MemorySafetyWeakness"])
    rec = world["store"].create(batch.proposals[0], "gemini:gemini-test", signal=batch.proposals[0].signal_id, llm_meta=meta)
    assert rec["status"] == "pending" and rec["compiled"]["new_classes"] == ["MemoryBufferBoundsWeakness"]
    world["class_id"] = rec["id"]


def test_4_missing_relation_becomes_object_property(world):
    g = kb.load(acquired_path=world["acq"])
    sig = {s["id"]: s for s in signals.detect(g, Catalogs())}
    rel = sig["literal-relation:otherCweIds"]
    assert any(r["refers_to"] == "CWE_862" for r in rel["data"]["rows"])
    rec = world["store"].create(SECONDARY, "analyst:teste", signal=rel["id"])
    assert rec["status"] == "pending", rec["gate"]
    assert rec["compiled"]["new_properties"] == ["hasSecondaryWeakness"]
    world["prop_id"] = rec["id"]


def test_5_approved_proposals_change_the_owl(world):
    st = world["store"]
    for pid in (world["class_id"], world["prop_id"]):
        st.approve(pid, "Analista Teste")
        assert st.apply(pid)["status"] == "applied"
    evo = Graph().parse(world["d"] / "evo.ttl", format="turtle")
    assert (OC.MemoryBufferBoundsWeakness, RDFS.subClassOf, OC.MemorySafetyWeakness) in evo
    assert (OC.hasSecondaryWeakness, RDF.type, OWL.ObjectProperty) in evo
    assert (OC.Vuln_CVE_2026_111357, OC.hasSecondaryWeakness, OC.CWE_862) in evo
    assert '"evo-2"' in (world["d"] / "evo.ttl").read_text(encoding="utf-8")


def test_6_hermit_consistent_and_7_shacl_conforms(world):
    g = kb.load(acquired_path=world["acq"])
    ok, _, unsat = v7.run_hermit(g)
    assert ok and [c for c in unsat if c != "Nothing"] == []
    rep = val.validate(g, use_pellet=True)
    assert rep["conforms"], rep["violations"]
    assert rep["pellet"]["consistent"]
