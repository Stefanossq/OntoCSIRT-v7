"""Etapa 5: evolucao estrutural real - sinais nos dados -> proposta (Gemini simulado ou analista) ->
compilacao -> portao (SHACL, HermiT, Pellet, regressao) -> aprovacao -> alteracao efetiva no OWL.

Dados: 10 CVEs reais do KEV (registos NVD reais em tests/fixtures/nvd) adquiridos sobre a base do artigo.
Os ficheiros do projeto nao sao tocados: modulo de evolucao, dados e copias vao para uma pasta temporaria."""
import json
import os
import shutil

import pytest
from rdflib import Graph, Literal
from rdflib.namespace import OWL, RDF, RDFS

import ingest_real_cases as ing
import ontocsirt_v7 as v7
import validar_ingestao as val
from ontoevo import agent as agent_mod
from ontoevo import gemini as gm
from ontoevo import kb, proposals, signals
from ontoevo.catalogs import Catalogs
from ontoevo.enrich import VulnAcquirer

from conftest import EVO_EMPTY
from test_enrich import FixtureNVD

OC = v7.OC
CVES = ("CVE-2025-6558 CVE-2025-5777 CVE-2025-6554 CVE-2025-27038 CVE-2025-32709 CVE-2025-27363 CVE-2024-53197 "
        "CVE-2024-21413 CVE-2023-44487 CVE-2023-2868").split()


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("evo")
    evo = d / "OntoCSIRT_v7_evo.ttl"
    shutil.copy(EVO_EMPTY, evo)                 # modulo vazio (evo-0), independente do estado do projeto
    mp = pytest.MonkeyPatch()
    mp.setattr(val, "EVO", str(evo))
    mp.setattr(kb, "BACKUPS", str(d / "backups"))
    acquired = str(d / "acquired.ttl")
    _, kev = ing.load_kev()
    _, ctid = ing.load_ctid()
    acq = VulnAcquirer(catalogs=Catalogs(), profile="base", nvd=FixtureNVD(), kev=kev, ctid=ctid,
                       acquired_path=acquired, use_llm=False, use_pellet=False)
    for cve in CVES:
        r = acq.acquire(cve)
        assert r["status"] == "written", r
    store = proposals.Store(directory=str(d / "proposals"), evo_path=str(evo), changelog=str(d / "CHANGELOG.json"),
                            profile="base", acquired_path=acquired)
    yield {"dir": d, "evo": str(evo), "acquired": acquired, "store": store}
    mp.undo()


@pytest.fixture(autouse=True)
def _module_evo(env, monkeypatch):
    """O conftest aponta val.EVO para o modulo vazio em cada teste; aqui cada teste usa o modulo temporario
    onde este ficheiro aplica as suas propostas (estado partilhado, por ordem)."""
    monkeypatch.setattr(val, "EVO", env["evo"])


def g_of(env):
    return kb.load("base", acquired_path=env["acquired"])


def sig_by_id(env):
    return {s["id"]: s for s in signals.detect(g_of(env), Catalogs())}


BUFFER = {
    "kind": "new_class", "signal_id": "heterogeneous:MemorySafetyWeakness",
    "class_name": "MemoryBufferBoundsWeakness", "parent": "MemorySafetyWeakness",
    "label_pt": "Violacao dos limites de buffer de memoria", "label_en": "Memory buffer bounds violation",
    "definition": "Fraqueza de seguranca de memoria em que a operacao le ou escreve fora dos limites do buffer "
                  "(ramo oficial CWE-119 da vista 1000).",
    "disjoint_with_siblings": False,
    "members": [{"individual": "CWE_787", "justification": "CWE-787 ChildOf CWE-119"},
                {"individual": "CWE_125", "justification": "CWE-125 ChildOf CWE-119"},
                {"individual": "CWE_416", "justification": "CWE-416 ChildOf CWE-825 ChildOf CWE-119"}],
    "rationale": "Tres das quatro CWEs de MemorySafetyWeakness na base descendem de CWE-119; CWE-843 (confusao de "
                 "tipos) pertence a CWE-704. A subcategoria separa as violacoes de limites, que partilham mitigacoes.",
    "evidence": [{"source": "cwe", "ref": "CWE-119", "note": "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
                 {"source": "signal", "ref": "heterogeneous:MemorySafetyWeakness", "note": "3 de 4 sob CWE-119"}],
    "confidence": 0.8,
}

MITIGATES = {
    "kind": "new_object_property", "signal_id": "cooccurrence:AttackPattern-ResolutionAction",
    "property_name": "mitigatesPattern", "domain": "CourseOfAction", "range": "AttackPattern",
    "inverse_name": "typicallyMitigatedBy",
    "label_pt": "mitiga o padrao", "label_en": "mitigates pattern",
    "definition": "Curso de acao que tipicamente mitiga um padrao de ataque abstrato (cf. relacao STIX 2.1 "
                  "course-of-action mitigates attack-pattern). Conhecimento ao nivel do tipo, nao do incidente.",
    "assertions": [{"subject": "CoA_RotateCredentials", "object": "AP_CredentialAbuse"},
                   {"subject": "CoA_WAFRule", "object": "AP_XSS"},
                   {"subject": "CoA_Segment", "object": "AP_SSRF"}],
    "rationale": "Nos casos da base os padroes CredentialAbuse, XSS e SSRF convergem em 100% para a mesma acao; a "
                 "ontologia so liga acoes a incidentes (mitigatedBy), nao a padroes. A relacao generaliza o que os casos mostram.",
    "evidence": [{"source": "ontology", "ref": "mitigatedBy", "note": "so existe ao nivel do incidente"},
                 {"source": "signal", "ref": "cooccurrence:AttackPattern-ResolutionAction", "note": "suporte 3/3, 3/3, 2/2"}],
    "confidence": 0.7,
}


def test_signals_detect_missing_concepts_and_relations(env):
    s = sig_by_id(env)
    het = s["heterogeneous:MemorySafetyWeakness"]
    assert het["data"]["official_groups"][0]["cwe_ancestor"] in ("CWE-119", "CWE-118")
    assert set(het["data"]["official_groups"][0]["members"]) == {"CWE_125", "CWE_416", "CWE_787"}
    assert set(s["residual:OtherWeakness"]["data"]["members"]) == {"CWE_20", "CWE_400"}
    pairs = {(p["pattern"], p["solution"]) for p in s["cooccurrence:AttackPattern-ResolutionAction"]["data"]["pairs"]}
    assert ("AP_CredentialAbuse", "CoA_RotateCredentials") in pairs


def test_agent_with_tools_proposes_new_class(env):
    """Gemini simulado que USA as ferramentas reais (hierarquia, catalogo CWE, verificacao a seco)."""
    turns = [
        {"interaction_id": "a0", "function_calls": [
            {"id": "f1", "name": "get_class_hierarchy", "arguments": {"root": "MemorySafetyWeakness"}},
            {"id": "f2", "name": "lookup_cwe", "arguments": {"cwe_id": "CWE-416"}}]},
        {"interaction_id": "a1", "function_calls": [{"id": "f3", "name": "dry_run_proposal", "arguments": {"proposal": BUFFER}}]},
        {"interaction_id": "a2", "output_text": "pronto"},
        {"interaction_id": "a3", "model": "gemini-test", "output_text": json.dumps({"proposals": [BUFFER]})},
    ]
    client = gm.GeminiClient(model="gemini-test", mode="cached", cache_dir=str(env["dir"] / "gem"),
                             transport=gm.ScriptedTransport(turns))
    ag = agent_mod.EvolutionAgent(gemini=client, catalogs=Catalogs(), profile="base", acquired_path=env["acquired"])
    batch, meta = ag.propose(sig_by_id(env)["heterogeneous:MemorySafetyWeakness"])
    trace = {t["tool"]: t for t in meta["trace"]}
    assert '"CWE-825"' in trace["lookup_cwe"]["result_preview"]           # catalogo oficial consultado
    assert '"ok": true' in trace["dry_run_proposal"]["result_preview"]    # a proposta passou SHACL+HermiT a seco
    assert len(client.transport().requests[0]["tools"]) == 8
    rec = env["store"].create(batch.proposals[0], "gemini:gemini-test", signal=batch.proposals[0].signal_id, llm_meta=meta)
    assert rec["status"] == "pending", json.dumps(rec["gate"], indent=1)[:3000]
    env["buffer_id"] = rec["id"]
    names = {c["name"]: c["ok"] for c in rec["gate"]["checks"]}
    assert all(names.values()) and "HermiT: sem redundancia (equivalencia inferida)" in names


def test_missing_relation_becomes_object_property_proposal(env):
    rec = env["store"].create(MITIGATES, "analyst:teste")
    assert rec["status"] == "pending", rec["gate"]
    assert rec["compiled"]["new_properties"] == ["mitigatesPattern", "typicallyMitigatedBy"]
    env["mitigates_id"] = rec["id"]


def test_apply_requires_approval(env):
    with pytest.raises(proposals.ProposalError):
        env["store"].apply(env["buffer_id"])


def test_approved_class_changes_the_owl(env):
    st = env["store"]
    st.approve(env["buffer_id"], "Analista Teste", "ancorada em CWE-119")
    rec = st.apply(env["buffer_id"])
    assert rec["status"] == "applied" and rec["applied"]["evo_version"] == "evo-1"
    assert rec["applied"]["verification"]["ok"] and rec["applied"]["verification"]["competency"] == "8/8"
    evo = Graph().parse(env["evo"], format="turtle")
    C = OC.MemoryBufferBoundsWeakness
    assert (C, RDF.type, OWL.Class) in evo and (C, RDFS.subClassOf, OC.MemorySafetyWeakness) in evo
    assert (OC.CWE_787, RDF.type, C) in evo and evo.value(C, proposals.compiler.EVO.approvedBy) == Literal("Analista Teste")
    # modulo autossuficiente: a identidade da CWE classificada vai com ela (nao depende do ficheiro de dados)
    assert (OC.CWE_787, OC.cweId, Literal("CWE-787")) in evo
    g = g_of(env)
    rep = val.validate(g, use_pellet=True, use_hermit=True)
    assert rep["conforms"] and rep["hermit"]["consistent"] and not rep["hermit"]["unsatisfiable_classes"] and rep["pellet"]["consistent"]
    F = v7.features(g)                                       # o CBR passa a usar a subcategoria
    assert F["Incident_CVE_2025_27363"]["cat"] == "MemoryBufferBoundsWeakness"
    assert F["Incident_CVE_2025_6554"]["cat"] == "MemorySafetyWeakness"     # CWE-843 fica no 1.o nivel
    assert ing.policy_action("MemoryBufferBoundsWeakness", "State_Integrity", g) == "CoA_Patch"  # herdada
    with open(env["dir"] / "CHANGELOG.json", encoding="utf-8") as f:
        assert json.load(f)[0]["new_classes"] == ["MemoryBufferBoundsWeakness"]


def test_approved_property_changes_the_owl(env):
    st = env["store"]
    st.approve(env["mitigates_id"], "Analista Teste")
    rec = st.apply(env["mitigates_id"])
    assert rec["applied"]["evo_version"] == "evo-2"
    g = g_of(env)
    assert (OC.mitigatesPattern, RDF.type, OWL.ObjectProperty) in g
    assert (OC.CoA_WAFRule, OC.mitigatesPattern, OC.AP_XSS) in g
    assert (OC.typicallyMitigatedBy, OWL.inverseOf, OC.mitigatesPattern) in g
    ok, _, ig, _, world = v7.run_pellet(g)
    assert ok
    # Owlready2 trata owl:inverseOf nativamente (nao materializa a tripla inversa na exportacao, como ja
    # acontece com hasAsset/isAssetOf do v7): pergunta-se ao modelo OWL
    xss = world[str(OC) + "AP_XSS"]
    assert [x.name for x in xss.typicallyMitigatedBy] == ["CoA_WAFRule"]
    assert "cooccurrence:AttackPattern-ResolutionAction" not in sig_by_id(env)  # sinal resolvido


def test_residual_category_exit_with_policy(env):
    base = {"kind": "new_class", "signal_id": "residual:OtherWeakness", "class_name": "InputValidationWeakness",
            "parent": "Weakness", "label_pt": "Validacao de entrada inadequada", "label_en": "Improper input validation",
            "definition": "Fraqueza em que a entrada nao e validada quanto as propriedades exigidas antes de ser processada (CWE-20).",
            "disjoint_with_siblings": True, "members": [{"individual": "CWE_20", "justification": "e a propria CWE-20"}],
            "rationale": "CWE-20 aparece em 3 CVEs do KEV na base e esta na categoria residual; e uma fraqueza de classe "
                         "propria na CWE, distinta das injecoes (CWE-74), ambas sob o pilar CWE-707.",
            "evidence": [{"source": "cwe", "ref": "CWE-20", "note": "Improper Input Validation, ChildOf CWE-707"}],
            "confidence": 0.75}
    st = env["store"]
    assert st.create(base, "analyst:teste")["status"] == "invalid"            # sem politica de resposta
    rec = st.create(dict(base, policy_response="CoA_Patch"), "analyst:teste")
    assert rec["status"] == "pending", rec["gate"]
    assert rec["compiled"]["retractions"] == [["CWE_20", "type", "OtherWeakness"]]
    st.approve(rec["id"], "Analista Teste")
    st.apply(rec["id"])
    acq = Graph().parse(env["acquired"], format="turtle")
    assert (OC.CWE_20, RDF.type, OC.OtherWeakness) not in acq                 # saiu da categoria residual
    g = g_of(env)
    assert (OC.CWE_20, RDF.type, OC.InputValidationWeakness) in g and (OC.InputValidationWeakness, OWL.disjointWith, OC.InjectionWeakness) in g
    assert ing.cwe_category("CWE-20", g) == "InputValidationWeakness"         # a ingestao seguinte usa-a


def test_gate_blocks_unsatisfiable_class(env):
    bad = {"kind": "new_class", "signal_id": "teste:unsat", "class_name": "InjectionVulnerabilityMix", "parent": "InjectionWeakness",
           "label_pt": "Mistura impossivel", "definition": "Fraqueza que tem ela propria uma fraqueza (definicao incoerente de proposito).",
           "defined_by": {"property": "hasWeakness", "kind": "someValuesFrom", "value": "Weakness"},
           "rationale": "Caso de teste: hasWeakness tem dominio Vulnerability, disjunta de Weakness; a classe e impossivel.",
           "evidence": [{"source": "ontology", "ref": "hasWeakness", "note": "dominio Vulnerability"}], "confidence": 0.1}
    rec = env["store"].create(bad, "analyst:teste", regression=False)
    assert rec["status"] == "failed-gate"
    failed = {c["name"]: c["detail"] for c in rec["gate"]["checks"] if not c["ok"]}
    assert "InjectionVulnerabilityMix" in failed["HermiT: classes insatisfaziveis"]


def test_defined_class_classifies_by_reasoning_and_redundancy_is_blocked(env):
    sqli = {"kind": "new_class", "signal_id": "teste:defined", "class_name": "SQLInjectionVulnerability", "parent": "Vulnerability",
            "label_pt": "Vulnerabilidade de injecao de SQL", "definition": "Vulnerabilidade cuja fraqueza e a CWE-89 (injecao de SQL).",
            "defined_by": {"property": "hasWeakness", "kind": "hasValue", "value": "CWE_89"},
            "rationale": "Classe definida (condicao necessaria e suficiente): o raciocinador classifica as vulnerabilidades sozinho.",
            "evidence": [{"source": "cwe", "ref": "CWE-89", "note": "SQL Injection"}], "confidence": 0.6}
    st = env["store"]
    rec = st.create(sqli, "analyst:teste", regression=False)
    assert rec["status"] == "pending", rec["gate"]
    inferred = set(rec["gate"]["classification"]["classes"]["SQLInjectionVulnerability"]["inferred_members"])
    assert {"Vuln_CVE_2023_34362", "Vuln_L01"} <= inferred                      # classificados pelo HermiT
    st.approve(rec["id"], "Analista Teste")
    st.apply(rec["id"])
    dup = dict(sqli, class_name="SqlInjectionFlaw", label_pt="Falha de injecao de SQL")
    rec2 = st.create(dup, "analyst:teste", regression=False)
    assert rec2["status"] == "failed-gate"
    red = next(c for c in rec2["gate"]["checks"] if c["name"].startswith("HermiT: sem redundancia"))
    assert red["detail"] == {"SqlInjectionFlaw": ["SQLInjectionVulnerability"]}


def test_compiler_rejects_structural_errors(env):
    st = env["store"]
    cross = dict(BUFFER, class_name="AnotherBufferClass", label_pt="Outra classe de buffer",
                 members=[{"individual": "CWE_89", "justification": "erro: injecao nao e memoria"}])
    rec = st.create(cross, "analyst:teste")
    assert rec["status"] == "invalid" and "outro ramo" in " ".join(rec["compiled"]["errors"])
    core = dict(BUFFER, class_name="SpecialIncident", parent="Incident", label_pt="Incidente especial", members=None)
    assert "nucleo protegido" in " ".join(st.create(core, "analyst:teste")["compiled"]["errors"])
    with pytest.raises(proposals.ProposalError):
        st.approve(rec["id"], "x")                                            # invalida nao se aprova
