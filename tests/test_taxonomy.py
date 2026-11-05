"""Etapa 1: a hierarquia de classes passa a ser lida do grafo (ontotax) e nao de listas fixas.

O caso de referencia e o risco R1 da auditoria: criar SQLInjectionWeakness < InjectionWeakness e
classificar CWE-89 nela bloqueava a SHACL e fazia o Incident_04 desaparecer da recuperacao CBR."""
import json
import os

import pytest
from rdflib import Graph
from rdflib.namespace import OWL, RDF, RDFS

import ingest_real_cases as ing
import ontocsirt_v7 as v7
import ontotax
import validar_ingestao as val

OC = v7.OC
# evidencia LOOCV de referencia do artigo, congelada (copia de backup/v7_original_2026-11-03/evidence_v7/loocv.json,
# mesmo SHA-256): o backup/ nao vai para a imagem Docker, a fixture vai
REF_LOOCV = os.path.join(os.path.dirname(__file__), "fixtures", "reference_loocv_v7.json")


def evolved_graph():
    g = v7.base_graph()
    g.parse(val.EXT, format="turtle")
    g.add((OC.SQLInjectionWeakness, RDF.type, OWL.Class))
    g.add((OC.SQLInjectionWeakness, RDFS.subClassOf, OC.InjectionWeakness))
    g.add((OC.CWE_89, RDF.type, OC.SQLInjectionWeakness))   # aditivo: continua InjectionWeakness
    return g


@pytest.fixture(scope="module")
def evolved_inferred():
    ok, _, ig, _, _ = v7.run_pellet(evolved_graph())
    assert ok
    return ig


def test_second_level_subclass_passes_shacl_and_hermit():
    rep = val.validate(evolved_graph(), use_hermit=True)
    assert rep["conforms"], rep["violations"]
    assert rep["hermit"]["consistent"] and rep["hermit"]["unsatisfiable_classes"] == []


def test_incident_not_lost_from_cbr(evolved_inferred):
    F = v7.features(evolved_inferred)
    assert len(F) == 24                                     # nenhum incidente desaparece
    assert F["Incident_04"]["cat"] == "SQLInjectionWeakness"
    assert F["Incident_01"]["cat"] == "InjectionWeakness"   # CWE-77 fica na categoria de 1.o nivel


def test_taxonomic_similarity(evolved_inferred):
    F = v7.features(evolved_inferred)
    a, b = F["Incident_04"], F["Incident_01"]                # SQLi (nivel 2) vs injecao de comandos (nivel 1)
    # Wu-Palmer: LCS InjectionWeakness (prof. 1); profs 2 e 1 -> 2*1/3; credito parcial 0.5*wp
    assert ontotax.wu_palmer(a["tax"]["cat"]["SQLInjectionWeakness"], b["tax"]["cat"]["InjectionWeakness"],
                             "SQLInjectionWeakness", "InjectionWeakness") == pytest.approx(2 / 3)
    s_flat = v7.sim(dict(a, tax={}), dict(b, tax={}))       # sem hierarquia: categorias diferentes -> 0
    assert v7.sim(a, b) > s_flat


def test_alias_of_facet_root_is_collapsed():
    """:CWE = :Weakness (modulo de bug bounty; o Pellet exporta subClassOf nos dois sentidos): o alias nao pode
    parecer um nivel abaixo da raiz, senao categorias irmas ganhavam Wu-Palmer 1 em vez de 0."""
    g = Graph()
    for c in (OC.InjectionWeakness, OC.WebClientWeakness):
        g.add((c, RDFS.subClassOf, OC.Weakness))
    g.add((OC.CWE, RDFS.subClassOf, OC.Weakness))
    g.add((OC.Weakness, RDFS.subClassOf, OC.CWE))
    t = ontotax.Taxonomy(g)
    assert t.c(OC.CWE) == OC.Weakness and t.depth(OC.InjectionWeakness, OC.Weakness) == 1
    assert t.wu_palmer(OC.InjectionWeakness, OC.WebClientWeakness, OC.Weakness) == 0.0
    assert t.most_specific({OC.InjectionWeakness, OC.Weakness, OC.CWE}, OC.Weakness) == [OC.InjectionWeakness]
    g2 = Graph()                                              # owl:equivalentClass declarado tem o mesmo efeito
    g2.add((OC.InjectionWeakness, RDFS.subClassOf, OC.Weakness))
    g2.add((OC.CWE, OWL.equivalentClass, OC.Weakness))
    assert ontotax.Taxonomy(g2).c(OC.CWE) == OC.Weakness


def test_derived_classes_are_not_asset_types(evolved_inferred):
    F = v7.features(evolved_inferred)
    # Asset_Server_1 e RecurrentlyCriticalAsset (inferido por R3) mas o tipo para a similaridade e Server
    assert F["Incident_01"]["atype"] == "Server"
    assert F["Incident_01"]["atypes"] == ["Server"]


def test_loocv_identical_to_reference_per_query():
    """Na hierarquia de 2 niveis do artigo a similaridade taxonomica e identica a original, consulta a consulta."""
    with open(REF_LOOCV, encoding="utf-8") as f:
        ref = json.load(f)
    ok, _, ig, _, _ = v7.run_pellet(v7.base_graph())
    res = json.loads(json.dumps(v7.cmd_loocv(ig), default=str))
    assert res["summary"] == ref["summary"]
    assert res["ablation_acc1_without"] == ref["ablation_acc1_without"]
    assert res["per_query"] == ref["per_query"]


def test_policy_and_category_follow_the_ontology():
    ref = val.with_tbox(evolved_graph())
    assert ing.cwe_category("CWE-89", ref) == "SQLInjectionWeakness"      # a ontologia vence a tabela
    assert ing.cwe_category("CWE-9999", ref) == "OtherWeakness"           # ausente: tabela/residual
    assert ing.policy_action("SQLInjectionWeakness", "State_Confidentiality", ref) == "CoA_Isolate"  # herdada
    assert ing.policy_action("SQLInjectionWeakness", "State_Integrity", ref) == "CoA_Patch"
    ref.add((OC.SQLInjectionWeakness, OC.policyResponse, OC.CoA_WAFRule))  # anotacao na subclasse vence
    ing._TAX_CACHE.clear()
    assert ing.policy_action("SQLInjectionWeakness", "State_Confidentiality", ref) == "CoA_WAFRule"
    with pytest.raises(KeyError):
        ing.policy_action("CategoriaInexistente", "State_Integrity")


def test_real_kb_features_include_kev_cases():
    g = Graph().parse(os.path.join(v7.HERE, "OntoCSIRT_v7_real.ttl"), format="turtle")
    F = v7.features(val.with_tbox(g))
    kev = [i for i in F if i.startswith("Incident_CVE_")]
    assert len(kev) == 3 and all(F[i]["acat"] == "UnknownActor" for i in kev)


def test_webhook_once_without_reasoner():
    import soar_webhook as sw
    eng = sw.Engine(v7.TTL, reasoner="none")
    code, res = eng.handle({"src_ip": "1.2.3.4", "attack_type": "SQLi", "target": "Server_1", "cvss": 9.1,
                            "alert_id": "t1"})
    assert code == 200 and res["action_iri"] is not None and res["neighbors"]
