"""Modulo OntoBugBounty: coesao com o v7, regras BB-1/BB-2, classes definidas, dados de referencia e SHACL.
Os resultados esperados das regras sao recalculados a partir dos dados (o bloco de referencia e regeneravel)."""
import json
import os
import statistics

import pytest
from rdflib import Graph, Literal
from rdflib.namespace import RDF, RDFS, XSD

import ingest_bugbounty as bb
import ontocsirt_v7 as v7

OC = v7.OC
REF_LOOCV = os.path.join(os.path.dirname(__file__), "fixtures", "reference_loocv_v7.json")


@pytest.fixture(scope="module")
def composed():
    """Composicao com o modulo de evolucao VAZIO: isola o efeito do modulo de bug bounty (a fixture de modulo
    e criada antes do patch por teste do conftest; o evo-2 real muda, de proposito, a similaridade do v7)."""
    import validar_ingestao as val
    from conftest import EVO_EMPTY
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(val, "EVO", EVO_EMPTY)
        return bb.compose(include_data=False)


@pytest.fixture(scope="module")
def inferred(composed):
    ok, _, ig, _, world = v7.run_pellet(composed)
    assert ok, "Pellet: modulo inconsistente"
    return ig


def with_(g, triples=(), remove=()):
    h = Graph()
    for t in g:
        h.add(t)
    for t in remove:
        h.remove(t)
    for t in triples:
        h.add(t)
    return h


# ------------------------------------------------------------------ coesao com o v7
def test_reusing_v7_exploits_on_a_pattern_is_inconsistent():
    """Justifica :patternExploits: o :exploits do v7 tem dominio :ThreatAction, disjunto de :AttackPattern."""
    g = v7.base_graph()
    g.add((OC.AP_SQLInjection, OC.exploits, OC.Vuln_CVE_2023_34362))
    assert v7.run_hermit(g)[0] is False


def test_module_passes_shacl_hermit_and_pellet(composed, inferred):
    rep = bb.validate(composed)
    assert rep["conforms"], rep["violations"][:5]
    assert rep["hermit"]["consistent"] and rep["hermit"]["unsatisfiable_classes"] == []


def test_v7_competency_questions_unchanged_with_module(inferred):
    for cid, _, sparql, expected in v7.CQS:
        assert {r[0] for r in v7.q(inferred, sparql)} == expected, cid


def test_v7_retrieval_unchanged_with_module(inferred):
    with open(REF_LOOCV, encoding="utf-8") as f:
        ref = json.load(f)
    res = json.loads(json.dumps(v7.cmd_loocv(inferred), default=str))
    assert res["summary"] == ref["summary"] and res["per_query"] == ref["per_query"]


def test_researchers_are_authorized_and_not_threat_actors(inferred, composed):
    researchers = set(composed.subjects(RDF.type, OC.Researcher))
    assert len(researchers) == 6
    for r in researchers:
        types = set(inferred.objects(r, RDF.type))
        assert OC.AuthorizedResearcher in types              # participatedIn < authorizedBy + classe definida
        assert OC.ThreatActor not in types


def test_cve_is_a_defined_class(inferred):
    assert (OC.Vuln_CVE_2023_34362, RDF.type, OC.CVE) in inferred   # CVE do v7 classificada sozinha
    assert (OC.Vuln_L01, RDF.type, OC.CVE) not in inferred          # vulnerabilidade sintetica (sem cveId)


def test_insider_threat_is_internal_and_hats_are_disjoint():
    g = bb.compose(include_data=False)
    g.add((OC.Actor_X, RDF.type, OC.InsiderThreat))
    g.add((OC.Actor_X, RDF.type, OC.ExternalActor))               # interno e externo: disjuncao do v7
    assert v7.run_hermit(g)[0] is False
    g2 = bb.compose(include_data=False)
    g2.add((OC.Actor_Y, RDF.type, OC.BlackHat))
    g2.add((OC.Actor_Y, RDF.type, OC.GrayHat))
    assert v7.run_hermit(g2)[0] is False


# ------------------------------------------------------------------ regras SWRL
def expected_elite(g):
    out = set()
    for r in g.subjects(RDF.type, OC.Researcher):
        for ap in g.objects(r, OC.uses):
            if any(float(g.value(v, OC.cvssBaseScore)) >= 9.0 for v in g.objects(ap, OC.patternExploits)):
                out.add(r)
    return out


def test_bb1_elite_researcher(composed, inferred):
    elite = expected_elite(composed)
    assert elite, "os dados de referencia deviam produzir pelo menos um pesquisador de elite"
    assert set(inferred.subjects(RDF.type, OC.EliteResearcher)) == elite
    assert all((r, RDF.type, OC.Researcher) in inferred for r in elite)


def test_bb2_priority_reports(composed, inferred):
    elite = expected_elite(composed)
    expected = {rep for rep in composed.subjects(RDF.type, OC.Report)
                if any(r in elite for r in composed.objects(rep, OC.submittedBy))
                and any(str(composed.value(ap, OC.bountyPayout)) == "$$$" for ap in composed.objects(rep, OC.reportsPattern))}
    got = {s for s, o in inferred.subject_objects(OC.status) if str(o) == "Priority"}
    assert got == expected and OC.Report_001 in got and OC.Report_002 not in got
    assert "Triaged" in {str(o) for o in inferred.objects(OC.Report_001, OC.status)}   # o declarado continua


def test_skill_divergence_warning_on_inferred_graph(composed, inferred):
    """A forma de aviso (mundo fechado) corre sobre o grafo INFERIDO: Junior classificado como Elite."""
    from pyshacl import validate
    sg = Graph().parse(bb.SHAPES, format="turtle")
    conforms, rg, _ = validate(inferred, shacl_graph=sg, inference="none", allow_warnings=True)
    SH = "http://www.w3.org/ns/shacl#"
    warned = {v7.short(rg.value(r, bb.URIRef(SH + "focusNode"))) for r in rg.subjects(RDF.type, bb.URIRef(SH + "ValidationResult"))
              if rg.value(r, bb.URIRef(SH + "resultSeverity")) == bb.URIRef(SH + "Warning")}
    juniors_elite = {v7.short(r) for r in expected_elite(composed) if str(composed.value(r, OC.hasSkillLevel)) == "Junior"}
    assert warned == juniors_elite


# ------------------------------------------------------------------ dados de referencia
def test_owasp_patterns_have_real_cves_and_consistent_severity(composed):
    aps = set(composed.subjects(OC.owaspCategory, None))
    assert {OC.AP_IDOR, OC.AP_XSS, OC.AP_SQLInjection, OC.AP_SSRF, OC.AP_CommandInjection, OC.AP_Deserialization} <= aps
    for ap in aps:
        cves = list(composed.objects(ap, OC.patternExploits))
        assert len(cves) >= 2, ap
        scores = [float(composed.value(v, OC.cvssBaseScore)) for v in cves]
        assert all(str(composed.value(v, OC.cveId)).startswith("CVE-") for v in cves)
        assert all("nvd.nist.gov" in str(composed.value(v, bb.DCT.source)) for v in cves)
        mean = round(sum(scores) / len(scores), 2)
        assert float(composed.value(ap, OC.meanCvss)) == pytest.approx(mean, abs=0.01)
        assert str(composed.value(ap, OC.hasSeverity)) == bb.severity(mean)
        for v in cves:                                               # a CVE tem a CWE que o padrao visa
            assert composed.value(v, OC.hasWeakness) in set(composed.objects(ap, OC.targetsCWE))


def test_owasp_editions_from_cwe_catalog(composed):
    cats = set(composed.subjects(RDF.type, OC.OWASPCategory))
    assert len(cats) == 20
    ssrf = {str(composed.value(o, OC.owaspCode)) for o in composed.objects(OC.AP_SSRF, OC.owaspCategory)}
    assert ssrf == {"A10:2021", "A01:2025"}                         # SSRF passou para Broken Access Control em 2025
    assert (OC.OWASP_2021_A03, OC.includesWeakness, OC.CWE_89) in composed


@pytest.mark.skipif(not os.path.exists(bb.VRT_CACHE), reason="VRT ainda nao descarregado (ingest_bugbounty.py catalog)")
def test_bounty_payout_follows_bugcrowd_vrt(composed):
    with open(bb.VRT_CACHE, encoding="utf-8") as f:
        idx = bb.vrt_index(json.load(f))
    for ap, spec in bb.PATTERNS.items():
        pr = [p for nd in spec["vrt"] for p in bb.vrt_priorities(idx, nd)]
        assert str(composed.value(OC[ap], OC.bountyPayout)) == bb.TIERS[statistics.median_low(pr)], ap
    assert str(composed.value(OC.AP_SQLInjection, OC.bountyPayout)) == "$$$"


def test_targets_cwe_is_visible_to_v7_queries(inferred):
    rows = v7.q(inferred, "SELECT ?w WHERE { :AP_XXE :relatedWeakness ?w }")    # subpropriedade de relatedWeakness
    assert ("CWE_611",) in rows


# ------------------------------------------------------------------ SHACL: defeitos bloqueados
@pytest.mark.parametrize("name,add,remove,msg", [
    ("programa sem escopo", [], [(OC.Program_DemoSaaS, OC.hasScope, OC.Scope_DemoSaaS_Wildcard)], "Programa sem escopo"),
    ("pesquisador sem nivel", [], [(OC.Researcher_IDOR, OC.hasSkillLevel, Literal("Senior"))], "Pesquisador sem nivel"),
    ("relatorio sem programa", [], [(OC.Report_002, OC.submittedTo, OC.Program_DemoSaaS)], "Relatorio sem programa"),
    ("relatorio para programa invalido", [(OC.Report_002, OC.submittedTo, OC.Program_Bad),
                                          (OC.Program_Bad, RDF.type, OC.BugBountyProgram), (OC.Program_Bad, RDFS.label, Literal("x"))],
     [(OC.Report_002, OC.submittedTo, OC.Program_DemoSaaS), (OC.Report_002, OC.affectsScope, OC.Scope_DemoSaaS_Wildcard)],
     "nao cumpre"),
    ("escopo de outro programa", [(OC.Report_002, OC.affectsScope, OC.Scope_DemoFintech_Api)], [], "nao pertence ao programa"),
    ("faixa de recompensa invalida", [(OC.AP_XSS, OC.bountyPayout, Literal("$$$$"))], [], "Faixa de recompensa"),
    ("minimo maior que o maximo", [(OC.Program_DemoSaaS, OC.hasMinBounty, Literal("9000", datatype=XSD.decimal))],
     [(OC.Program_DemoSaaS, OC.hasMinBounty, Literal("50", datatype=XSD.decimal))], "maior que a maxima"),
])
def test_shacl_blocks_defects(composed, name, add, remove, msg):
    rep = bb.validate(with_(composed, add, remove), hermit=False)
    assert not rep["conforms"], name
    assert any(msg in v["message"] for v in rep["violations"]), [v["message"] for v in rep["violations"]]


def test_pattern_with_single_cve_is_blocked(composed):
    cves = list(composed.objects(OC.AP_IDOR, OC.patternExploits))
    rep = bb.validate(with_(composed, remove=[(OC.AP_IDOR, OC.patternExploits, v) for v in cves[1:]]), hermit=False)
    assert any("menos de 2 CVEs" in v["message"] for v in rep["violations"])


def test_severity_bands_match_rule_r1():
    assert [bb.severity(s) for s in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9)] == ["Critical", "High", "High", "Medium", "Medium", "Low"]
