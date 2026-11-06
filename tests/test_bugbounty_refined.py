"""Lapidacao bb-2 (ontology/bugbounty_refined.ttl, P1-P19) e ferramentas do hunter (ontology/hunter_tools.ttl,
P20-P22): composicao, rastreabilidade das fontes, classificacao automatica (HermiT) e axiomas que DEVEM tornar a
ontologia inconsistente quando violados. Relatorio: docs/bugbounty_refined_relatorio.md."""
import contextlib
import io
import os
import tempfile

import owlready2 as o2
import pytest
from rdflib import BNode, Graph, Literal, URIRef
from rdflib.collection import Collection
from rdflib.namespace import OWL, RDF, RDFS

import ingest_bugbounty as bb
import ontocsirt_v7 as v7

OC = v7.OC
BBNS = "http://www.semanticweb.org/ontocsirt/bugbounty#"
DCT_SOURCE = URIRef("http://purl.org/dc/terms/source")
PROPOSAL = URIRef(BBNS + "proposal")


@pytest.fixture(scope="module")
def composed():
    """Mesma composicao de tests/test_bugbounty.py: modulo de evolucao VAZIO."""
    import validar_ingestao as val
    from conftest import EVO_EMPTY
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(val, "EVO", EVO_EMPTY)
        return bb.compose(include_data=False)


def with_(g, triples=()):
    h = Graph()
    for t in g:
        h.add(t)
    for t in triples:
        h.add(t)
    return h


def realize(graph, names):
    """Tipos inferidos pelo HermiT (classes mais especificas, como o Owlready as mostra) de alguns individuos."""
    tmp = tempfile.NamedTemporaryFile(suffix=".owl", delete=False)
    tmp.close()
    try:
        v7.strip_swrl(graph).serialize(tmp.name, format="xml", encoding="utf-8")
        world = o2.World()
        world.get_ontology("file://" + tmp.name).load(format="rdfxml")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            o2.sync_reasoner_hermit(world, infer_property_values=False, debug=0)
        out = {}
        for n in names:
            ind = world[str(OC) + n]
            out[n] = {c.name for c in ind.INDIRECT_is_a if hasattr(c, "name")}
        return out
    finally:
        os.unlink(tmp.name)


def module_terms(path):
    g = Graph()
    g.parse(path, format="turtle")
    kinds = (OWL.Class, OWL.ObjectProperty, OWL.DatatypeProperty, OWL.NamedIndividual)
    return g, {s for k in kinds for s in g.subjects(RDF.type, k) if isinstance(s, URIRef)}


# ------------------------------------------------------------------ composicao e rastreabilidade
def test_compose_loads_refined_and_hunter(composed):
    assert (OC.PublicProgram, RDF.type, OWL.Class) in composed
    assert (OC.HunterTool, RDF.type, OWL.Class) in composed
    assert (OC.Tool_Nuclei, RDF.type, OC.ScanningTool) in composed


def test_composition_is_consistent_without_unsatisfiable_classes(composed):
    ok, _, unsat = v7.run_hermit(composed)
    assert ok
    assert sorted(set(unsat) - {"Nothing"}) == []


@pytest.mark.parametrize("path", [bb.REFINED, bb.HUNTER])
def test_every_new_term_has_source_proposal_and_label(path):
    """Regra da lapidacao: sem fonte, nao entra. Cada classe/propriedade tem dcterms:source; cada termo tem
    bb:proposal e rdfs:label."""
    g, terms = module_terms(path)
    assert terms
    for t in terms:
        assert list(g.objects(t, PROPOSAL)), "sem bb:proposal: %s" % t
        assert list(g.objects(t, RDFS.label)), "sem rdfs:label: %s" % t
        if (t, RDF.type, OWL.NamedIndividual) not in g:
            assert list(g.objects(t, DCT_SOURCE)), "sem dcterms:source: %s" % t


@pytest.mark.parametrize("path", [bb.REFINED, bb.HUNTER])
def test_at_most_one_label_per_language(path):
    g, terms = module_terms(path)
    for t in terms:
        langs = [l.language for l in g.objects(t, RDFS.label) if isinstance(l, Literal)]
        assert len(langs) == len(set(langs)), "rdfs:label repetido na mesma lingua: %s" % t


def test_refined_only_adds_to_existing_terms():
    """A lapidacao nao redefine termos do bb-1: nenhum dominio, contradominio ou superclasse novos em termos
    que ja existiam (so FunctionalProperty, anotacoes e a cardinalidade de :hasVisibility em :BugBountyProgram)."""
    old = Graph()
    old.parse(bb.MODULE, format="turtle")
    new = Graph()
    new.parse(bb.REFINED, format="turtle")
    old_terms = {s for s in old.subjects(RDF.type, None) if isinstance(s, URIRef)}
    for s, p, o in new:
        if s in old_terms and p in (RDFS.domain, RDFS.range, OWL.equivalentClass):
            pytest.fail("termo do bb-1 redefinido: %s %s" % (s, p))
        if s in old_terms and p == RDFS.subClassOf:
            assert s == OC.BugBountyProgram and isinstance(o, BNode)          # so a restricao de P1
        if s in old_terms and p == RDF.type:
            assert o == OWL.FunctionalProperty and s in (OC.eligibleForSubmission, OC.scopeType)


# ------------------------------------------------------------------ classificacao automatica
def test_existing_scopes_and_reward_are_classified(composed):
    r = realize(composed, ["Scope_DemoFintech_App", "Scope_DemoFintech_Net", "Scope_DemoSaaS_Wildcard", "Reward_001"])
    assert {"InScopeItem", "WebApplicationScope", "SpecificScope"} <= r["Scope_DemoFintech_App"]
    assert {"InScopeItem", "NetworkScope", "SpecificScope"} <= r["Scope_DemoFintech_Net"]
    assert {"InScopeItem", "WildcardScope"} <= r["Scope_DemoSaaS_Wildcard"]
    assert "SpecificScope" not in r["Scope_DemoSaaS_Wildcard"]
    assert "MonetaryReward" in r["Reward_001"]


def test_collaborative_and_duplicate_reports_are_inferred(composed):
    g = with_(composed, [(OC.Report_002, OC.submittedBy, OC.Researcher_SSRF),
                         (OC.Report_003, OC.duplicateOf, OC.Report_001)])
    d, lst = BNode(), BNode()
    Collection(g, lst, [OC.Researcher_XSS, OC.Researcher_SSRF])          # sem UNA: distintos declarados
    g.add((d, RDF.type, OWL.AllDifferent))
    g.add((d, OWL.distinctMembers, lst))
    r = realize(g, ["Report_002", "Report_003"])
    assert "CollaborativeReport" in r["Report_002"]
    assert "DuplicateReport" in r["Report_003"]


# ------------------------------------------------------------------ axiomas que recusam defeitos
X = OC.X_refined_test

INCONSISTENT = {
    "P15a WhiteHat e GrayHat no mesmo individuo": [(X, RDF.type, OC.WhiteHat), (X, RDF.type, OC.GrayHat)],
    "P13 duplicateOf reflexivo": [(OC.Report_001, OC.duplicateOf, OC.Report_001)],
    "P13 original e duplicata": [(OC.Report_002, OC.duplicateOf, OC.Report_001), (OC.Report_002, RDF.type, OC.OriginalReport)],
    "P1 publico e privado": [(OC.Program_DemoSaaS, OC.hasVisibility, OC.Visibility_Public),
                             (OC.Program_DemoSaaS, OC.hasVisibility, OC.Visibility_Private)],
    "P2 managed e self-managed": [(OC.Program_DemoSaaS, OC.hasManagementModel, OC.Management_Managed),
                                  (OC.Program_DemoSaaS, OC.hasManagementModel, OC.Management_SelfManaged)],
    "P4 dentro e fora do escopo": [(OC.Scope_DemoSaaS_Wildcard, OC.eligibleForSubmission, Literal(False))],
    "P7 recompensa nao monetaria com valor": [(OC.Reward_001, RDF.type, OC.NonMonetaryReward)],
    "P9 duas severidades no mesmo relatorio": [(OC.Report_001, OC.hasSeverityRating, OC.Severity_High),
                                               (OC.Report_001, OC.hasSeverityRating, OC.Severity_Critical)],
    "P20 ferramenta e nivel de severidade": [(OC.Tool_Nmap, RDF.type, OC.SeverityRating)],
    "P22 ferramenta ligada por :uses": [(OC.Researcher_IDOR, OC.uses, OC.Tool_Nmap)],
    "P18 targetsVulnerability sob relatedWeakness": [(OC.targetsVulnerability, RDFS.subPropertyOf, OC.relatedWeakness),
                                                    (OC.Report_001, OC.targetsVulnerability, OC.CWE_89)],
}


@pytest.mark.parametrize("name", sorted(INCONSISTENT))
def test_defect_makes_ontology_inconsistent(composed, name):
    assert v7.run_hermit(with_(composed, INCONSISTENT[name]))[0] is False, name


CONSISTENT = {
    "P3 relatorio com dois pesquisadores": [(OC.Report_002, OC.submittedBy, OC.Researcher_SSRF)],
    "P1/P2/P10/P12 programa completo": [
        (OC.Program_DemoSaaS, OC.hasVisibility, OC.Visibility_Public),
        (OC.Program_DemoSaaS, OC.hasManagementModel, OC.Management_SelfManaged),
        (OC.Program_DemoSaaS, OC.hasDisclosurePolicy, OC.CoordinatedDisclosure),
        (OC.Program_DemoSaaS, OC.hasDisclosureTimeline, OC.Timeline_HackerOneDefault)],
    "P18 relatorio visa CWE-89": [(OC.Report_001, OC.targetsVulnerability, OC.CWE_89)],
    "P22 Nuclei e Shodan": [(OC.Researcher_XSS, OC.usesTool, OC.Tool_Nuclei),
                            (OC.Tool_Shodan, OC.discovers, OC.Scope_DemoSaaS_Wildcard)],
}


@pytest.mark.parametrize("name", sorted(CONSISTENT))
def test_valid_usage_stays_consistent(composed, name):
    assert v7.run_hermit(with_(composed, CONSISTENT[name]))[0] is True, name
