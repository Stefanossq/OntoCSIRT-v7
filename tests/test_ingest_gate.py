"""Portao de ingestao (validar_ingestao.py): o autoteste original tem de continuar a bloquear os 6 defeitos."""
import validar_ingestao as val


def test_selftest_blocks_all_defects():
    assert val.selftest() == 0


def test_extension_version_constant_matches_file():
    from rdflib import Graph, Literal
    from rdflib.namespace import OWL
    g = Graph().parse(val.EXT, format="turtle")
    assert (val.EXT_ONTOLOGY, OWL.versionInfo, Literal(val.EXT_VERSION)) in g


def test_real_kb_is_owl2_dl_for_hermit():
    """A base ingerida (com a extensao e o modulo de evolucao) tem de ser aceite pelo HermiT:
    antes da migracao m001 o range xsd:date de :kevDateAdded punha-a fora do OWL 2 DL."""
    import os
    from rdflib import Graph
    g = Graph().parse(os.path.join(val.HERE, "OntoCSIRT_v7_real.ttl"), format="turtle")
    rep = val.validate(g, use_pellet=True, use_hermit=True)
    assert rep["conforms"], rep["violations"]
    assert rep["hermit"]["consistent"] and rep["hermit"]["unsatisfiable_classes"] == []
    assert rep["pellet"]["consistent"]
