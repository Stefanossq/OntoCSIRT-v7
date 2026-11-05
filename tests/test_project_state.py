"""Estado REAL do projeto (nao os ficheiros temporarios dos outros testes): a base composta com o modulo de
evolucao aplicado e os dados adquiridos tem de ser consistente (HermiT, Pellet), conforme (SHACL) e manter
as 8 questoes de competencia do artigo."""
import os

import pytest

import validar_ingestao as val
from ontoevo import evogate, kb

from conftest import PROJECT_EVO


@pytest.fixture
def project_evo(monkeypatch):
    monkeypatch.setattr(val, "EVO", PROJECT_EVO)


def test_project_composed_kb_is_consistent_and_conforms(project_evo):
    g = kb.load("real")
    rep = val.validate(g, use_pellet=True, use_hermit=True)
    assert rep["conforms"], rep["violations"]
    assert rep["hermit"]["consistent"] and rep["hermit"]["unsatisfiable_classes"] == []
    assert rep["pellet"]["consistent"]


def test_project_competency_questions(project_evo):
    cq, _ = evogate.competency(None)
    assert cq["consistent"] and cq["passed"] == cq["total"] == 8, cq


def test_provenance_annotations_are_not_structural_signals(project_evo):
    """evo:evidence/evo:rationale citam CWEs por natureza: nao sao relacoes escondidas em literais."""
    from ontoevo import signals
    from ontoevo.catalogs import Catalogs
    ids = {s["id"] for s in signals.detect(kb.load("real"), Catalogs())}
    assert not {i for i in ids if i.startswith("literal-relation:") and i.split(":")[1] in ("evidence", "rationale")}
    # as subcategorias aplicadas resolveram os seus sinais
    assert "heterogeneous:MemorySafetyWeakness" not in ids and "heterogeneous:InjectionWeakness" not in ids


def test_evo_changelog_matches_module(project_evo):
    import json
    import re
    log_path = os.path.join(kb.HERE, "evolution", "CHANGELOG.json")
    text = open(PROJECT_EVO, encoding="utf-8").read()
    n = int(re.search(r'owl:versionInfo "evo-(\d+)"', text).group(1))
    log = json.load(open(log_path, encoding="utf-8")) if os.path.exists(log_path) else []
    assert len(log) == n                                   # uma entrada por versao aplicada
    for e in log:
        assert "# %s (%s)" % (e["id"], e["version"]) in text
