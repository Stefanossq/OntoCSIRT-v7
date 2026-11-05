import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def isolated_evidence(tmp_path, monkeypatch):
    """Os subcomandos do v7 gravam evidence_v7/*.json: nos testes vao para uma pasta temporaria,
    para nao alterar as evidencias de referencia nem os numeros do artigo."""
    import ontocsirt_v7 as v7
    import validar_ingestao as val
    from ontoevo import kb
    monkeypatch.setattr(v7, "EVID", str(tmp_path / "evidence"))
    monkeypatch.setattr(kb, "BACKUPS", str(tmp_path / "backups"))   # copias de seguranca dos testes fora do projeto
    # o modulo de evolucao do projeto muda a cada proposta aplicada; os testes partem do modulo vazio (evo-0)
    # para serem reprodutiveis. O estado real do projeto e verificado em tests/test_project_state.py.
    monkeypatch.setattr(val, "EVO", EVO_EMPTY)
    yield


EVO_EMPTY = os.path.join(ROOT, "tests", "fixtures", "OntoCSIRT_v7_evo_empty.ttl")
PROJECT_EVO = os.path.join(ROOT, "OntoCSIRT_v7_evo.ttl")
