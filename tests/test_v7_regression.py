"""Regressao do v7: os numeros do artigo (README, evidence_v7/SUMMARY.json) nao podem mudar."""
import hashlib
import os

import pytest

import ontocsirt_v7 as v7

V7_SHA256 = "8c2fc5f00faee4bf5a4b8e38a96d8ed2b92da8f28c825f49eda68a80b1720e69"


@pytest.fixture(scope="module")
def inferred():
    ok, _, ig, _, _ = v7.run_pellet(v7.base_graph())
    assert ok
    return ig


def test_v7_ttl_is_frozen():
    with open(v7.TTL, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == V7_SHA256, "OntoCSIRT_v7.ttl nao pode ser alterado"


def test_consistency_hermit_pellet_shacl():
    res, _ = v7.cmd_consistency()
    assert res["hermit_consistent"] and res["hermit_unsatisfiable_classes"] == []
    assert res["pellet_consistent"] and res["shacl_conforms"]
    m = res["metrics"]
    assert (m["classes"], m["object_properties"], m["data_properties"], m["incidents"], m["cases"], m["swrl_rules"]) \
        == (28, 17, 6, 24, 24, 8)


def test_competency_questions(inferred):
    assert v7.cmd_cq(inferred)["passed"] == 8


def test_rule_tests():
    res = v7.cmd_ruletests()
    assert res["passed"] == res["total"] == 20


def test_mutations():
    res = v7.cmd_mutations()
    assert res["detected"] == res["total"] == 10


def test_loocv_numbers(inferred):
    s = v7.cmd_loocv(inferred)["summary"]
    assert s["majority"]["acc1"] == 0.292
    assert s["v7"]["acc1"] == 0.688 and s["v7"]["p3"] == 0.486
    assert s["v7_eq"]["acc1"] == 0.625
    assert s["rule_R6"]["acc1"] == 0.5


def test_scenario():
    res = v7.cmd_scenario()
    assert res["inferences"]["risk"] == [("High",)]
    # top-5 de referencia (evidence_v7/scenario.json)
    assert [(r["incident"], r["score"]) for r in res["v7_top5"][:3]] == \
        [("Incident_03", 1.0), ("Incident_17", 0.84), ("Incident_24", 0.8)]
