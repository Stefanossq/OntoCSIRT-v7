"""Contrato da API: openapi.yaml e valido (OpenAPI 3.1) e as respostas REAIS do webhook - recomendacao com
enriquecimento NVD, fallback de revisao manual, /health e /retain - validam contra os esquemas declarados."""
import json
import os

import jsonschema
import pytest
import requests
import yaml

import ontocsirt_v7 as v7

from test_nvd_enricher import FakeSession, enricher

SPEC_PATH = os.path.join(v7.HERE, "openapi.yaml")


@pytest.fixture(scope="module")
def spec():
    with open(SPEC_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def validator(spec, schema):
    """Esquema OpenAPI 3.1 (JSON Schema 2020-12) com as referencias #/components/schemas resolvidas."""
    doc = json.loads(json.dumps(schema).replace("#/components/schemas/", "#/$defs/"))
    doc["$defs"] = json.loads(json.dumps(spec["components"]["schemas"]).replace("#/components/schemas/", "#/$defs/"))
    return jsonschema.Draft202012Validator(doc)


def ok(spec, schema, instance):
    errs = sorted(validator(spec, schema).iter_errors(instance), key=str)
    assert not errs, "\n".join("%s: %s" % (list(e.path), e.message) for e in errs[:5])


def test_spec_is_valid_openapi_31(spec):
    osv = pytest.importorskip("openapi_spec_validator")
    osv.validate(spec)
    assert spec["openapi"].startswith("3.1") and {"/alert", "/retain", "/health"} <= set(spec["paths"])


def test_examples_match_schemas(spec):
    post = spec["paths"]["/alert"]["post"]
    for ex in post["requestBody"]["content"]["application/json"]["examples"].values():
        ok(spec, {"$ref": "#/components/schemas/Alert"}, ex["value"])
    resp = post["responses"]["200"]["content"]["application/json"]
    for ex in resp["examples"].values():
        ok(spec, resp["schema"], ex["value"])
    h = spec["paths"]["/health"]["get"]["responses"]["200"]["content"]["application/json"]
    ok(spec, h["schema"], h["example"])


def test_real_responses_match_contract(spec, tmp_path):
    import soar_webhook as sw
    out = str(tmp_path / "acquired.ttl")
    eng = sw.Engine(v7.TTL, reasoner="none", acquired=out, enricher=enricher(tmp_path, FakeSession()))
    resp = spec["paths"]["/alert"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    alert = {"src_ip": "198.51.100.23", "attack_type": "cmdi", "target": "Gateway_1", "cve": "CVE-2024-3400",
             "attribute": "confidentiality", "alert_id": "C-1"}
    ok(spec, {"$ref": "#/components/schemas/Alert"}, alert)
    code, rec = eng.handle(dict(alert))
    assert code == 200 and rec["nvd_enrichment"]["status"] == "written"
    ok(spec, resp, rec)                                                      # oneOf: so Recommendation
    ok(spec, {"$ref": "#/components/schemas/Recommendation"}, rec)
    assert not any(a.startswith("CWE inferido do attack_type") for a in rec["assumptions"])   # CWE real da CVE
    err = requests.ConnectionError("offline")
    down = sw.Engine(v7.TTL, reasoner="none", acquired=str(tmp_path / "b.ttl"),
                     enricher=enricher(tmp_path / "x", FakeSession([err, err, err])))
    code, fb = down.handle(dict(alert, alert_id="C-2"))
    assert code == 200
    ok(spec, resp, fb)
    ok(spec, {"$ref": "#/components/schemas/ManualReview"}, fb)
    ok(spec, {"$ref": "#/components/schemas/Health"},
       {"status": "ok", "kb": os.path.basename(eng.kb_path), "incidents": eng.n_incidents, "reasoner": eng.reasoner})


def test_lifecycle_realtime_offline():
    """lifecycle_metrics.py, coluna "tempo real", sem rede (registo NVD guardado): nada no projeto muda."""
    import lifecycle_metrics as lm
    from ontoevo import kb
    before = os.path.getmtime(kb.ACQUIRED) if os.path.exists(kb.ACQUIRED) else None
    g, rt = lm.realtime("CVE-2024-3400", live=False)
    assert rt["alert1"]["risk"] == "Critical" and rt["enrichment"]["cvss"] == 10.0
    assert rt["alert2"]["nvd_enrichment"] is None and rt["nvd_mode"].startswith("registo")
    assert (os.path.getmtime(kb.ACQUIRED) if os.path.exists(kb.ACQUIRED) else None) == before
    s = lm.structure(g)
    assert s["cves"] >= 20 and s["incidents"] >= 19
