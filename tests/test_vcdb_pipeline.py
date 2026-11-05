"""Pipeline VCDB (contrato docs/vcdb/RODADA1_CONTRATO.md): uma regra por teste, sem rede.

Os testes unitarios usam registos minimos no formato VERIS; o teste de regressao usa os dados reais fixados
(cache/vcdb/<commit>/vcdb.json.zip e cache/vcdb/nvd/*.json, versionados no repositorio)."""
import io
import json
import os
import zipfile

import pytest

from vcdb_pipeline import cves, download, labels, normalize, nvd, pipeline, rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------ utilitarios
def veris(master="M-1", incident="I-1", year=2023, hacking_cve=None, malware_cve=None, summary="s", **extra):
    rec = {"incident_id": incident, "schema_version": "1.4.0", "security_incident": "Confirmed", "summary": summary,
           "timeline": {"incident": {"year": year}}, "actor": {"external": {"variety": ["Organized crime"]}},
           "action": {}, "asset": {"assets": [{"variety": "S - Web application"}]},
           "attribute": {"confidentiality": {"data_disclosure": "Yes"}},
           "discovery_method": {"external": {"variety": ["Customer"]}}, "victim": {"industry": "522110"},
           "plus": {"master_id": master}}
    if hacking_cve is not None:
        rec["action"]["hacking"] = {"variety": ["Exploit vuln"], "cve": hacking_cve}
    if malware_cve is not None:
        rec["action"]["malware"] = {"variety": ["Ransomware"], "cve": malware_cve}
    rec.update(extra)
    return rec


def env(cve_id, refs, kev=None):
    cve = {"id": cve_id, "vulnStatus": "Analyzed", "lastModified": "2025-01-01T00:00:00.000", "references": refs}
    if kev:
        cve["cisaRequiredAction"] = kev
    return nvd.envelope(cve, "https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=" + cve_id,
                        {"timestamp": "2026-11-05T00:00:00.000", "version": "2.0", "format": "NVD_CVE"})


def ref(*tags, url="https://example.org/x"):
    return {"url": url, "source": "cna@example.org", "tags": list(tags)}


class FakeResp:
    def __init__(self, status=200, payload=None, content=b""):
        self.status_code, self._payload, self.content = status, payload, content

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)


class FakeSession:
    def __init__(self, responses):
        self.responses, self.urls = list(responses), []

    def get(self, url, headers=None, timeout=None):
        self.urls.append(url)
        r = self.responses.pop(0)
        return r(url) if callable(r) else r


# ------------------------------------------------------------------ downloader versionado
def test_git_blob_hash_matches_git_hash_object():
    assert download.git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"   # git hash-object


def test_downloader_rejects_wrong_hash_and_writes_nothing(tmp_path):
    s = FakeSession([FakeResp(content=b"conteudo adulterado")])
    with pytest.raises(download.IntegrityError):
        download.fetch(str(tmp_path), session=s)
    assert not any(tmp_path.rglob("*.zip")) and not any(tmp_path.rglob("*.part"))


def test_downloader_pins_commit_and_writes_manifest(tmp_path):
    data = b"zip fixado"
    blob, sha = download.git_blob_sha1(data), download.sha256(data)
    s = FakeSession([FakeResp(content=data)])
    path, man = download.fetch(str(tmp_path), session=s, commit="abc123", expected_blob=blob, expected_sha256=sha)
    assert s.urls == ["https://raw.githubusercontent.com/vz-risk/VCDB/abc123/data/joined/vcdb.json.zip"]
    assert path.endswith(os.path.join("abc123", "vcdb.json.zip")) and man["sha256"] == sha
    assert json.load(open(os.path.join(tmp_path, "abc123", "manifest.json")))["commit"] == "abc123"
    # segunda chamada: nao vai a rede, reverifica o ficheiro
    path2, _ = download.fetch(str(tmp_path), session=FakeSession([]), commit="abc123", expected_blob=blob,
                              expected_sha256=sha)
    assert path2 == path


def test_downloader_offline_without_file_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        download.fetch(str(tmp_path), offline=True)


# ------------------------------------------------------------------ extracao de CVEs
def test_cve_extract_1_separators_dedup_and_order():
    r = cves.extract(veris(hacking_cve="CVE-2023-35708; CVE-2023-34362, CVE-2023-34362",
                           malware_cve="CVE-2012-0158,CVE-2010-3333"))
    assert r["cves"] == ["CVE-2010-3333", "CVE-2012-0158", "CVE-2023-34362", "CVE-2023-35708"]
    assert [x["field"] for x in r["cve_raw"]] == ["action.hacking.cve", "action.malware.cve"]
    assert r["review"] == []


def test_cve_extract_1_does_not_truncate_five_digit_ids():
    assert cves.extract(veris(hacking_cve="CVE-2014-12345"))["cves"] == ["CVE-2014-12345"]     # [S8]
    assert cves.extract(veris(hacking_cve="CVE-2014-123"))["cves"] == []                        # 3 digitos: invalido


@pytest.mark.parametrize("value", ["Heartbleed", "CVE 2012-4792", "cve unknown", "Wordpress"])
def test_cve_extract_2_values_without_id_go_to_review_uncorrected(value):
    r = cves.extract(veris(hacking_cve=value))
    assert r["cves"] == [] and [x["reason_code"] for x in r["review"]] == ["CVE_FIELD_NO_ID"]
    assert r["review"][0]["evidence"]["value"] == value


def test_cve_extract_3_text_mentions_are_not_structured_cves():
    r = cves.extract(veris(summary="Exploracao da CVE-2025-61882 no EBS."))
    assert r["cves"] == [] and r["cve_mentions_text"] == ["CVE-2025-61882"]
    assert [x["reason_code"] for x in r["review"]] == ["CVE_ONLY_IN_TEXT"]
    r2 = cves.extract(veris(hacking_cve="CVE-2017-5638", summary="CVE-2017-5638 e CVE-2017-9805"))
    assert r2["cves"] == ["CVE-2017-5638"] and r2["cve_mentions_text"] == ["CVE-2017-9805"] and r2["review"] == []


# ------------------------------------------------------------------ normalizacao
def test_canonical_copies_fields_without_inventing():
    rec = veris(extra_field_ignored=1, campaign_id="C-1")
    rec["plus"]["attribute"] = {"confidentiality": {"credit_monitoring": "Yes"}}
    c, rv = normalize.canonical(rec)
    assert rv == [] and c["record_key"] == "M-1" and c["asset_classes"] == ["S"]
    assert c["actor_varieties"] == [["external", "Organized crime"]] and c["discovery"] == [["external", "Customer"]]
    assert c["credit_monitoring"] == "Yes" and c["campaign_id"] == "C-1" and c["industry_naics"] == "522110"
    assert "extra_field_ignored" not in c and c["confidence"] is None          # ausente fica ausente


def test_canonical_year_out_of_schema_goes_to_review():
    _, rv = normalize.canonical(veris(year=1949))
    assert [x["reason_code"] for x in rv] == ["YEAR_OUT_OF_SCHEMA"]


def test_duplicate_master_id_goes_to_review_and_incident_id_is_only_flagged():
    a, _ = normalize.canonical(veris(master="M-1", incident="I-1"))
    b, _ = normalize.canonical(veris(master="M-1", incident="I-2"))
    c, _ = normalize.canonical(veris(master="M-2", incident="I-2"))
    rv = normalize.mark_duplicates([a, b, c])
    assert sorted(r["record_key"] for r, x in rv) == ["M-1", "M-1"]
    assert {x["reason_code"] for _, x in rv} == {"DUP_MASTER_ID"}
    assert (a["dup_incident_id"], b["dup_incident_id"], c["dup_incident_id"]) == (False, True, True)


# ------------------------------------------------------------------ rotulos
@pytest.mark.parametrize("refs,value,rule,review", [
    ([ref("Patch", "Vendor Advisory")], "patch", "LABEL-CVE-1", None),
    ([ref("Mitigation")], "mitigation", "LABEL-CVE-2", None),
    ([ref("Patch"), ref("Mitigation")], None, "LABEL-CVE-3", "TAG_BOTH"),
    ([ref("Exploit"), ref("Third Party Advisory")], "none_tagged", "LABEL-CVE-4", None),
    ([], "none_tagged", "LABEL-CVE-4", None),
    ([ref("Patch", "Broken Link")], None, "LABEL-CVE-5", "TAG_ON_BROKEN_LINK"),
    ([ref("Patch", "Broken Link"), ref("Patch", url="https://example.org/ok")], "patch", "LABEL-CVE-1", None),
])
def test_cve_label_rules(refs, value, rule, review):
    lab = labels.cve_label(env("CVE-2020-0001", refs))
    assert (lab["value"], lab["rule"], lab["review"]) == (value, rule, review)


def test_kev_required_action_is_recorded_but_does_not_decide():
    a = labels.cve_label(env("CVE-2020-0001", [ref("Exploit")], kev="Apply updates per vendor instructions."))
    assert a["value"] == "none_tagged" and a["evidence"]["kev_required_action"].startswith("Apply updates")


def test_incident_label_aggregation():
    L = {"A": labels.cve_label(env("A", [ref("Patch")])), "B": labels.cve_label(env("B", [ref("Patch")])),
         "C": labels.cve_label(env("C", [])), "D": labels.cve_label(env("D", [ref("Patch"), ref("Mitigation")]))}
    lab, rv = labels.incident_label(["A", "B"], L, set())
    assert (lab["status"], lab["remediation_documented"], lab["rule"], rv) == ("auto", "patch", "LABEL-INC-1", [])
    lab, rv = labels.incident_label(["A", "C"], L, set())
    assert lab["status"] == "review" and [x["reason_code"] for x in rv] == ["CVE_SET_DISAGREES"]
    # como o MOVEit: duas sem tag e uma com Patch+Mitigation
    lab, rv = labels.incident_label(["C", "C2", "D"], dict(L, C2=L["C"]), set())
    assert sorted(x["reason_code"] for x in rv) == ["CVE_SET_DISAGREES", "TAG_BOTH"]
    lab, rv = labels.incident_label(["A", "Z"], L, {"Z"})
    assert sorted(x["reason_code"] for x in rv) == ["CVE_NOT_IN_NVD", "CVE_SET_DISAGREES"]
    lab, rv = labels.incident_label([], L, set())
    assert (lab["status"], lab["rule"], rv) == ("no_cve", "LABEL-INC-3", [])


def test_human_decision_resolves_only_when_it_covers_every_open_code():
    lab = {"remediation_documented": None, "status": "review", "rule": None}
    items = [{"reason_code": "TAG_BOTH"}, {"reason_code": "CVE_SET_DISAGREES"}]
    partial = [{"record_key": "M", "reason_codes": ["TAG_BOTH"], "decision": {"remediation_documented": "patch"}}]
    assert labels.apply_decisions(lab, items, partial)[2] is None
    invalid = [{"record_key": "M", "reason_codes": ["TAG_BOTH", "CVE_SET_DISAGREES"],
                "decision": {"remediation_documented": "CoA_Patch"}}]                  # fora de LABEL_VALUES
    assert labels.apply_decisions(lab, items, invalid)[2] is None
    ok = [dict(invalid[0], decision={"remediation_documented": "patch"}, decided_by="Analista")]
    new, remaining, used = labels.apply_decisions(lab, items, ok)
    assert (new["status"], new["remediation_documented"], new["rule"], remaining) == ("human", "patch", "HUMAN-DECISION", [])
    ex = [dict(invalid[0], decision={"exclude": True})]
    assert labels.apply_decisions(lab, items, ex)[0]["status"] == "excluded_by_human"


# ------------------------------------------------------------------ cliente e cache NVD
def _nvd_payload(ids):
    return {"timestamp": "2026-11-05T00:00:00.000", "version": "2.0", "format": "NVD_CVE",
            "vulnerabilities": [{"cve": {"id": i, "references": [ref("Patch")]}} for i in ids]}


def test_nvd_batches_of_100_with_six_second_pause_and_provenance(tmp_path):
    ids = ["CVE-2020-%04d" % i for i in range(150)]
    s = FakeSession([lambda u: FakeResp(payload=_nvd_payload(u.split("cveIds=")[1].split(",")))] * 2)
    slept = []
    envs, info = nvd.fetch(ids, nvd.NVDCache(str(tmp_path)), session=s, sleep=slept.append)
    assert info["requests"] == 2 and len(s.urls[0].split("cveIds=")[1].split(",")) == 100 and slept == [6.0]
    e = json.load(open(tmp_path / "CVE-2020-0000.json", encoding="utf-8"))
    assert e["request_url"] == s.urls[0] and e["response_timestamp"] == "2026-11-05T00:00:00.000"
    assert e["sha256_of_cve_object"] == nvd.object_sha256(e["cve"]) and e["notice"] == nvd.NOTICE
    # segunda execucao: so cache, nenhum pedido
    _, info2 = nvd.fetch(ids, nvd.NVDCache(str(tmp_path)), session=FakeSession([]))
    assert info2["requests"] == 0 and info2["from_cache"] == 150


def test_nvd_retries_on_429_and_reports_missing(tmp_path):
    s = FakeSession([FakeResp(429), FakeResp(payload=_nvd_payload(["CVE-2020-0001"]))])
    slept = []
    envs, info = nvd.fetch(["CVE-2020-0001", "CVE-2099-0001"], nvd.NVDCache(str(tmp_path)), session=s,
                           sleep=slept.append)
    assert list(envs) == ["CVE-2020-0001"] and info["missing"] == ["CVE-2099-0001"] and slept == [12.0]


def test_nvd_offline_reads_only_cache(tmp_path):
    envs, info = nvd.fetch(["CVE-2020-0001"], nvd.NVDCache(str(tmp_path)), offline=True, session=FakeSession([]))
    assert envs == {} and info["missing"] == ["CVE-2020-0001"]


def test_tampered_nvd_envelope_is_rejected(tmp_path):
    c = nvd.NVDCache(str(tmp_path))
    c.put(env("CVE-2020-0001", [ref("Patch")]))
    p = tmp_path / "CVE-2020-0001.json"
    e = json.load(open(p, encoding="utf-8"))
    e["cve"]["references"][0]["tags"] = ["Mitigation"]
    p.write_text(json.dumps(e), encoding="utf-8")
    with pytest.raises(ValueError):
        c.get("CVE-2020-0001")


# ------------------------------------------------------------------ pipeline: determinismo e hash
def _fixture(tmp_path, records, envelopes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("vcdb_1-of-1.json", json.dumps(records))
    data = buf.getvalue()
    zpath = tmp_path / "vcdb.json.zip"
    zpath.write_bytes(data)
    cache = tmp_path / "cache"
    for e in envelopes:
        nvd.NVDCache(str(cache / "nvd")).put(e)
    return str(zpath), {"sha256": download.sha256(data), "git_blob_sha1": download.git_blob_sha1(data)}, str(cache)


RECS = [veris("M-1", "I-1", hacking_cve="CVE-2020-0001"),
        veris("M-2", "I-2", hacking_cve="CVE-2020-0002; CVE-2020-0003"),
        veris("M-3", "I-2", hacking_cve="Heartbleed"),
        veris("M-4", "I-4")]
ENVS = [env("CVE-2020-0001", [ref("Patch")]), env("CVE-2020-0002", []),
        env("CVE-2020-0003", [ref("Patch"), ref("Mitigation")])]


def test_pipeline_end_to_end_and_deterministic_hash(tmp_path):
    zpath, man, cache = _fixture(tmp_path, RECS, ENVS)
    runs = [pipeline.run(cache_dir=cache, out_dir=str(tmp_path / ("out%d" % i)), offline=True,
                         vcdb_path=zpath, vcdb_manifest=man) for i in range(2)]
    h = [r["manifest"]["reproducibility_hash"] for r in runs]
    assert h[0] == h[1]
    for name in ("vcdb_canonical.jsonl", "review_queue.jsonl"):
        assert (tmp_path / "out0" / name).read_bytes() == (tmp_path / "out1" / name).read_bytes()
    recs = {r["record_key"]: r for r in runs[0]["records"]}
    assert recs["M-1"]["label"]["remediation_documented"] == "patch"
    assert recs["M-2"]["label"]["status"] == "review" and recs["M-4"]["label"]["status"] == "no_cve"
    codes = sorted((q["record_key"], q["reason_code"]) for q in runs[0]["queue"])
    assert codes == [("M-2", "CVE_SET_DISAGREES"), ("M-2", "TAG_BOTH"), ("M-3", "CVE_FIELD_NO_ID")]
    assert all(q["rule_id"] == rules.REVIEW_CODES[q["reason_code"]] for q in runs[0]["queue"])
    assert (tmp_path / "out0" / "coverage.md").exists()


def test_hash_changes_with_rules_version_and_with_inputs(tmp_path, monkeypatch):
    zpath, man, cache = _fixture(tmp_path, RECS, ENVS)
    base = pipeline.run(cache_dir=cache, out_dir=None, offline=True, vcdb_path=zpath, vcdb_manifest=man)
    monkeypatch.setattr(rules, "RULES_VERSION", "vcdb-pipeline-test")
    other = pipeline.run(cache_dir=cache, out_dir=None, offline=True, vcdb_path=zpath, vcdb_manifest=man)
    assert base["manifest"]["reproducibility_hash"] != other["manifest"]["reproducibility_hash"]


def test_human_decisions_file_is_read_and_applied(tmp_path):
    zpath, man, cache = _fixture(tmp_path, RECS, ENVS)
    dec = tmp_path / "review_decisions.jsonl"
    dec.write_text(json.dumps({"record_key": "M-2", "reason_codes": ["TAG_BOTH", "CVE_SET_DISAGREES"],
                               "decision": {"remediation_documented": "mitigation"}, "decided_by": "Analista",
                               "decided_on": "2026-11-05", "note": "teste"}) + "\n", encoding="utf-8")
    res = pipeline.run(cache_dir=cache, out_dir=None, offline=True, vcdb_path=zpath, vcdb_manifest=man,
                       decisions_path=str(dec))
    m2 = [r for r in res["records"] if r["record_key"] == "M-2"][0]
    assert m2["label"]["status"] == "human" and m2["label"]["decision"]["decided_by"] == "Analista"
    assert [q["record_key"] for q in res["queue"]] == ["M-3"]
    assert res["manifest"]["inputs"]["review_decisions_sha256"] and res["manifest"]["human_decisions_applied"] == 1


# ------------------------------------------------------------------ regressao sobre os dados reais fixados
REAL_ZIP = os.path.join(ROOT, "cache", "vcdb", rules.VCDB_COMMIT, "vcdb.json.zip")
EXPECTED_HASH = "d806142bd9cc574aefdf65718f06eac82b254c0ded2b09a9cb0fa9c3bc06393f"


@pytest.mark.skipif(not os.path.exists(REAL_ZIP), reason="dados VCDB fixados ausentes")
def test_real_pinned_data_reproduces_reference_hash_and_counts():
    res = pipeline.run(out_dir=None, offline=True)
    c = res["coverage"]
    assert res["manifest"]["inputs"]["vcdb"]["sha256"] == rules.VCDB_JOINED_SHA256
    assert c["records"] == 10047 and c["cves"]["incidents_with_structured_cve"] == 926
    assert c["cves"]["distinct_cves"] == 31 and c["nvd"]["missing"] == []
    assert c["review_queue"]["by_reason"] == {"TAG_BOTH": 751, "CVE_SET_DISAGREES": 750, "DUP_MASTER_ID": 6,
                                              "CVE_FIELD_NO_ID": 6, "CVE_ONLY_IN_TEXT": 4}
    assert c["labels_per_incident"] == {"auto/mitigation": 1, "auto/none_tagged": 67, "auto/patch": 106,
                                        "no_cve/None": 9121, "review/None": 752}
    assert res["manifest"]["reproducibility_hash"] == EXPECTED_HASH
