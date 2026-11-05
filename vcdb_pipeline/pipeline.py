# -*- coding: utf-8 -*-
"""Orquestracao: download -> parse -> normalizacao -> CVEs -> NVD -> rotulos -> revisao -> saidas + hash.

Saidas (em out_dir, LF, chaves ordenadas):
  vcdb_canonical.jsonl  um registo canonico por registo do joined (nada e deduplicado em silencio)
  review_queue.jsonl    pendencias para revisao humana
  coverage.json / coverage.md
  manifest.json         entradas (hashes), saidas (hashes), versao das regras e hash de reprodutibilidade
O hash de reprodutibilidade nao inclui datas de execucao: duas execucoes com as mesmas entradas dao o
mesmo hash.
"""
import datetime
import hashlib
import json
import os

from . import download, labels, normalize, nvd, parse, report, rules

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(HERE, "cache", "vcdb")
OUT = os.path.join(HERE, "data", "vcdb")
NVD_SCHEMA = os.path.join(HERE, "cache", "nvd_schema", "cve_api_json_2.0.schema")
SCHEMA = os.path.join(CACHE, "schema", rules.VCDB_COMMIT, "vcdb-merged.json")


def _jsonl(rows):
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows).encode("utf-8")


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _read_decisions(path):
    out = {}
    if path and os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.strip():
                d = json.loads(line)
                out.setdefault(d["record_key"], []).append(d)
    return out


def run(cache_dir=CACHE, out_dir=OUT, offline=False, refresh_nvd=False, api_key=None, decisions_path=None,
        schema_check=False, session=None, sleep=None, vcdb_path=None, vcdb_manifest=None):
    # 1. fonte versionada
    if vcdb_path is None:
        vcdb_path, vcdb_manifest = download.fetch(cache_dir, offline=offline, session=session)
    member, raw = parse.read_joined(vcdb_path)
    # 2. normalizacao + extracao de CVEs
    records, review = [], []
    for rec in raw:
        canon, rv = normalize.canonical(rec)
        records.append(canon)
        review += [(canon, x) for x in rv]
    review += normalize.mark_duplicates(records)
    # 3. NVD
    cache = nvd.NVDCache(os.path.join(cache_dir, "nvd"))
    all_cves = sorted({c for r in records for c in r["cves"]})
    kw = {"sleep": sleep} if sleep else {}
    envs, nvd_info = nvd.fetch(all_cves, cache, offline=offline, refresh=refresh_nvd, api_key=api_key,
                               session=session, schema_path=NVD_SCHEMA, **kw)
    cve_labels = {c: labels.cve_label(e) for c, e in envs.items()}
    missing = set(nvd_info["missing"])
    # 4. rotulos por incidente + decisoes humanas
    decisions = _read_decisions(decisions_path)
    used_decisions = 0
    for r in records:
        lab, rv = labels.incident_label(r["cves"], cve_labels, missing)
        own = [x for (rr, x) in review if rr is r]
        lab, remaining, used = labels.apply_decisions(lab, own + rv, decisions.get(r["record_key"]))
        if used:
            used_decisions += 1
            lab["decision"] = {k: used.get(k) for k in ("decided_by", "decided_on", "note", "reason_codes")}
            review = [(rr, x) for (rr, x) in review if rr is not r]
        else:
            review += [(r, x) for x in rv]
        r["label"] = lab
        r["rules_applied"] = sorted(set(r["rules_applied"]) | ({lab["rule"]} if lab.get("rule") else set()))
    queue = []
    for r, x in review:
        queue.append({"record_key": r["record_key"], "incident_id": r["incident_id"], "reason_code": x["reason_code"],
                      "rule_id": rules.REVIEW_CODES[x["reason_code"]], "evidence": x["evidence"],
                      "rules_version": rules.RULES_VERSION, "decision": None})
    records.sort(key=lambda r: (str(r["record_key"]), str(r["incident_id"]), _sha((r["summary"] or "").encode())))
    queue.sort(key=lambda q: (str(q["record_key"]), q["reason_code"], json.dumps(q["evidence"], sort_keys=True)))
    # 5. saidas e hash
    canon_b, queue_b = _jsonl(records), _jsonl(queue)
    schema_failures = parse.schema_check(raw, SCHEMA) if schema_check and os.path.exists(SCHEMA) else None
    cov = report.coverage(records, queue, cve_labels, nvd_info, schema_failures)
    inputs = {"vcdb": {"repo": rules.VCDB_REPO, "commit": rules.VCDB_COMMIT, "path": rules.VCDB_JOINED_PATH,
                       "member": member, "sha256": vcdb_manifest["sha256"],
                       "git_blob_sha1": vcdb_manifest["git_blob_sha1"]},
              "nvd_envelopes": {c: e["sha256_of_cve_object"] for c, e in sorted(envs.items())},
              "nvd_missing": sorted(missing),
              "review_decisions_sha256": _sha(open(decisions_path, "rb").read())
              if decisions_path and os.path.exists(decisions_path) else None,
              "rules_version": rules.RULES_VERSION}
    outputs = {"vcdb_canonical.jsonl": _sha(canon_b), "review_queue.jsonl": _sha(queue_b)}
    repro = _sha(json.dumps({"inputs": inputs, "outputs": outputs}, sort_keys=True).encode("utf-8"))
    manifest = {"rules_version": rules.RULES_VERSION, "inputs": inputs, "outputs": outputs,
                "reproducibility_hash": repro, "license": rules.VCDB_LICENSE,
                "human_decisions_applied": used_decisions,
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "notice": nvd.NOTICE}
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        for name, data in (("vcdb_canonical.jsonl", canon_b), ("review_queue.jsonl", queue_b)):
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(data)
        for name, obj in (("coverage.json", cov), ("manifest.json", manifest)):
            with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
                json.dump(obj, fh, indent=1, sort_keys=True, ensure_ascii=False)
                fh.write("\n")
        with open(os.path.join(out_dir, "coverage.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report.markdown(cov, manifest))
    return {"manifest": manifest, "coverage": cov, "records": records, "queue": queue, "cve_labels": cve_labels}
