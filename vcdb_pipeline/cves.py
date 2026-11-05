# -*- coding: utf-8 -*-
"""Extracao de CVEs segundo as regras CVE-EXTRACT-1..3 (a 4 depende do NVD e fica em labels.py)."""
import re

# [S8]: sequencia com 4 ou mais digitos; (?!\d) impede truncar CVE-2014-12345 para CVE-2014-1234
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,}(?!\d)")
STRUCTURED = (("hacking", "cve"), ("malware", "cve"))            # [S2]
TEXT_FIELDS = (("summary",), ("reference",), ("action", "hacking", "notes"))


def _get(rec, *path):
    for k in path:
        if not isinstance(rec, dict):
            return None
        rec = rec.get(k)
    return rec


def extract(rec):
    """Devolve dict: cve_raw (lista de {field, value}), cves (ordenada), cve_mentions_text, review (codigos)."""
    raw, found, review = [], set(), []
    for cat, key in STRUCTURED:
        value = _get(rec, "action", cat, key)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        value = value if isinstance(value, str) else str(value)
        field = "action.%s.%s" % (cat, key)
        raw.append({"field": field, "value": value})
        ids = CVE_RX.findall(value)
        if ids:
            found.update(ids)
        else:
            review.append({"reason_code": "CVE_FIELD_NO_ID", "evidence": {"field": field, "value": value}})
    mentions = set()
    for path in TEXT_FIELDS:
        v = _get(rec, *path)
        if isinstance(v, str):
            mentions.update(CVE_RX.findall(v))
    if not found and mentions:
        review.append({"reason_code": "CVE_ONLY_IN_TEXT", "evidence": {"mentions": sorted(mentions)}})
    rules_applied = ["CVE-EXTRACT-1"] if raw else []
    return {"cve_raw": raw, "cves": sorted(found), "cve_mentions_text": sorted(mentions - found),
            "review": review, "rules_applied": rules_applied}
