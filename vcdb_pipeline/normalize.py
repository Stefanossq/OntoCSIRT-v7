# -*- coding: utf-8 -*-
"""Registo VERIS -> registo canonico (contrato, secao 3). Copia campos; nao interpreta nem completa."""
from collections import Counter

from . import cves as cvemod

ACTOR_KEYS = ("external", "internal", "partner", "unknown")                 # [S2] actor.properties
ATTR_KEYS = ("availability", "confidentiality", "integrity", "unknown")      # [S2] attribute.properties
DISCOVERY_KEYS = ("external", "internal", "partner", "unknown")              # [S2] discovery_method


def _get(rec, *path):
    for k in path:
        if not isinstance(rec, dict):
            return None
        rec = rec.get(k)
    return rec


def _pairs(section, keys, field):
    out = []
    for k in keys:
        sub = section.get(k) if isinstance(section, dict) else None
        if isinstance(sub, dict):
            for v in sub.get(field) or []:
                out.append([k, v])
    return sorted(out)


def canonical(rec):
    """Devolve (registo_canonico, revisoes). As revisoes ainda nao tem record_key nem duplicados."""
    review = []
    plus = rec.get("plus") or {}
    action = rec.get("action") or {}
    actor = rec.get("actor") or {}
    attribute = rec.get("attribute") or {}
    assets = _get(rec, "asset", "assets") or []
    year = _get(rec, "timeline", "incident", "year")
    applied = ["CANON-KEY-1", "CANON-KEY-2", "CANON-YEAR-1", "CANON-ASSET-1"]
    if not isinstance(year, int) or not 1950 <= year <= 2050:                # CANON-YEAR-1
        review.append({"reason_code": "YEAR_OUT_OF_SCHEMA", "evidence": {"year": year}})
    asset_varieties = sorted(a.get("variety") for a in assets if isinstance(a, dict) and a.get("variety"))
    c = cvemod.extract(rec)
    review += c["review"]
    out = {
        "record_key": plus.get("master_id"),
        "incident_id": rec.get("incident_id"),
        "dup_incident_id": False,
        "schema_version": rec.get("schema_version"),
        "security_incident": rec.get("security_incident"),
        "confidence": rec.get("confidence"),
        "summary": rec.get("summary"),
        "reference": rec.get("reference"),
        "year": year,
        "month": _get(rec, "timeline", "incident", "month"),
        "day": _get(rec, "timeline", "incident", "day"),
        "actor_categories": sorted(k for k in ACTOR_KEYS if k in actor),
        "actor_varieties": _pairs(actor, ACTOR_KEYS, "variety"),
        "action_categories": sorted(action),
        "action_varieties": _pairs(action, sorted(action), "variety"),
        "action_vectors": _pairs(action, sorted(action), "vector"),
        "asset_varieties": asset_varieties,
        "asset_classes": sorted({v.split(" - ")[0] for v in asset_varieties}),       # CANON-ASSET-1
        "attributes": sorted(k for k in ATTR_KEYS if k in attribute),
        "data_disclosure": _get(attribute, "confidentiality", "data_disclosure"),
        "discovery": _pairs(rec.get("discovery_method") or {}, DISCOVERY_KEYS, "variety"),
        "industry_naics": _get(rec, "victim", "industry"),
        "victim_country": sorted(_get(rec, "victim", "country") or []),
        "campaign_id": rec.get("campaign_id"),
        "sub_source": plus.get("sub_source"),
        "analysis_status": plus.get("analysis_status"),
        # D4: so no contrato canonico, sem regra de rotulo [S2] plus.attribute.confidentiality.credit_monitoring
        "credit_monitoring": _get(plus, "attribute", "confidentiality", "credit_monitoring"),
        "cve_raw": c["cve_raw"],
        "cves": c["cves"],
        "cve_mentions_text": c["cve_mentions_text"],
        "rules_applied": applied + c["rules_applied"],
    }
    if out["schema_version"] and not str(out["schema_version"]).startswith("1.4."):
        out["warnings"] = ["schema_version %s diferente de 1.4.x [S2]" % out["schema_version"]]
    return out, review


def mark_duplicates(records):
    """CANON-KEY-1 e CANON-KEY-2 sobre o conjunto: devolve revisoes DUP_MASTER_ID."""
    keys = Counter(r["record_key"] for r in records)
    ids = Counter(r["incident_id"] for r in records)
    review = []
    for r in records:
        if ids[r["incident_id"]] > 1:
            r["dup_incident_id"] = True
        if r["record_key"] is None or keys[r["record_key"]] > 1:
            review.append((r, {"reason_code": "DUP_MASTER_ID",
                               "evidence": {"master_id": r["record_key"], "occurrences": keys[r["record_key"]],
                                            "incident_id": r["incident_id"]}}))
    return review
