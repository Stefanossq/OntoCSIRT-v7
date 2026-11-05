# -*- coding: utf-8 -*-
"""Derivacao do rotulo remediation_documented (decisao D2) a partir das tags de referencia do NVD.

O rotulo diz que tipo de remediacao esta DOCUMENTADO nas referencias da CVE [S9]; nao diz o que a vitima
fez (lacuna L-2). Casos ambiguos vao para a fila de revisao, nunca para uma escolha automatica.
"""
from . import rules

PATCH, MITIGATION, BROKEN = "Patch", "Mitigation", "Broken Link"


def cve_label(env):
    """Rotulo de uma CVE a partir do envelope NVD. Devolve dict com value | review e a evidencia."""
    cve = env["cve"]
    refs = cve.get("references") or []
    tagged = {PATCH: [], MITIGATION: []}
    usable = {PATCH: False, MITIGATION: False}
    for r in refs:
        tags = set(r.get("tags") or [])
        for t in (PATCH, MITIGATION):
            if t in tags:
                tagged[t].append(r.get("url"))
                if BROKEN not in tags:
                    usable[t] = True
    evidence = {"cve": cve["id"], "vulnStatus": cve.get("vulnStatus"), "lastModified": cve.get("lastModified"),
                "patch_refs": sorted(tagged[PATCH]), "mitigation_refs": sorted(tagged[MITIGATION]),
                "sha256_of_cve_object": env["sha256_of_cve_object"],
                # KEV-RECORD-1 (D5): registado, nao decide
                "kev_required_action": cve.get("cisaRequiredAction")}
    has_p, has_m = bool(tagged[PATCH]), bool(tagged[MITIGATION])
    if (has_p and not usable[PATCH]) or (has_m and not usable[MITIGATION]):
        return {"value": None, "rule": "LABEL-CVE-5", "review": "TAG_ON_BROKEN_LINK", "evidence": evidence}
    if has_p and has_m:
        return {"value": None, "rule": "LABEL-CVE-3", "review": "TAG_BOTH", "evidence": evidence}
    if has_p:
        return {"value": "patch", "rule": "LABEL-CVE-1", "review": None, "evidence": evidence}
    if has_m:
        return {"value": "mitigation", "rule": "LABEL-CVE-2", "review": None, "evidence": evidence}
    return {"value": "none_tagged", "rule": "LABEL-CVE-4", "review": None, "evidence": evidence}


def incident_label(cve_ids, cve_labels, missing):
    """Agrega por incidente. Devolve (label_dict, revisoes)."""
    if not cve_ids:
        return {"remediation_documented": None, "status": "no_cve", "rule": "LABEL-INC-3"}, []
    review = []
    for c in cve_ids:
        if c in missing:
            review.append({"reason_code": "CVE_NOT_IN_NVD", "evidence": {"cve": c}})
    per = {c: cve_labels[c] for c in cve_ids if c in cve_labels}
    for c, lab in sorted(per.items()):
        if lab["review"]:
            review.append({"reason_code": lab["review"], "evidence": lab["evidence"]})
    outcomes = {lab["value"] or "review:" + lab["review"] for lab in per.values()} | \
               {"review:CVE_NOT_IN_NVD" for c in cve_ids if c in missing}
    if len(cve_ids) > 1 and len(outcomes) > 1:
        review.append({"reason_code": "CVE_SET_DISAGREES",
                       "evidence": {"per_cve": {c: (per[c]["value"] or "review:" + per[c]["review"])
                                                if c in per else "review:CVE_NOT_IN_NVD" for c in cve_ids}}})
    per_cve = {c: {"value": lab["value"], "rule": lab["rule"], "review": lab["review"],
                   "kev_required_action": lab["evidence"]["kev_required_action"],
                   "sha256_of_cve_object": lab["evidence"]["sha256_of_cve_object"]} for c, lab in sorted(per.items())}
    if review:
        return {"remediation_documented": None, "status": "review", "rule": None, "per_cve": per_cve}, review
    (value,) = outcomes
    return {"remediation_documented": value, "status": "auto", "rule": "LABEL-INC-1", "per_cve": per_cve}, []


def apply_decisions(label, review_items, decisions):
    """Decisoes humanas (review_decisions.jsonl) de um registo. Uma decisao resolve os codigos que cita.

    Formato: {"record_key", "reason_codes": [...], "decision": {"remediation_documented": v} | {"exclude": true},
              "decided_by", "decided_on", "note"}
    """
    if not decisions:
        return label, review_items, None
    open_codes = {r["reason_code"] for r in review_items}
    for d in decisions:
        codes = set(d.get("reason_codes") or [])
        if not codes or not codes >= open_codes:
            continue                                  # so resolve se cobrir TODAS as pendencias do registo
        dec = d.get("decision") or {}
        if dec.get("exclude"):
            return dict(label, status="excluded_by_human"), [], d
        value = dec.get("remediation_documented")
        if value in rules.LABEL_VALUES:
            return dict(label, remediation_documented=value, status="human", rule="HUMAN-DECISION"), [], d
    return label, review_items, None
