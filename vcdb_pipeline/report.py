# -*- coding: utf-8 -*-
"""Relatorio de cobertura (contrato, secao 7): preenchimento, vies de amostragem, CVEs, rotulos e revisao."""
from collections import Counter

FIELDS = ["record_key", "incident_id", "schema_version", "security_incident", "confidence", "summary",
          "reference", "year", "month", "day", "actor_categories", "actor_varieties", "action_categories",
          "action_varieties", "action_vectors", "asset_varieties", "asset_classes", "attributes",
          "data_disclosure", "discovery", "industry_naics", "victim_country", "campaign_id", "sub_source",
          "analysis_status", "credit_monitoring", "cve_raw", "cves", "cve_mentions_text"]


def _filled(v):
    return v not in (None, "", [], {})


def coverage(records, review, cve_labels, nvd_info, schema_failures=None):
    n = len(records)
    fill = {f: {"filled": sum(_filled(r.get(f)) for r in records)} for f in FIELDS}
    for f in fill:
        fill[f]["pct"] = round(100.0 * fill[f]["filled"] / n, 2) if n else 0.0
    with_cve = [r for r in records if r["cves"]]
    sets = Counter(tuple(r["cves"]) for r in with_cve)
    distinct = sorted({c for r in with_cve for c in r["cves"]})
    lab = Counter((r["label"]["status"], r["label"]["remediation_documented"]) for r in records)
    # D5: concordancia (so medida) entre o rotulo da CVE e o texto do KEV
    kev = Counter((l["value"] or "review:" + l["review"], l["evidence"]["kev_required_action"] or "(fora do KEV)")
                  for l in cve_labels.values())
    rep = {
        "records": n,
        "field_fill": fill,
        "distributions": {
            "sub_source (vies de amostragem [S4])": dict(Counter(str(r["sub_source"]) for r in records).most_common()),
            "analysis_status": dict(Counter(str(r["analysis_status"]) for r in records).most_common()),
            "schema_version": dict(Counter(str(r["schema_version"]) for r in records).most_common()),
            "security_incident": dict(Counter(str(r["security_incident"]) for r in records).most_common()),
            "credit_monitoring (D4, sem regra de rotulo)": dict(
                Counter(str(r["credit_monitoring"]) for r in records).most_common()),
        },
        "keys": {"dup_incident_id_records": sum(r["dup_incident_id"] for r in records),
                 "distinct_record_keys": len({r["record_key"] for r in records})},
        "cves": {"incidents_with_structured_cve": len(with_cve), "distinct_cves": len(distinct),
                 "distinct_cve_sets": len(sets),
                 "top_cve_sets": [{"cves": list(k), "incidents": v} for k, v in sets.most_common(10)],
                 "incidents_with_text_only_mentions": sum(1 for r in records if r["cve_mentions_text"] and not r["cves"])},
        "nvd": {k: v for k, v in nvd_info.items() if k != "schema_errors"} |
               {"schema_errors": len(nvd_info.get("schema_errors", []))},
        "labels_per_cve": dict(Counter(l["value"] or "review:" + l["review"] for l in cve_labels.values()).most_common()),
        "labels_per_incident": {"%s/%s" % k: v for k, v in sorted(lab.items(), key=lambda kv: str(kv[0]))},
        "review_queue": {"items": len(review), "records": len({x["record_key"] for x in review}),
                         "by_reason": dict(Counter(x["reason_code"] for x in review).most_common())},
        "kev_vs_tags (D5, so medida)": [{"label": a, "cisaRequiredAction": b, "cves": c}
                                         for (a, b), c in sorted(kev.items())],
    }
    if schema_failures is not None:
        rep["schema_check_vcdb_merged"] = {"failing_records": len(schema_failures),
                                           "examples": dict(list(sorted(schema_failures.items()))[:5])}
    return rep


def markdown(rep, manifest):
    L = ["# Relatorio de cobertura - pipeline VCDB", "",
         "Gerado por `python -m vcdb_pipeline run`. Regras: `%s`. Hash de reprodutibilidade: `%s`." % (
             manifest["rules_version"], manifest["reproducibility_hash"]), "",
         "Fonte: `%s` @ `%s` (sha256 `%s`). Licenca dos dados derivados: CC BY-SA 4.0." % (
             manifest["inputs"]["vcdb"]["path"], manifest["inputs"]["vcdb"]["commit"],
             manifest["inputs"]["vcdb"]["sha256"]), "",
         "## Registos e chaves", "",
         "| Medida | Valor |", "|---|---|",
         "| Registos | %d |" % rep["records"],
         "| `record_key` (plus.master_id) distintos | %d |" % rep["keys"]["distinct_record_keys"],
         "| Registos com `incident_id` repetido | %d |" % rep["keys"]["dup_incident_id_records"], "",
         "## Preenchimento dos campos canonicos", "", "| Campo | Preenchidos | % |", "|---|---|---|"]
    L += ["| `%s` | %d | %.2f |" % (f, v["filled"], v["pct"]) for f, v in rep["field_fill"].items()]
    for name, dist in rep["distributions"].items():
        L += ["", "## %s" % name, "", "| Valor | Registos |", "|---|---|"]
        L += ["| %s | %d |" % (k, v) for k, v in dist.items()]
    c = rep["cves"]
    L += ["", "## CVEs", "", "| Medida | Valor |", "|---|---|",
          "| Incidentes com CVE estruturada | %d |" % c["incidents_with_structured_cve"],
          "| CVEs distintas | %d |" % c["distinct_cves"],
          "| Conjuntos distintos de CVEs | %d |" % c["distinct_cve_sets"],
          "| Incidentes com CVE so no texto | %d |" % c["incidents_with_text_only_mentions"], "",
          "Conjuntos mais frequentes (risco de fuga de informacao numa avaliacao futura, contrato 5.4):", "",
          "| CVEs | Incidentes |", "|---|---|"]
    L += ["| %s | %d |" % (", ".join(s["cves"]), s["incidents"]) for s in c["top_cve_sets"]]
    L += ["", "## NVD", "", "| Medida | Valor |", "|---|---|"]
    L += ["| %s | %s |" % (k, v) for k, v in rep["nvd"].items()]
    L += ["", "## Rotulos por CVE (`remediation_documented`)", "", "| Rotulo | CVEs |", "|---|---|"]
    L += ["| %s | %d |" % kv for kv in rep["labels_per_cve"].items()]
    L += ["", "## Rotulos por incidente", "", "| Estado/valor | Incidentes |", "|---|---|"]
    L += ["| %s | %d |" % kv for kv in rep["labels_per_incident"].items()]
    q = rep["review_queue"]
    L += ["", "## Fila de revisao humana", "", "%d pendencias em %d registos." % (q["items"], q["records"]), "",
          "| Codigo | Pendencias |", "|---|---|"]
    L += ["| `%s` | %d |" % kv for kv in q["by_reason"].items()]
    L += ["", "## Tags NVD x `cisaRequiredAction` do KEV (D5: so medida, nao decide)", "",
          "| Rotulo pelas tags | cisaRequiredAction | CVEs |", "|---|---|---|"]
    L += ["| %s | %s | %d |" % (k["label"], k["cisaRequiredAction"], k["cves"]) for k in rep["kev_vs_tags (D5, so medida)"]]
    if "schema_check_vcdb_merged" in rep:
        s = rep["schema_check_vcdb_merged"]
        L += ["", "## Validacao contra vcdb-merged.json", "", "%d registos com erros de schema (informativo)." % s["failing_records"]]
    L += ["", "*Este produto usa dados da API do NVD, mas nao e endossado nem certificado pelo NVD.*", ""]
    return "\n".join(L)
