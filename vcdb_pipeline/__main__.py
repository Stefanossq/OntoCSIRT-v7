# -*- coding: utf-8 -*-
"""python -m vcdb_pipeline run [--offline] [--refresh-nvd] [--decisions data/vcdb/review_decisions.jsonl]
python -m vcdb_pipeline rules        # lista as regras com a fonte de cada uma
"""
import argparse
import json
import os
import sys

from . import pipeline, rules


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m vcdb_pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="executa o pipeline e grava data/vcdb/")
    r.add_argument("--offline", action="store_true", help="so cache local (VCDB e NVD); sem rede")
    r.add_argument("--refresh-nvd", action="store_true", help="volta a pedir ao NVD as CVEs ja em cache")
    r.add_argument("--decisions", default=os.path.join(pipeline.OUT, "review_decisions.jsonl"),
                   help="decisoes humanas sobre a fila de revisao (so lidas, nunca escritas)")
    r.add_argument("--schema-check", action="store_true", help="valida cada registo contra vcdb-merged.json")
    r.add_argument("--out", default=pipeline.OUT)
    sub.add_parser("rules", help="lista as regras versionadas")
    a = ap.parse_args(argv)
    if a.cmd == "rules":
        print(rules.RULES_VERSION)
        for rid, rule in rules.RULES.items():
            print("\n%s\n  %s\n  fonte: %s" % (rid, rule["text"], rule["source"]))
        return 0
    res = pipeline.run(out_dir=a.out, offline=a.offline, refresh_nvd=a.refresh_nvd,
                       api_key=os.environ.get("NVD_API_KEY") or None, decisions_path=a.decisions,
                       schema_check=a.schema_check)
    m, c = res["manifest"], res["coverage"]
    print(json.dumps({"reproducibility_hash": m["reproducibility_hash"], "records": c["records"],
                      "incidents_with_cve": c["cves"]["incidents_with_structured_cve"],
                      "labels_per_incident": c["labels_per_incident"], "review_queue": c["review_queue"],
                      "nvd": c["nvd"], "out": a.out}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
