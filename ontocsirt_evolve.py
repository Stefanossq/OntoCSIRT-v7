#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ontocsirt_evolve.py - aquisicao de vulnerabilidades, de casos CBR e evolucao estrutural do OntoCSIRT v7
com a API Gemini (ontoevo/). O OntoCSIRT_v7.ttl do artigo nunca e alterado.

  status                         catalogos, base composta, modo/chave do Gemini, propostas por estado
  fetch-catalogs                 baixa e compacta CWE (MITRE) e ATT&CK 16.1 (MITRE STIX) em cache/catalogs
  acquire CVE [CVE...]           CVE real -> individuos OWL em OntoCSIRT_v7_acquired.ttl (Gemini so nas lacunas)
  analyze CVE                    analisar vulnerabilidade -> novo caso CBR (retrieve + reuse pelo Gemini)
  signals                        sinais estruturais detetados nos dados
  propose [--signal ID|--all]    agente Gemini -> propostas (compiladas e passadas no portao)
  propose --from-file F.json     proposta de um analista (mesmo pipeline)
  list [--status S] / show ID    propostas
  approve ID --by NOME           aprovacao humana (obrigatoria)
  reject ID --by NOME --note T
  apply ID                       acrescenta a OntoCSIRT_v7_evo.ttl (portao repetido + verificacao + rollback)
  validate                       SHACL + HermiT + Pellet + questoes de competencia da base composta
  export [--out F]               base composta num unico Turtle (Protege, consultas externas)

Gemini: GEMINI_API_KEY (ou GOOGLE_API_KEY); modelo em GEMINI_MODEL (padrao %(model)s); modo em
ONTOCSIRT_GEMINI_MODE ou --gemini-mode (live | cached | replay). Cache e registo em cache/gemini/.
"""
import argparse
import json
import os
import sys

from ontoevo import gemini as gm


def _client(a):
    return gm.GeminiClient(model=a.model, mode=a.gemini_mode)


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=1, default=str))


def cmd_status(a):
    from ontoevo import kb
    from ontoevo.catalogs import Catalogs
    from ontoevo.proposals import Store
    from collections import Counter
    import ontocsirt_v7 as v7
    g = kb.load(a.profile)
    _print({"profile": a.profile, "triples": len(g),
            "incidents": len(set(g.subjects(v7.RDF.type, v7.OC.Incident))),
            "cases": len(set(g.subjects(v7.RDF.type, v7.OC.Case))),
            "acquired_file": kb.ACQUIRED if os.path.exists(kb.ACQUIRED) else None,
            "catalogs": Catalogs().status(),
            "gemini": {"model": a.model or gm.DEFAULT_MODEL, "mode": a.gemini_mode or os.environ.get("ONTOCSIRT_GEMINI_MODE", "cached"),
                       "api_key": bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))},
            "proposals": dict(Counter(r["status"] for r in Store(profile=a.profile).list()))})


def cmd_fetch_catalogs(a):
    from ontoevo import catalogs
    c = catalogs.fetch_cwe()
    t = catalogs.fetch_attack()
    _print({"cwe": c["version"], "cwe_entries": len(c["items"]), "attack": t["version"], "attack_techniques": len(t["items"])})


def cmd_acquire(a):
    from ontoevo.enrich import VulnAcquirer
    acq = VulnAcquirer(gemini=None if a.no_llm else _client(a), profile=a.profile, use_llm=not a.no_llm,
                       use_pellet=not a.no_pellet)
    out, code = [], 0
    for cve in a.cve:
        r = acq.acquire(cve.strip().upper(), label_mode=a.label, dry_run=a.dry_run)
        out.append(r)
        print("%-18s %-9s %s" % (cve, r["status"], r.get("reason") or ", ".join(r.get("new_individuals", [])[:6])), file=sys.stderr)
        code |= 0 if r["status"] in ("written", "dry-run") else 1
    _print(out)
    return code


def cmd_analyze(a):
    from ontoevo.cases import CaseAcquirer
    from ontoevo.enrich import VulnAcquirer
    client = _client(a)
    ca = CaseAcquirer(gemini=client, profile=a.profile, use_pellet=not a.no_pellet,
                      vuln_acquirer=VulnAcquirer(gemini=client, profile=a.profile))
    r = ca.analyze(a.cve.strip().upper(), dry_run=a.dry_run)
    _print(r)
    return 0 if r["status"] in ("written", "dry-run") else 1


def cmd_signals(a):
    from ontoevo import kb, signals
    from ontoevo.catalogs import Catalogs
    sig = signals.detect(kb.load(a.profile), Catalogs())
    if a.json:
        _print(sig)
    else:
        for s in sig:
            print("%-50s %s" % (s["id"], s["summary"]))
    return 0


def cmd_propose(a):
    from ontoevo import kb, signals
    from ontoevo.agent import EvolutionAgent
    from ontoevo.catalogs import Catalogs
    from ontoevo.proposals import Store
    store = Store(profile=a.profile)
    created = []
    if a.from_file:
        with open(a.from_file, encoding="utf-8") as f:
            data = json.load(f)
        for p in (data if isinstance(data, list) else [data]):
            created.append(store.create(p, a.by or "analyst", signal=p.get("signal_id")))
    else:
        sig = signals.detect(kb.load(a.profile), Catalogs())
        chosen = sig if a.all else [s for s in sig if s["id"] == a.signal]
        if not chosen:
            print("sinal nao encontrado; use 'signals' para ver os disponiveis", file=sys.stderr)
            return 2
        client = _client(a)
        for s in chosen:
            batch, meta = EvolutionAgent(gemini=client, profile=a.profile).propose(s)
            if not batch.proposals:
                print("%s: sem alteracao (%s)" % (s["id"], batch.no_change_reason), file=sys.stderr)
            for p in batch.proposals:
                created.append(store.create(p, "gemini:%s" % meta.get("model"), signal=s["id"],
                                            llm_meta={k: meta[k] for k in ("model", "trace", "cache_keys")}))
    for r in created:
        print("%s %-12s %s" % (r["id"], r["status"], ", ".join(r["compiled"]["new_classes"] + r["compiled"]["new_properties"])
                                or r["proposal"].get("class_name")), file=sys.stderr)
    _print([{"id": r["id"], "status": r["status"], "compiled": r["compiled"],
             "gate": [(c["name"], c["ok"]) for c in (r.get("gate") or {}).get("checks", [])]} for r in created])
    return 0 if all(r["status"] == "pending" for r in created) else 1


def cmd_list(a):
    from ontoevo.proposals import Store
    for r in Store(profile=a.profile).list(a.status):
        print("%s  %-12s %-22s %-40s %s" % (r["id"], r["status"], r["proposal"]["kind"],
                                           ", ".join(r["compiled"]["new_classes"] + r["compiled"]["new_properties"]) or r["proposal"].get("class_name"),
                                           r["proposed_by"]))


def cmd_show(a):
    from ontoevo.proposals import Store
    r = Store(profile=a.profile).get(a.id)
    if not a.full:
        r = {k: v for k, v in r.items() if k not in ("llm",)}
    _print(r)


def cmd_approve(a):
    from ontoevo.proposals import Store
    r = Store(profile=a.profile).approve(a.id, a.by, a.note)
    print("%s aprovada por %s" % (r["id"], r["approved_by"]))


def cmd_reject(a):
    from ontoevo.proposals import Store
    r = Store(profile=a.profile).reject(a.id, a.by, a.note)
    print("%s recusada" % r["id"])


def cmd_apply(a):
    from ontoevo.proposals import Store
    r = Store(profile=a.profile).apply(a.id, a.by)
    _print({"id": r["id"], "status": r["status"], **r["applied"]})


def cmd_validate(a):
    from ontoevo import evogate, kb
    import validar_ingestao as val
    g = kb.load(a.profile)
    rep = val.validate(g, use_pellet=True, use_hermit=True)
    cq, _ = evogate.competency(None)
    ok = rep["conforms"] and rep["hermit"]["consistent"] and not rep["hermit"]["unsatisfiable_classes"] \
        and rep["pellet"]["consistent"] and cq["passed"] == cq["total"]
    _print({"ok": ok, "triples": rep["n_triples"], "shacl_conforms": rep["conforms"],
            "violations": [v["message"] for v in rep["violations"]][:20], "hermit": rep["hermit"], "pellet": rep["pellet"],
            "competency_questions": "%d/%d" % (cq["passed"], cq["total"])})
    return 0 if ok else 1


def cmd_export(a):
    from ontoevo import kb
    out = a.out or os.path.join(kb.HERE, "OntoCSIRT_v7_composed_%s.ttl" % a.profile)
    kb.load(a.profile).serialize(out, format="turtle")
    print(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__ % {"model": gm.DEFAULT_MODEL},
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=["real", "base"], default="real")
    ap.add_argument("--model", default=None)
    ap.add_argument("--gemini-mode", choices=["live", "cached", "replay"], default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("fetch-catalogs").set_defaults(fn=cmd_fetch_catalogs)
    p = sub.add_parser("acquire")
    p.add_argument("cve", nargs="+")
    p.add_argument("--label", choices=["cwe-policy", "kev"], default="cwe-policy")
    p.add_argument("--no-llm", action="store_true", help="so fontes autorizadas (CVEs com lacunas sao recusadas)")
    p.add_argument("--no-pellet", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_acquire)
    p = sub.add_parser("analyze")
    p.add_argument("cve")
    p.add_argument("--no-pellet", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_analyze)
    p = sub.add_parser("signals")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_signals)
    p = sub.add_parser("propose")
    p.add_argument("--signal")
    p.add_argument("--all", action="store_true")
    p.add_argument("--from-file")
    p.add_argument("--by", help="autor de uma proposta --from-file")
    p.set_defaults(fn=cmd_propose)
    p = sub.add_parser("list")
    p.add_argument("--status")
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("show")
    p.add_argument("id")
    p.add_argument("--full", action="store_true")
    p.set_defaults(fn=cmd_show)
    p = sub.add_parser("approve")
    p.add_argument("id")
    p.add_argument("--by", required=True)
    p.add_argument("--note")
    p.set_defaults(fn=cmd_approve)
    p = sub.add_parser("reject")
    p.add_argument("id")
    p.add_argument("--by", required=True)
    p.add_argument("--note", required=True)
    p.set_defaults(fn=cmd_reject)
    p = sub.add_parser("apply")
    p.add_argument("id")
    p.add_argument("--by")
    p.set_defaults(fn=cmd_apply)
    sub.add_parser("validate").set_defaults(fn=cmd_validate)
    p = sub.add_parser("export")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_export)
    a = ap.parse_args()
    try:
        sys.exit(a.fn(a) or 0)
    except gm.GeminiUnavailable as e:
        print("Gemini indisponivel: %s" % e, file=sys.stderr)
        sys.exit(3)
    except Exception as e:  # noqa: BLE001
        from ontoevo.proposals import ProposalError
        if isinstance(e, ProposalError):
            print("erro: %s" % e, file=sys.stderr)
            sys.exit(2)
        raise


if __name__ == "__main__":
    main()
