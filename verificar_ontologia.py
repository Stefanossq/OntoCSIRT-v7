#!/usr/bin/env python3
"""Verificacao rapida da OntoCSIRT v7 para a banca (cerca de 1 minuto, sem rede e sem chaves).

    python verificar_ontologia.py            # checklist no terminal; codigo de saida 0 se tudo passar
    python verificar_ontologia.py --json     # o mesmo em JSON

Verifica, por esta ordem:
  1. sintaxe Turtle de todos os .ttl do repositorio;
  2. SHA-256 da base do artigo (OntoCSIRT_v7.ttl), igual ao citado no artigo;
  3. HermiT (consistencia e classes insatisfaziveis), Pellet com as regras SWRL e SHACL, em cinco composicoes
     (base do artigo; + extensao e evolucao; dados reais; producao com os dados adquiridos; modulo de bug bounty);
  4. as 8 questoes de competencia do artigo sobre a base inferida pelo Pellet;
  5. o portao de qualidade recusa defeitos injetados (SHACL, HermiT e Pellet).
A suite completa (164 testes, ~8 min) continua a ser `python -m pytest -q tests`.
"""
import argparse
import glob
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

from rdflib import Graph, Literal, RDF, RDFS, OWL, XSD  # noqa: E402

import ontocsirt_v7 as v7  # noqa: E402
import validar_ingestao as val  # noqa: E402

BASE_SHA256 = "8c2fc5f00faee4bf5a4b8e38a96d8ed2b92da8f28c825f49eda68a80b1720e69"
OC = v7.OC
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ARGS.json:
        print("  [%s] %s%s" % ("OK" if ok else "FALHOU", name, ("  (%s)" % detail) if detail else ""), flush=True)
    return ok


def parse(path):
    g = Graph()
    g.parse(path, format="turtle")
    return g


def union(*graphs):
    g = Graph()
    for x in graphs:
        for t in x:
            g.add(t)
    return g


def section(title):
    if not ARGS.json:
        print("\n" + title, flush=True)


def main():
    t0 = time.time()
    section("1. Sintaxe Turtle")
    graphs = {}
    for f in sorted(glob.glob("*.ttl") + glob.glob("ontology/*.ttl")):
        try:
            graphs[f.replace(os.sep, "/")] = g = parse(f)
            check(f.replace(os.sep, "/"), True, "%d triplas" % len(g))
        except Exception as e:  # noqa: BLE001
            check(f, False, str(e)[:120])

    section("2. Integridade da base do artigo")
    sha = v7.sha256(v7.TTL)
    check("SHA-256 de OntoCSIRT_v7.ttl", sha == BASE_SHA256, sha[:16] + "...")

    section("3. Raciocinadores e SHACL por composicao")
    base, ext, evo = graphs["OntoCSIRT_v7.ttl"], graphs["OntoCSIRT_v7_ext.ttl"], graphs["OntoCSIRT_v7_evo.ttl"]
    comps = [
        ("base do artigo", base),
        ("base + extensao + evolucao", union(base, ext, evo)),
        ("dados reais (KEV/NVD/ATT&CK)", union(base, ext, evo, graphs["OntoCSIRT_v7_real.ttl"])),
        ("producao (reais + adquiridos)", union(base, ext, evo, graphs["OntoCSIRT_v7_real.ttl"],
                                                graphs["OntoCSIRT_v7_acquired.ttl"])),
        ("modulo OntoBugBounty", union(base, ext, evo, graphs["ontology/OntoBugBounty.ttl"],
                                        graphs["ontology/bugbounty_refined.ttl"], graphs["ontology/hunter_tools.ttl"])),
    ]
    inferred_base = None
    for name, g in comps:
        ok_h, dt_h, unsat = v7.run_hermit(g)
        unsat = [u for u in unsat if u != "Nothing"]
        check("%s: HermiT consistente, 0 classes insatisfaziveis" % name, ok_h and not unsat,
              "%.1f s%s" % (dt_h, "; insatisfaziveis: %s" % unsat if unsat else ""))
        ok_p, dt_p, ig, _, _ = v7.run_pellet(g)
        check("%s: Pellet + SWRL consistente" % name, ok_p, "%.1f s" % dt_p)
        rep = val.validate(g)
        check("%s: SHACL conforme" % name, rep["conforms"], "%d violacoes" % rep["n_violations"])
        if inferred_base is None:
            inferred_base = ig

    section("4. Questoes de competencia (artigo)")
    passed = 0
    for cid, text, sparql, expected in v7.CQS:
        got = {r[0] for r in v7.q(inferred_base, sparql)} if inferred_base is not None else set()
        passed += check("%s %s" % (cid, text), got == expected, "%d/%d" % (len(got & expected), len(expected)))

    section("5. O portao recusa defeitos injetados")

    def rejected(name, triples, pellet=False):
        g = union(base, ext)
        for t in triples:
            g.add(t)
        rep = val.validate(g, use_hermit=True, use_pellet=pellet)
        h = rep["hermit"]
        blocked = (not rep["conforms"]) or (not h["consistent"]) or h["unsatisfiable_classes"] or \
                  (pellet and not rep["pellet"]["consistent"])
        why = [w for w, c in (("SHACL", not rep["conforms"]), ("HermiT", not h["consistent"] or h["unsatisfiable_classes"]),
                              ("Pellet", pellet and not rep["pellet"]["consistent"])) if c]
        check(name, blocked, "detetado por " + ", ".join(why) if why else "NAO detetado")

    V, W = OC.Vuln_Banca, OC.Weak_Banca
    rejected("incidente sem ator, acao, ativo e atributo", [(OC.Incident_Banca, RDF.type, OC.Incident)])
    rejected("CVSS 12.5 e CVE mal formado", [
        (V, RDF.type, OC.Vulnerability), (V, OC.cveId, Literal("CVE-24-1")),
        (V, OC.cvssBaseScore, Literal("12.5", datatype=XSD.decimal)), (V, OC.hasWeakness, W),
        (W, RDF.type, OC.InjectionWeakness), (W, OC.cweId, Literal("CWE-89"))])
    rejected("nivel de risco fora do vocabulario", [(OC.Incident_01, OC.hasRiskLevel, Literal("Catastrophic"))])
    rejected("individuo em classes disjuntas (Incident e Asset)", [(OC.Incident_01, RDF.type, OC.Asset)], pellet=True)
    rejected("classe sob duas categorias de fraqueza disjuntas", [
        (OC.ClasseBanca, RDF.type, OWL.Class), (OC.ClasseBanca, RDFS.subClassOf, OC.InjectionWeakness),
        (OC.ClasseBanca, RDFS.subClassOf, OC.AccessControlWeakness)])

    ok = all(r["ok"] for r in RESULTS)
    total, good = len(RESULTS), sum(r["ok"] for r in RESULTS)
    if ARGS.json:
        print(json.dumps({"ok": ok, "passed": good, "total": total, "seconds": round(time.time() - t0, 1),
                          "results": RESULTS}, indent=1, ensure_ascii=False))
    else:
        print("\n%s: %d/%d verificacoes passaram em %.0f s" % ("TUDO OK" if ok else "HA FALHAS", good, total,
                                                              time.time() - t0))
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="resultado em JSON")
    ARGS = ap.parse_args()
    sys.exit(main())
