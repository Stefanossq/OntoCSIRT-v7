#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
validar_ingestao.py - portao de qualidade antes de gravar dados ingeridos no .ttl.

Valida um grafo (TBox do OntoCSIRT v7 + extensao + modulo de evolucao + dados novos) com:
  1. pySHACL usando shapes_v7.ttl (as mesmas do artigo) + shapes_ingest.ttl
     (CVE duplicado, ator duplicado, ATT&CK mal formado, proveniencia do caso)
     + shapes_evo.ttl (meta-restricoes das classes/propriedades criadas pela evolucao);
  2. HermiT (padrao; --no-hermit desliga): consistencia OWL 2 DL sem as regras e classes
     insatisfaziveis - uma classe nova impossivel (p.ex. subclasse de duas categorias
     disjuntas) nao torna a ontologia inconsistente enquanto nao tiver membros, mas e um erro;
  3. opcionalmente o Pellet (via ontocsirt_v7.run_pellet), com as regras SWRL, que apanha o que o
     SHACL nao ve: p.ex. um CWE posto em duas categorias disjuntas.
Se algo falhar, o .ttl de saida NAO e escrito e o codigo de saida e != 0
(serve para CI: GitHub Actions, GitLab CI, um passo de pipeline no Shuffle).

Uso:
  python validar_ingestao.py staging.ttl --out OntoCSIRT_v7_real.ttl     # valida e, se passar, grava
  python validar_ingestao.py staging.ttl --pellet                        # + consistencia OWL
  python validar_ingestao.py --selftest                                  # injeta defeitos e mostra o bloqueio

Codigos de saida: 0 conforme; 1 violacoes SHACL; 2 inconsistente (HermiT ou Pellet); 3 erro de entrada;
4 classes insatisfaziveis (HermiT).
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

from rdflib import Graph, Literal, URIRef
from rdflib.namespace import OWL, RDF, RDFS, XSD

import ontocsirt_v7 as v7  # reutiliza run_pellet, TTL, SHAPES, OC, base_graph

HERE = v7.HERE
EXT = os.path.join(HERE, "OntoCSIRT_v7_ext.ttl")
SHAPES_INGEST = os.path.join(HERE, "shapes_ingest.ttl")
EVO = os.path.join(HERE, "OntoCSIRT_v7_evo.ttl")
SHAPES_EVO = os.path.join(HERE, "shapes_evo.ttl")
EVO_ONTOLOGY = URIRef("http://www.semanticweb.org/ontocsirt/evo")
EXT_ONTOLOGY = URIRef("http://www.semanticweb.org/ontocsirt/ext")
EXT_VERSION = "ext-2"          # igual ao owl:versionInfo de OntoCSIRT_v7_ext.ttl (verificado nos testes)
SH = "http://www.w3.org/ns/shacl#"
OC = v7.OC


def load_shapes():
    """shapes_v7.ttl (artigo) + shapes_ingest.ttl (ingestao) + shapes_evo.ttl (evolucao) num so grafo."""
    sg = Graph()
    sg.parse(v7.SHAPES, format="turtle")
    sg.parse(SHAPES_INGEST, format="turtle")
    if os.path.exists(SHAPES_EVO):
        sg.parse(SHAPES_EVO, format="turtle")
    return sg


def with_tbox(data, include_evo=True):
    """Garante que a TBox do v7, a extensao e (por omissao) o modulo de evolucao estao no grafo
    (as formas usam sh:class e subclasses). O modulo de evolucao nunca e copiado para os ficheiros
    de dados gravados pelo portao (include_evo=False): vive so em OntoCSIRT_v7_evo.ttl."""
    g = Graph()
    for t in data:
        g.add(t)
    if (OC.Incident, RDF.type, OWL.Class) not in g:
        g.parse(v7.TTL, format="turtle")
    # versao explicita da extensao: bases gravadas com uma copia antiga (p.ex. OntoCSIRT_v7_real.ttl,
    # ext-1) recebem o vocabulario atual; a uniao de triplas nomeadas e idempotente
    if (EXT_ONTOLOGY, OWL.versionInfo, Literal(EXT_VERSION)) not in g:
        g.parse(EXT, format="turtle")
    if include_evo and os.path.exists(EVO) and (EVO_ONTOLOGY, RDF.type, OWL.Ontology) not in g:
        g.parse(EVO, format="turtle")
    return g


def validate(graph, use_pellet=False, use_hermit=False):
    """Devolve um relatorio dict: conforms, n_violations, violations[...], hermit{...}, pellet{...}."""
    from pyshacl import validate as shacl_validate
    g = with_tbox(graph)
    conforms, rg, text = shacl_validate(g, shacl_graph=load_shapes(), inference="rdfs",
                                        advanced=True, abort_on_first=False, allow_warnings=True)
    if not isinstance(rg, Graph):                     # pySHACL: formas mal construidas (nao e uma violacao)
        raise RuntimeError("grafo de formas SHACL invalido: %s" % text)
    viol = []
    for r in rg.subjects(RDF.type, URIRef(SH + "ValidationResult")):
        get = lambda p: rg.value(r, URIRef(SH + p))  # noqa: E731
        viol.append({
            "focus": v7.short(get("focusNode")),
            "path": v7.short(get("resultPath")) if get("resultPath") is not None else None,
            "value": v7.short(get("value")) if get("value") is not None else None,
            "shape": v7.short(get("sourceShape")) if isinstance(get("sourceShape"), URIRef) else
                     v7.short(get("sourceConstraintComponent")),
            "severity": v7.short(get("resultSeverity")),
            "message": str(get("resultMessage")).replace(str(OC), ":"),
        })
    # SHACL-SPARQL reporta o par (A,B) e (B,A); mantem um so
    seen, uniq = set(), []
    for v in sorted(viol, key=lambda x: (x["message"], x["focus"])):
        iris = frozenset(re.findall(r":[A-Za-z_][\w-]*", v["message"])) or frozenset([v["focus"]])
        key = (v["shape"], v["path"], iris, v["message"].split(":")[0])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(v)
    rep = {"conforms": bool(conforms), "n_violations": len(uniq), "violations": uniq, "n_triples": len(g)}
    if use_hermit:
        ok, dt, unsat = v7.run_hermit(g)
        # owl:Nothing aparece na lista do Owlready2 sempre que ha outra classe equivalente a ela
        rep["hermit"] = {"consistent": ok, "seconds": round(dt, 2),
                         "unsatisfiable_classes": sorted(c for c in unsat if c != "Nothing")}
    if use_pellet:
        ok, dt, ig, _, _ = v7.run_pellet(g)
        rep["pellet"] = {"consistent": ok, "seconds": round(dt, 2),
                         "inferred_triples": len(ig) if ig is not None else None}
    return rep


def print_report(rep, out=sys.stdout):
    h = rep.get("hermit", {})
    if rep["conforms"] and rep.get("pellet", {}).get("consistent", True) and h.get("consistent", True) \
            and not h.get("unsatisfiable_classes"):
        print("OK: grafo conforme (%d triplas)%s%s" % (
            rep["n_triples"], "; HermiT: consistente, 0 classes insatisfaziveis (%.1f s)" % h["seconds"] if h else "",
            "; Pellet: consistente em %.1f s" % rep["pellet"]["seconds"] if "pellet" in rep else ""), file=out)
        return
    if rep["conforms"]:
        print("BLOQUEADO pelo raciocinador (SHACL conforme)", file=out)
    by_msg = defaultdict(list)
    for v in rep["violations"]:
        by_msg[v["message"].split(":")[0]].append(v)
    print("BLOQUEADO: %d violacao(oes) SHACL" % rep["n_violations"], file=out)
    for msg, vs in sorted(by_msg.items()):
        print("  - %s (%d)" % (msg, len(vs)), file=out)
        for v in vs[:8]:
            print("      no=%s propriedade=%s valor=%s :: %s" % (v["focus"], v["path"], v["value"], v["message"]), file=out)
        if len(vs) > 8:
            print("      ... mais %d" % (len(vs) - 8), file=out)
    if h and not h["consistent"]:
        print("  - HermiT: ONTOLOGIA INCONSISTENTE (OWL 2 DL, sem as regras SWRL)", file=out)
    if h and h.get("unsatisfiable_classes"):
        print("  - HermiT: classes insatisfaziveis: %s" % ", ".join(h["unsatisfiable_classes"]), file=out)
    if "pellet" in rep and not rep["pellet"]["consistent"]:
        print("  - Pellet: ONTOLOGIA INCONSISTENTE (ver disjuncoes de classes, funcionalidade do CVSS)", file=out)


def gate(graph, out_path=None, use_pellet=False, report_path=None, use_hermit=True):
    """Valida; se passar e out_path for dado, grava o .ttl. Devolve o codigo de saida."""
    rep = validate(graph, use_pellet, use_hermit)
    print_report(rep)
    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
    if not rep["conforms"]:
        return 1
    if use_hermit and not rep["hermit"]["consistent"]:
        return 2
    if use_hermit and rep["hermit"]["unsatisfiable_classes"]:
        return 4
    if use_pellet and not rep["pellet"]["consistent"]:
        return 2
    if out_path:
        with_tbox(graph, include_evo=False).serialize(out_path, format="turtle")
        print("gravado: %s" % out_path)
    return 0


# ------------------------------------------------------------------ autoteste
def selftest():
    """Injeta defeitos tipicos de uma ingestao e verifica que cada um e bloqueado."""
    base = v7.base_graph()
    base.parse(EXT, format="turtle")
    print("base v7 + extensao:")
    assert gate(base) == 0, "a base deveria passar"

    def case(name, triples, expect_code, pellet=False):
        g = Graph()
        for t in base:
            g.add(t)
        for t in triples:
            g.add(t)
        print("\n[%s]" % name)
        code = gate(g, use_pellet=pellet)
        status = "OK" if code == expect_code else "FALHOU (esperado %d, obtido %d)" % (expect_code, code)
        print("  -> codigo %d: %s" % (code, status))
        return code == expect_code

    V = OC.Vuln_Test
    results = [
        case("CVE mal formado", [(V, RDF.type, OC.Vulnerability), (V, OC.cveId, Literal("CVE-21-44228")),
                                 (V, OC.hasWeakness, OC.CWE_502), (V, OC.cvssBaseScore, Literal("10.0", datatype=XSD.decimal))], 1),
        case("CVE duplicado (mesmo id, IRI diferente)", [(V, RDF.type, OC.Vulnerability), (V, OC.cveId, Literal("CVE-2021-26855")),
                                                         (V, OC.hasWeakness, OC.CWE_918), (V, OC.cvssBaseScore, Literal("9.8", datatype=XSD.decimal))], 1),
        case("ator duplicado (mesmo rotulo, IRI diferente)", [(OC.Actor_FIN_A_bis, RDF.type, OC.ExternalActor),
                                                              (OC.Actor_FIN_A_bis, RDFS.label, Literal("Grupo FIN-A (externo, motivacao financeira, ficticio)"))], 1),
        case("CVSS fora de [0,10]", [(V, RDF.type, OC.Vulnerability), (V, OC.cveId, Literal("CVE-2099-0001")),
                                     (V, OC.hasWeakness, OC.CWE_89), (V, OC.cvssBaseScore, Literal("11.5", datatype=XSD.decimal))], 1),
        case("ATT&CK mal formado", [(OC.AP_Bad, RDF.type, OC.AttackPattern), (OC.AP_Bad, OC.attackId, Literal("T19"))], 1),
        case("CWE em duas categorias disjuntas (SHACL + Pellet)", [(OC.CWE_89, RDF.type, OC.MemorySafetyWeakness)], 1, pellet=True),
        # HermiT: classe sem membros sob duas categorias disjuntas - consistente, mas insatisfazivel
        case("classe insatisfazivel (HermiT)", [(OC.Bad_Category, RDF.type, OWL.Class),
                                                (OC.Bad_Category, RDFS.subClassOf, OC.InjectionWeakness),
                                                (OC.Bad_Category, RDFS.subClassOf, OC.MemorySafetyWeakness)], 4),
        # subcategoria de 2.o nivel e uma so categoria: tem de PASSAR (antes era bloqueada pela SHACL)
        case("subcategoria de 2.o nivel (deve passar)", [(OC.SQLInjectionWeakness, RDF.type, OWL.Class),
                                                         (OC.SQLInjectionWeakness, RDFS.subClassOf, OC.InjectionWeakness),
                                                         (OC.CWE_89, RDF.type, OC.SQLInjectionWeakness)], 0, pellet=True),
    ]
    print("\nautoteste: %d/%d defeitos bloqueados como esperado" % (sum(results), len(results)))
    return 0 if all(results) else 1


def main():
    ap = argparse.ArgumentParser(description="Validacao SHACL (+Pellet) antes de gravar dados ingeridos.")
    ap.add_argument("staging", nargs="?", help="Turtle com os dados novos (pode ou nao incluir a TBox)")
    ap.add_argument("--out", help="caminho do .ttl a gravar se a validacao passar")
    ap.add_argument("--pellet", action="store_true", help="tambem verifica consistencia com o Pellet")
    ap.add_argument("--no-hermit", action="store_true", help="nao corre o HermiT (consistencia e classes insatisfaziveis)")
    ap.add_argument("--report", help="grava o relatorio em JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if not a.staging or not os.path.exists(a.staging):
        print("erro: indique um ficheiro Turtle existente", file=sys.stderr)
        sys.exit(3)
    g = Graph()
    try:
        g.parse(a.staging, format="turtle")
    except Exception as e:  # noqa: BLE001
        print("erro: Turtle invalido: %s" % e, file=sys.stderr)
        sys.exit(3)
    sys.exit(gate(g, a.out, a.pellet, a.report, use_hermit=not a.no_hermit))


if __name__ == "__main__":
    main()
