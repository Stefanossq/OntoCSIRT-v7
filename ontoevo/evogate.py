# -*- coding: utf-8 -*-
"""
evogate.py - portao de qualidade de uma alteracao estrutural (antes de aprovar e de novo antes de aplicar).

Verificacoes, todas sobre o grafo CANDIDATO (base composta atual + alteracao compilada):
  1. compilacao      erros estruturais do compiler (nomes, raizes, ramos, dominio/contradominio)
  2. sintaxe         as triplas da alteracao serializam e voltam a ler em Turtle
  3. SHACL           shapes_v7 + shapes_ingest + shapes_evo (rotulos, definicao, superclasse,
                     proveniencia, conceito duplicado, nucleo protegido, categoria unica...)
  4. HermiT          consistencia OWL 2 DL e ZERO classes insatisfaziveis
  5. HermiT (classificacao)  redundancia: uma classe nova inferida EQUIVALENTE a uma classe existente
                     e recusada (nao acrescenta conceito); regista superclasses e membros inferidos
                     (uma classe definida pode classificar individuos sozinha)
  6. Pellet + SWRL   consistencia com as regras R1-R6
  7. regressao       as 8 questoes de competencia do artigo continuam a dar as respostas esperadas
                     na base do artigo com a alteracao (OntoCSIRT_v7.ttl + ext + evo + alteracao)
  8. LOOCV (informativo)  Acc@1 da recuperacao antes/depois na base do artigo - nao bloqueia: uma
                     taxonomia mais fina pode mudar a similaridade por boas razoes, mas a variacao fica registada
"""
import contextlib
import io
import os
import tempfile
import time

from rdflib import Graph

import ontocsirt_v7 as v7
import validar_ingestao as val

from . import kb

OC = v7.OC


def candidate_graph(compiled, profile="real", acquired_path=None, base=None):
    g = base if base is not None else kb.load(profile, acquired_path=acquired_path)
    for t in compiled.retracts:
        g.remove(t)
    for t in compiled.adds:
        g.add(t)
    return g


def hermit_classification(graph, new_classes):
    """Classifica com HermiT (sem SWRL) e devolve, por classe nova: equivalentes nomeadas, superclasses
    nomeadas inferidas e individuos inferidos como membros."""
    import owlready2 as o2
    tmp = tempfile.NamedTemporaryFile(suffix=".owl", delete=False)
    tmp.close()
    v7.strip_swrl(graph).serialize(tmp.name, format="xml", encoding="utf-8")
    world = o2.World()
    world.get_ontology("file://" + tmp.name).load(format="rdfxml")
    out, t0 = {}, time.time()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            o2.sync_reasoner_hermit(world, infer_property_values=False, debug=0)
    except o2.OwlReadyInconsistentOntologyError:
        os.unlink(tmp.name)
        return {"consistent": False}
    for name in new_classes:
        cls = world[str(OC) + name]
        if cls is None:
            continue
        named = lambda xs: sorted({c.name for c in xs if isinstance(c, o2.ThingClass) and c is not cls})  # noqa: E731
        out[name] = {"equivalent_named": [n for n in named(cls.equivalent_to) if n != "Nothing"],
                     "inferred_parents": named(cls.is_a),
                     "inferred_members": sorted({i.name for i in cls.instances()})}
    os.unlink(tmp.name)
    return {"consistent": True, "classes": out, "seconds": round(time.time() - t0, 2)}


def base_with(compiled=None):
    """Base do artigo + extensao + modulo de evolucao atual (+ alteracao)."""
    g = v7.base_graph()
    g.parse(val.EXT, format="turtle")
    if os.path.exists(val.EVO):
        g.parse(val.EVO, format="turtle")
    if compiled is not None:
        for t in compiled.adds:
            g.add(t)
    return g


def competency(compiled=None):
    g = base_with(compiled)
    ok, dt, ig, _, _ = v7.run_pellet(g)
    if not ok:
        return {"consistent": False, "passed": 0, "total": len(v7.CQS)}, None
    rows = []
    for cid, text, sparql, expected in v7.CQS:
        got = {r[0] for r in v7.q(ig, sparql)}
        rows.append({"id": cid, "pass": got == expected, "missing": sorted(expected - got), "unexpected": sorted(got - expected)})
    return {"consistent": True, "passed": sum(r["pass"] for r in rows), "total": len(rows),
            "failed": [r for r in rows if not r["pass"]], "seconds": round(dt, 2)}, ig


def loocv_acc1(ig):
    F = v7.features(ig)
    ids = sorted(i for i in F if F[i]["sol"])
    acc = []
    for qi in ids:
        others = [i for i in ids if i != qi]
        relevant = {i for i in others if F[i]["sol"] == F[qi]["sol"]}
        acc.append(v7.expected_topk([(v7.sim(F[qi], F[i]), i) for i in others], relevant, 1))
    return round(sum(acc) / len(acc), 3) if acc else None


_BASELINE = {}


def baseline_loocv():
    key = os.path.getmtime(val.EVO) if os.path.exists(val.EVO) else 0
    if key not in _BASELINE:
        _BASELINE.clear()
        _, ig = competency(None)
        _BASELINE[key] = loocv_acc1(ig) if ig is not None else None
    return _BASELINE[key]


def run(compiled, profile="real", acquired_path=None, regression=True):
    t0 = time.time()
    checks = []

    def check(name, ok, detail=None, blocking=True):
        checks.append({"name": name, "ok": bool(ok), "blocking": blocking, "detail": detail})
        return ok

    if not check("compilacao", compiled.ok, compiled.errors or None):
        return _result(checks, t0)
    try:
        Graph().parse(data=compiled.turtle(), format="turtle")
        check("sintaxe Turtle", True)
    except Exception as e:  # noqa: BLE001
        check("sintaxe Turtle", False, str(e))
        return _result(checks, t0)
    cand = candidate_graph(compiled, profile, acquired_path)
    rep = val.validate(cand, use_pellet=True, use_hermit=True)
    check("SHACL (v7 + ingestao + evo)", rep["conforms"], [v["message"] for v in rep["violations"]][:20] or None)
    h = rep["hermit"]
    check("HermiT: consistencia", h["consistent"])
    check("HermiT: classes insatisfaziveis", h["consistent"] and not h["unsatisfiable_classes"], h["unsatisfiable_classes"] or None)
    check("Pellet + SWRL: consistencia", rep["pellet"]["consistent"])
    classification = None
    if h["consistent"] and compiled.new_classes:
        classification = hermit_classification(cand, compiled.new_classes)
        redundant = {c: x["equivalent_named"] for c, x in classification.get("classes", {}).items() if x["equivalent_named"]}
        check("HermiT: sem redundancia (equivalencia inferida)", not redundant, redundant or None)
    loocv = None
    if regression:
        cq, ig = competency(compiled)
        check("regressao: questoes de competencia do artigo", cq["consistent"] and cq["passed"] == cq["total"],
              {"passed": cq["passed"], "total": cq["total"], "failed": cq.get("failed")})
        if ig is not None:
            loocv = {"base_acc1_before": baseline_loocv(), "base_acc1_after": loocv_acc1(ig)}
            check("LOOCV Acc@1 na base do artigo (informativo)", True, loocv, blocking=False)
    res = _result(checks, t0)
    res.update(classification=classification, loocv=loocv,
               hermit={"seconds": h.get("seconds")}, pellet={"seconds": rep["pellet"]["seconds"]})
    return res


def _result(checks, t0):
    return {"passed": all(c["ok"] for c in checks if c["blocking"]), "checks": checks,
            "seconds": round(time.time() - t0, 2)}
