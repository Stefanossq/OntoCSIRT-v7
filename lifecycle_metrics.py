#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
lifecycle_metrics.py - numeros do ciclo de vida da ontologia para o artigo (mesmo padrao do ontocsirt_v7.py:
os numeros do texto vem sempre desta execucao, nunca escritos a mao).

Tres configuracoes:
  A  Base       OntoCSIRT_v7.ttl (o artigo; 24 casos, 18 sinteticos)
  B  Real       OntoCSIRT_v7_real.ttl + extensao + modulo de evolucao (evo-N) + OntoCSIRT_v7_acquired.ttl
  C  Tempo real B + um alerta SOAR com uma CVE ausente da base (CVE-2024-3400 por omissao), tratado pelo
                soar_webhook.Engine com o NVDEnricher: NVD -> ramo validado -> Pellet -> recomendacao;
                um segundo alerta com a mesma CVE mede o caminho sem NVD.
Os ficheiros do projeto nao sao alterados: C trabalha numa copia temporaria do ficheiro de dados.

  python lifecycle_metrics.py            # NVD a partir do registo guardado (tests/fixtures/nvd): reprodutivel, sem rede
  python lifecycle_metrics.py --live     # consulta real a API do NVD (sem cache) - mede a latencia da rede

Gera: evidence_v7/lifecycle.json, artigo/numbers_lifecycle.tex, artigo/tab_lifecycle.tex
"""
import argparse
import contextlib
import io
import json
import os
import shutil
import tempfile
import time
from collections import Counter

import requests
from rdflib import URIRef
from rdflib.namespace import OWL, RDF

import nvd_enricher as ne
import ontocsirt_v7 as v7
import ontotax
import validar_ingestao as val
from ontoevo import kb, signals
from ontoevo.catalogs import Catalogs

OC = v7.OC
FIX = os.path.join(v7.HERE, "tests", "fixtures", "nvd")


# ------------------------------------------------------------------ metricas de uma configuracao
def structure(g):
    tax = ontotax.Taxonomy(g)
    classes = {c for c in g.subjects(RDF.type, OWL.Class) if isinstance(c, URIRef)}
    depth = max((max(tax.ancestors(c).values()) + 1 for c in classes), default=0)   # 1 = classe de topo
    cases = set(g.subjects(RDF.type, OC.Case))
    prov = Counter(str(g.value(c, OC.solutionProvenance) or "historico (artigo)") for c in cases)
    return {
        "triples": len(g),
        "classes": len(classes),
        "object_properties": len(set(g.subjects(RDF.type, OWL.ObjectProperty))),
        "data_properties": len(set(g.subjects(RDF.type, OWL.DatatypeProperty))),
        "max_depth": depth,
        "weakness_categories": len([c for c in tax.subclasses(OC.Weakness) if c not in tax.derived]),
        "incidents": len(set(g.subjects(RDF.type, OC.Incident))),
        "cases": len(cases),
        "case_provenance": dict(prov),
        "cves": len({str(o) for o in g.objects(None, OC.cveId)}),
        "cwes": len({str(o) for o in g.objects(None, OC.cweId)}),
        "attack_techniques": len({str(o) for o in g.objects(None, OC.attackId)}),
        "evo_version": str(g.value(val.EVO_ONTOLOGY, OWL.versionInfo) or "-"),
    }


def reasoning(g, shapes="all"):
    ok_h, t_h, unsat = v7.run_hermit(g)
    ok_p, t_p, ig, _, _ = v7.run_pellet(g)
    if shapes == "v7":
        conf, nviol, _ = v7.run_shacl(g)
    else:
        rep = val.validate(g)
        conf, nviol = rep["conforms"], rep["n_violations"]
    return {"hermit_consistent": ok_h, "hermit_unsat": len([c for c in unsat if c != "Nothing"]), "hermit_seconds": round(t_h, 2),
            "pellet_consistent": ok_p, "pellet_seconds": round(t_p, 2),
            "pellet_inferred": (len(ig) - len(g)) if ig is not None else None,
            "shacl_conforms": conf, "shacl_violations": nviol, "shacl_shapes": shapes}, ig


def cq_base(ig):
    got = sum({r[0] for r in v7.q(ig, s)} == exp for _, _, s, exp in v7.CQS)
    return "%d/%d" % (got, len(v7.CQS))


def loocv_base(ig):
    from ontoevo.evogate import loocv_acc1
    return loocv_acc1(ig)


# ------------------------------------------------------------------ sessao NVD (registo guardado ou rede real)
class FixtureSession:
    """Serve o registo NVD guardado (reprodutivel, sem rede)."""

    def __init__(self):
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        cve = params["cveId"]
        with open(os.path.join(FIX, cve + ".json"), encoding="utf-8") as f:
            rec = json.load(f)
        self.calls.append({"cve": cve, "seconds": 0.0})

        class R:
            status_code = 200

            def json(self_inner):
                return {"totalResults": 1, "vulnerabilities": [{"cve": rec}]}
        return R()


class TimedSession(requests.Session):
    """Sessao real que regista o tempo de cada pedido ao NVD."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def get(self, url, **kw):
        t0 = time.time()
        r = super().get(url, **kw)
        self.calls.append({"cve": kw.get("params", {}).get("cveId"), "status": r.status_code, "seconds": round(time.time() - t0, 2)})
        return r


def realtime(cve, live):
    import soar_webhook as sw
    tmp = tempfile.mkdtemp(prefix="ontocsirt_lc_")
    try:
        acq = os.path.join(tmp, "acquired.ttl")
        if os.path.exists(kb.ACQUIRED):
            shutil.copy(kb.ACQUIRED, acq)
        session = TimedSession() if live else FixtureSession()
        enricher = ne.NVDEnricher(kb_path=kb.REAL, cache_dir=os.path.join(tmp, "cache"), session=session)
        eng = sw.Engine(kb.REAL, reasoner="pellet", acquired=acq, enricher=enricher)
        if eng.cve_in_kb(cve):
            raise SystemExit("%s ja esta na base; escolha uma CVE ausente (--cve)" % cve)
        alert = {"src_ip": "198.51.100.23", "attack_type": "cmdi", "target": "Gateway_1", "cve": cve,
                 "attribute": "confidentiality", "alert_id": "LC-1"}
        code1, r1 = eng.handle(dict(alert))
        code2, r2 = eng.handle(dict(alert, alert_id="LC-2", src_ip="198.51.100.24"))
        if code1 != 200 or r1.get("fallback"):
            raise SystemExit("o alerta nao foi enriquecido: %s" % json.dumps(r1, ensure_ascii=False)[:600])
        g = kb.load("real", acquired_path=acq)
        enr = r1["nvd_enrichment"]
        return g, {
            "cve": cve, "nvd_mode": "api (rede real)" if live else "registo NVD guardado (tests/fixtures/nvd)",
            "nvd_http": session.calls,
            "nvd_fetch_seconds": session.calls[0]["seconds"] if session.calls else None,
            "enrichment": {k: enr.get(k) for k in ("vulnerability", "cwe", "category", "cvss", "cvss_version", "vuln_status",
                                                    "triples", "seconds", "gate")},
            "alert1": {"seconds": r1["elapsed_seconds"], "pellet_seconds": r1["reasoner"]["seconds"], "risk": r1["risk_level"],
                       "action": r1["action_iri"], "playbook": r1["playbook"], "confidence": r1["confidence"],
                       "requires_human_approval": r1["requires_human_approval"]},
            "alert2": {"seconds": r2["elapsed_seconds"], "pellet_seconds": r2["reasoner"]["seconds"], "risk": r2["risk_level"],
                       "action": r2["action_iri"], "nvd_enrichment": r2["nvd_enrichment"]},
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ saida
def tex_num(v):
    if isinstance(v, bool):
        return "sim" if v else "n\\~ao"
    if isinstance(v, float):
        return ("%.2f" % v).replace(".", "{,}")
    return str(v).replace("_", "\\_").replace("&", "\\&").replace("%", "\\%")


def write_tex(res):
    A, B, C = res["A_base"], res["B_real"], res["C_realtime"]
    rt = res["realtime"]
    N = {}
    for key, cfg in (("Base", A), ("Real", B), ("Live", C)):
        s, r = cfg["structure"], cfg["reasoning"]
        for name, val_ in (("Triples", s["triples"]), ("Classes", s["classes"]), ("ObjProps", s["object_properties"]),
                           ("Depth", s["max_depth"]), ("WeakCats", s["weakness_categories"]), ("Incidents", s["incidents"]),
                           ("Cases", s["cases"]), ("Cves", s["cves"]), ("Cwes", s["cwes"]), ("Attack", s["attack_techniques"]),
                           ("HermitSec", r["hermit_seconds"]), ("PelletSec", r["pellet_seconds"]),
                           ("Inferred", r["pellet_inferred"]), ("Unsat", r["hermit_unsat"]), ("ShaclViol", r["shacl_violations"])):
            N["lc%s%s" % (key, name)] = tex_num(val_)
    N["lcEvoVersion"] = tex_num(B["structure"]["evo_version"])
    N["lcBaseCq"], N["lcRegressionCq"] = A["cq"], res["regression_cq"]
    N["lcBaseAcc"] = tex_num(A["loocv_acc1"])
    N["lcCve"] = tex_num(rt["cve"])
    N["lcCvss"] = tex_num(float(rt["enrichment"]["cvss"]))
    N["lcCwe"] = tex_num(rt["enrichment"]["cwe"])
    N["lcCategory"] = tex_num(rt["enrichment"]["category"])
    N["lcEnrichSec"] = tex_num(rt["enrichment"]["seconds"])
    N["lcEnrichTriples"] = tex_num(rt["enrichment"]["triples"])
    N["lcNvdSec"] = tex_num(rt["nvd_fetch_seconds"]) if rt["nvd_fetch_seconds"] is not None else "n/d"
    N["lcNvdMode"] = "API real" if rt["nvd_mode"].startswith("api") else "registro guardado"
    N["lcAlertOneSec"] = tex_num(rt["alert1"]["seconds"])
    N["lcAlertTwoSec"] = tex_num(rt["alert2"]["seconds"])
    N["lcRisk"] = tex_num(rt["alert1"]["risk"])
    N["lcAction"] = tex_num(rt["alert1"]["action"])
    N["lcConfidence"] = tex_num(float(rt["alert1"]["confidence"]))
    N["lcSignals"] = tex_num(res["open_signals"])
    out = os.path.join(v7.HERE, "artigo")
    with open(os.path.join(out, "numbers_lifecycle.tex"), "w", encoding="utf-8") as f:
        f.write("% Gerado por lifecycle_metrics.py - nao editar\n")
        for k, v in N.items():
            f.write("\\newcommand{\\%s}{%s}\n" % (k, v))
    rows = [
        ("Triplas", "Triples"), ("Classes nomeadas", "Classes"), ("Propriedades de objeto", "ObjProps"),
        ("Profundidade m\\'axima da hierarquia", "Depth"), ("Categorias de fraqueza", "WeakCats"),
        ("Incidentes", "Incidents"), ("Casos", "Cases"), ("CVE distintos", "Cves"), ("CWE distintas", "Cwes"),
        ("T\\'ecnicas ATT\\&CK", "Attack"), ("Classes insatisfaz\\'iveis (HermiT)", "Unsat"),
        ("Viola\\c{c}\\~oes SHACL", "ShaclViol"),
        ("Tempo do HermiT (s)", "HermitSec"), ("Tempo do Pellet (s)", "PelletSec"),
    ]
    # "triplas inferidas" (len(grafo exportado) - len(grafo afirmado)) fica so na evidencia JSON: depende de como
    # o Owlready2 reexporta cada ficheiro (anotacoes, nos em branco) e nao e comparavel entre configuracoes
    with open(os.path.join(out, "tab_lifecycle.tex"), "w", encoding="utf-8") as f:
        f.write("% Gerado por lifecycle_metrics.py\n\\begin{tabular}{@{}lrrr@{}}\n\\toprule\n"
                " & Base & Ingest\\~ao real & Tempo real (NVD)\\\\\n\\midrule\n")
        for label, key in rows:
            f.write("%s & \\lcBase%s & \\lcReal%s & \\lcLive%s\\\\\n" % (label, key, key, key))
        f.write("\\bottomrule\n\\end{tabular}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true", help="consulta real a API do NVD (sem cache)")
    ap.add_argument("--cve", default="CVE-2024-3400")
    ap.add_argument("--no-tex", action="store_true")
    ap.add_argument("--from-evidence", action="store_true",
                    help="so regenera os .tex a partir de evidence_v7/lifecycle.json (mantem a medicao anterior)")
    a = ap.parse_args()
    if a.from_evidence:
        with open(os.path.join(v7.EVID, "lifecycle.json"), encoding="utf-8") as f:
            write_tex(json.load(f))
        print("artigo/numbers_lifecycle.tex e artigo/tab_lifecycle.tex regenerados de evidence_v7/lifecycle.json")
        return
    res = {"env": v7.env_info(), "generated": time.strftime("%Y-%m-%dT%H:%M:%S")}
    with contextlib.redirect_stdout(io.StringIO()):
        gA = v7.base_graph()
        rA, igA = reasoning(gA, shapes="v7")
        res["A_base"] = {"structure": structure(gA), "reasoning": rA, "cq": cq_base(igA), "loocv_acc1": loocv_base(igA)}
        gB = kb.load("real")
        rB, _ = reasoning(gB)
        res["B_real"] = {"structure": structure(gB), "reasoning": rB}
        from ontoevo.evogate import competency
        cq, _ = competency(None)
        res["regression_cq"] = "%d/%d" % (cq["passed"], cq["total"])
        res["open_signals"] = len(signals.detect(gB, Catalogs()))
        gC, rt = realtime(a.cve, a.live)
        rC, _ = reasoning(gC)
        res["C_realtime"] = {"structure": structure(gC), "reasoning": rC}
        res["realtime"] = rt
    os.makedirs(v7.EVID, exist_ok=True)
    with open(os.path.join(v7.EVID, "lifecycle.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False, default=str)
    if not a.no_tex:
        write_tex(res)
    for k in ("A_base", "B_real", "C_realtime"):
        s, r = res[k]["structure"], res[k]["reasoning"]
        print("%-11s triplas=%-5d classes=%-3d prof=%d cat.fraqueza=%-2d incid=%-3d casos=%-3d CVE=%-3d CWE=%-3d "
              "HermiT=%s/%d SHACL=%s Pellet=%s %.1fs" % (k, s["triples"], s["classes"], s["max_depth"], s["weakness_categories"],
                                                       s["incidents"], s["cases"], s["cves"], s["cwes"], r["hermit_consistent"],
                                                       r["hermit_unsat"], r["shacl_conforms"], r["pellet_consistent"], r["pellet_seconds"]))
    print("A: CQ %s, Acc@1 %s | regressao CQ (base+evo): %s | sinais abertos em B: %d"
          % (res["A_base"]["cq"], res["A_base"]["loocv_acc1"], res["regression_cq"], res["open_signals"]))
    print("C:", json.dumps({k: res["realtime"][k] for k in ("nvd_mode", "nvd_fetch_seconds", "alert1", "alert2")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
