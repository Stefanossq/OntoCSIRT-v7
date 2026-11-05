#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ontocsirt_v7.py - processamento reproduzivel do OntoCSIRT v7 (Owlready2 + Pellet + rdflib + pySHACL).

Uso:
  python ontocsirt_v7.py all          # tudo abaixo, gera evidence_v7/ e numbers_v7.tex
  python ontocsirt_v7.py consistency  # HermiT (TBox, sem regras) + Pellet (TBox+ABox+SWRL) + SHACL
  python ontocsirt_v7.py scenario     # novo incidente IDOR: inferencias + recuperacao ranqueada
  python ontocsirt_v7.py cq           # questoes de competencia com respostas esperadas
  python ontocsirt_v7.py ruletests    # testes positivos/negativos de cada regra (fixtures)
  python ontocsirt_v7.py mutations    # injecao de defeitos: o raciocinador/SHACL tem de os detetar
  python ontocsirt_v7.py loocv        # avaliacao leave-one-out da recuperacao vs. baselines

Requisitos: Java 8+, rdflib>=7, owlready2 (testado com 0.25; compativel com 0.4x/0.5x), pyshacl.
Owlready2 nao le Turtle: o script converte o .ttl para RDF/XML com rdflib antes de carregar.
As regras SWRL vivem SO no .ttl (fonte unica); o script nao as redefine.
"""
import argparse
import logging
import contextlib
import hashlib
import io
import itertools
import json
import os
import platform
import sys
import tempfile
import time
from collections import Counter, defaultdict

import rdflib
from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS, XSD

import owlready2 as o2

logging.getLogger("rdflib").setLevel(logging.CRITICAL)  # silencia avisos de rdf:PlainLiteral vindos do Pellet
HERE = os.path.dirname(os.path.abspath(__file__))
TTL = os.path.join(HERE, "OntoCSIRT_v7.ttl")
SHAPES = os.path.join(HERE, "shapes_v7.ttl")
EVID = os.path.join(HERE, "evidence_v7")
OC = Namespace("http://www.semanticweb.org/ontocsirt#")
PFX = "PREFIX : <http://www.semanticweb.org/ontocsirt#>\nPREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\nPREFIX owl: <http://www.w3.org/2002/07/owl#>\n"
SWRL = "http://www.w3.org/2003/11/swrl#"

# Pesos da similaridade, fixados ANTES da avaliacao (ver artigo, Secao 4.4).
WEIGHTS = {"weakness": 0.35, "pattern": 0.15, "asset": 0.20, "attribute": 0.20, "actor": 0.10}

# ---------------------------------------------------------------- utilitarios


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def short(x):
    return str(x).split("#")[-1]


def save_json(name, data):
    os.makedirs(EVID, exist_ok=True)
    with open(os.path.join(EVID, name + ".json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def base_graph():
    g = Graph()
    g.parse(TTL, format="turtle")
    return g


def env_info():
    try:
        jv = os.popen("java -version 2>&1").read().strip().splitlines()
        jv = [l for l in jv if "version" in l][:1]
    except Exception:  # noqa: BLE001
        jv = []
    return {"python": platform.python_version(), "rdflib": rdflib.__version__, "owlready2": o2.VERSION,
            "java": jv[0] if jv else "n/d", "ttl": os.path.basename(TTL), "ttl_sha256": sha256(TTL)}


def run_pellet(graph):
    """Raciocina com Pellet (TBox+ABox+SWRL). Devolve (consistente, tempo_s, grafo_inferido_rdflib|None, onto, world)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".owl", delete=False)
    tmp.close()
    graph.serialize(tmp.name, format="xml", encoding="utf-8")  # Owlready2 nao le Turtle; RDF/XML e o formato nativo
    world = o2.World()
    onto = world.get_ontology("file://" + tmp.name).load(format="rdfxml")
    t0 = time.time()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            o2.sync_reasoner_pellet(world, infer_property_values=True, infer_data_property_values=True, debug=0)
    except o2.OwlReadyInconsistentOntologyError:
        os.unlink(tmp.name)
        return False, time.time() - t0, None, onto, world
    dt = time.time() - t0
    # Exporta o quadstore do Owlready2 (afirmado + inferido) em N-Triples e le linha a linha:
    # uma linha corrompida (o leitor da saida do Pellet no Owlready2 parte literais com virgulas)
    # e descartada e contada, sem perder as restantes.
    out = tmp.name + ".inferred.nt"
    world.save(out, format="ntriples")
    ig, bad = Graph(), 0
    with open(out, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                ig.parse(data=line, format="nt")
            except Exception:  # noqa: BLE001
                bad += 1
    ig.bad_lines = bad
    os.unlink(out)
    os.unlink(tmp.name)
    return True, dt, ig, onto, world


def strip_swrl(graph):
    """Copia sem as regras SWRL (HermiT nao processa builtins SWRL)."""
    g = Graph()
    swrl_nodes = set()
    for s, p, o in graph:
        if str(p).startswith(SWRL) or (p == RDF.type and str(o).startswith(SWRL)):
            swrl_nodes.add(s)
    for s, p, o in graph:
        if s in swrl_nodes or str(p).startswith(SWRL):
            continue
        if p == RDF.type and str(o).startswith(SWRL):
            continue
        g.add((s, p, o))
    # remove listas RDF orfas usadas pelas regras (cada passagem apaga a cabeca de uma lista sem dono;
    # repete ate nao sobrar nenhuma). O segundo laco que existia aqui nao removia nada e foi retirado.
    changed = True
    while changed:
        changed = False
        for s in list(g.subjects(RDF.first, None)):
            if (None, None, s) not in g:
                for t in list(g.triples((s, None, None))):
                    g.remove(t)
                changed = True
    return g


def run_hermit(graph):
    """HermiT via Owlready2 (classificacao da TBox e consistencia, sem regras)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".owl", delete=False)
    tmp.close()
    strip_swrl(graph).serialize(tmp.name, format="xml", encoding="utf-8")
    world = o2.World()
    onto = world.get_ontology("file://" + tmp.name).load(format="rdfxml")
    t0 = time.time()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            o2.sync_reasoner_hermit(world, debug=0)
        consistent = True
    except o2.OwlReadyInconsistentOntologyError:
        consistent = False
    unsat = [c.name for c in world.inconsistent_classes()] if consistent else []
    os.unlink(tmp.name)
    return consistent, time.time() - t0, unsat


def run_shacl(graph):
    from pyshacl import validate
    sh = Graph()
    sh.parse(SHAPES, format="turtle")
    conforms, rg, txt = validate(graph, shacl_graph=sh, inference="rdfs", abort_on_first=False)
    msgs = sorted({str(o) for o in rg.objects(None, URIRef("http://www.w3.org/ns/shacl#resultMessage"))})
    n = len(list(rg.subjects(RDF.type, URIRef("http://www.w3.org/ns/shacl#ValidationResult"))))
    return bool(conforms), n, msgs


def q(graph, query):
    return [tuple(short(x) if isinstance(x, URIRef) else (str(x) if x is not None else None) for x in row)
            for row in graph.query(PFX + query)]


def metrics(graph):
    def n(qs):
        return int(list(graph.query(PFX + qs))[0][0])
    return {
        "triples": len(graph),
        "classes": n("SELECT (COUNT(DISTINCT ?c) AS ?n) WHERE { ?c a owl:Class . FILTER(isIRI(?c)) }"),
        "object_properties": n("SELECT (COUNT(DISTINCT ?p) AS ?n) WHERE { ?p a owl:ObjectProperty }"),
        "data_properties": n("SELECT (COUNT(DISTINCT ?p) AS ?n) WHERE { ?p a owl:DatatypeProperty }"),
        "annotation_properties": n("SELECT (COUNT(DISTINCT ?p) AS ?n) WHERE { ?p a owl:AnnotationProperty }"),
        "individuals": n("SELECT (COUNT(DISTINCT ?i) AS ?n) WHERE { ?i a ?c . ?c a owl:Class . FILTER(isIRI(?i) && isIRI(?c)) }"),
        "incidents": n("SELECT (COUNT(DISTINCT ?i) AS ?n) WHERE { ?i a :Incident }"),
        "cases": n("SELECT (COUNT(DISTINCT ?i) AS ?n) WHERE { ?i a :Case }"),
        "swrl_rules": n("SELECT (COUNT(DISTINCT ?r) AS ?n) WHERE { ?r a <http://www.w3.org/2003/11/swrl#Imp> }"),
        "disjoint_axioms": n("SELECT (COUNT(*) AS ?n) WHERE { ?x a owl:AllDisjointClasses }"),
        "defined_classes": n("SELECT (COUNT(DISTINCT ?c) AS ?n) WHERE { ?c owl:equivalentClass ?d . FILTER(isIRI(?c)) }"),
    }

# --------------------------------------------------------------- consistencia


def cmd_consistency():
    g = base_graph()
    ok_h, t_h, unsat = run_hermit(g)
    ok_p, t_p, ig, _, _ = run_pellet(g)
    conf, nviol, msgs = run_shacl(g)
    res = {"env": env_info(), "metrics": metrics(g), "hermit_consistent": ok_h, "hermit_seconds": round(t_h, 2),
           "hermit_unsatisfiable_classes": unsat, "pellet_consistent": ok_p, "pellet_seconds": round(t_p, 2),
           "pellet_inferred_triples": (len(ig) - len(g)) if ig is not None else None,
           "shacl_conforms": conf, "shacl_violations": nviol, "shacl_messages": msgs}
    save_json("consistency", res)
    print(json.dumps({k: v for k, v in res.items() if k != "env"}, indent=1, ensure_ascii=False))
    return res, ig

# ----------------------------------------------------------------- cenario


SCENARIO = [
    (OC.Act_New, RDF.type, OC.ThreatAction), (OC.Act_New, OC.instantiatesPattern, OC.AP_IDOR),
    (OC.Act_New, OC.exploits, OC.Vuln_CVE_2023_2065),
    (OC.Incident_New, RDF.type, OC.Incident), (OC.Incident_New, RDFS.label, Literal("Novo incidente: IDOR na Base de dados 1")),
    (OC.Incident_New, OC.hasActor, OC.Actor_FIN_A), (OC.Incident_New, OC.hasAction, OC.Act_New),
    (OC.Incident_New, OC.hasAsset, OC.Asset_Database_1), (OC.Incident_New, OC.hasAttribute, OC.State_Confidentiality),
    (OC.Incident_New, OC.involvesVulnerability, OC.Vuln_CVE_2023_2065), (OC.Incident_New, OC.detectedBy, OC.Detector_IDS_1),
]


def add_scenario(g):
    for t in SCENARIO:
        g.add(t)
    for i in g.subjects(RDF.type, OC.Incident):
        if i != OC.Incident_New:
            g.add((OC.Incident_New, OWL.differentFrom, i))
    return g


# Consulta original do artigo (mantida como referencia e para quem a importa). As features usadas
# pelo CBR vem agora de features(), que le a hierarquia do grafo (ontotax) em vez de VALUES fixos:
# com subclasses de 2.o nivel esta consulta devolve zero linhas para o incidente (ver tests/test_taxonomy.py).
FEATURE_Q = """SELECT ?i ?cwe ?cat ?ap ?asset ?atype ?attr ?actor ?acat ?sol WHERE {
  ?i a :Incident ; :involvesVulnerability ?v ; :hasAction ?act ; :hasAsset ?asset ; :hasAttribute ?attr ; :hasActor ?actor .
  ?v :hasWeakness ?cwe . ?cwe a ?cat . ?cat rdfs:subClassOf :Weakness . FILTER(?cat != :Weakness)
  ?act :instantiatesPattern ?ap .
  ?asset a ?atype . VALUES ?atype { :Server :Database :Gateway :Workstation }
  ?actor a ?acat . VALUES ?acat { :ExternalActor :InternalActor :PartnerActor }
  OPTIONAL { ?c :hasProblem ?i ; :hasSolution ?sol } }"""


# Varios casos para o mesmo incidente: a solucao principal segue a proveniencia (desfecho registado
# por analista > rotulo de fonte/politica > hipotese adaptada pelo Gemini). Os casos do artigo nao
# declaram proveniencia: sao registos historicos (nivel 0).
_PROV_RANK = {None: 0, "analyst:retain": 0, "kev:requiredAction": 1, "policy:cwe-category-v1": 1,
              "llm:case-analysis-v1": 2}


def features(ig):
    """Features de recuperacao por incidente, lidas da hierarquia do grafo (ontotax).

    Equivale ao FEATURE_Q do artigo quando a hierarquia tem 2 niveis, mas:
      - a categoria da CWE, o tipo de ativo e a categoria do ator sao o tipo MAIS ESPECIFICO sob
        :Weakness/:Asset/:ThreatActor (qualquer profundidade), ignorando classes derivadas por SWRL;
      - incidentes com varios valores (2 vulnerabilidades, 2 atributos...) guardam conjuntos e o valor
        principal e escolhido de forma deterministica (antes valia a ultima linha da consulta);
      - com varios casos para o mesmo incidente, "sol" segue _PROV_RANK e "sols" guarda todas;
      - "tax" guarda {antepassado: profundidade} de cada tipo, usado pela similaridade de Wu-Palmer.
    Um incidente so entra se tiver os cinco eixos (mesma juncao interna do FEATURE_Q)."""
    import ontotax
    tax = ontotax.Taxonomy(ig)
    roots = ontotax.FACETS
    sols = defaultdict(set)
    for c in ig.subjects(RDF.type, OC.Case):
        prov = ig.value(c, OC.solutionProvenance)
        rank = _PROV_RANK.get(str(prov) if prov is not None else None, 3)
        for i in ig.objects(c, OC.hasProblem):
            sols[i] |= {(rank, s) for s in ig.objects(c, OC.hasSolution)}
    out = {}
    for i in sorted(set(ig.subjects(RDF.type, OC.Incident)), key=str):
        vulns = set(ig.objects(i, OC.involvesVulnerability))
        cwes = sorted({w for v in vulns for w in ig.objects(v, OC.hasWeakness)}, key=str)
        aps = sorted({p for a in ig.objects(i, OC.hasAction) for p in ig.objects(a, OC.instantiatesPattern)}, key=str)
        assets = sorted(set(ig.objects(i, OC.hasAsset)), key=str)
        attrs = sorted(set(ig.objects(i, OC.hasAttribute)), key=str)
        actors = sorted(set(ig.objects(i, OC.hasActor)), key=str)
        cats = sorted({c for w in cwes for c in tax.classify(w, roots["weakness"], fallback_root=False)}, key=str)
        atypes = sorted({c for a in assets for c in tax.classify(a, roots["asset"])}, key=str)
        acats = sorted({c for a in actors for c in tax.classify(a, roots["actor"])}, key=str)
        apcls = sorted({c for p in aps for c in tax.classify(p, roots["pattern"])}, key=str)
        if not (cwes and cats and aps and assets and atypes and attrs and actors and acats):
            continue
        sol = [s for _, s in sorted(sols.get(i, ()), key=lambda rs: (rs[0], str(rs[1])))]
        S = lambda xs: [short(x) for x in xs]  # noqa: E731
        out[short(i)] = dict(
            cwe=short(cwes[0]), cat=short(cats[0]), ap=short(aps[0]), asset=short(assets[0]), atype=short(atypes[0]),
            attr=short(attrs[0]), actor=short(actors[0]), acat=short(acats[0]), sol=short(sol[0]) if sol else None,
            cwes=S(cwes), cats=S(cats), aps=S(aps), assets=S(assets), atypes=S(atypes), attrs=S(attrs),
            actors=S(actors), acats=S(acats), apcls=S(apcls), sols=S(sol),
            tax={"cat": {short(c): {short(a): d for a, d in tax.depth_map(c, roots["weakness"]).items()} for c in cats},
                 "atype": {short(c): {short(a): d for a, d in tax.depth_map(c, roots["asset"]).items()} for c in atypes},
                 "acat": {short(c): {short(a): d for a, d in tax.depth_map(c, roots["actor"]).items()} for c in acats},
                 "apcls": {short(c): {short(a): d for a, d in tax.depth_map(c, roots["pattern"]).items()} for c in apcls}})
    return out


def _vals(f, key, single):
    return f.get(key) or [f[single]]


_FACET_LIST = {"cat": "cats", "atype": "atypes", "acat": "acats", "apcls": "apcls"}


def _tax_sim(a, b, key):
    """Maior Wu-Palmer entre os tipos de a e b na faceta key. Features sem "tax" (formato do artigo,
    um valor por eixo) caem na igualdade simples: 1 se a mesma categoria, 0 caso contrario."""
    import ontotax
    va = a.get(_FACET_LIST[key]) or ([a[key]] if key in a else [])
    vb = b.get(_FACET_LIST[key]) or ([b[key]] if key in b else [])
    ta, tb = a.get("tax", {}).get(key), b.get("tax", {}).get(key)
    if ta is None or tb is None:
        return 1.0 if key != "apcls" and set(va) & set(vb) else 0.0
    return max((ontotax.wu_palmer(ta.get(x, {}), tb.get(y, {}), x, y) for x in va for y in vb), default=0.0)


def sim(a, b, w=WEIGHTS):
    """Similaridade ponderada do v7 (pesos a priori). Com a hierarquia de 2 niveis do artigo os valores
    sao identicos aos originais: o credito parcial "mesma categoria" passa a ser Wu-Palmer na faceta,
    que vale 1 para a mesma categoria e 0 para categorias irmas. Com conjuntos (varios valores por
    incidente) conta a melhor correspondencia."""
    s_w = 1.0 if set(_vals(a, "cwes", "cwe")) & set(_vals(b, "cwes", "cwe")) else 0.5 * _tax_sim(a, b, "cat")
    s_p = 1.0 if set(_vals(a, "aps", "ap")) & set(_vals(b, "aps", "ap")) else 0.5 * _tax_sim(a, b, "apcls")
    s_as = 1.0 if set(_vals(a, "assets", "asset")) & set(_vals(b, "assets", "asset")) else 0.7 * _tax_sim(a, b, "atype")
    s_at = 1.0 if set(_vals(a, "attrs", "attr")) & set(_vals(b, "attrs", "attr")) else 0.0
    s_ac = 1.0 if set(_vals(a, "actors", "actor")) & set(_vals(b, "actors", "actor")) else 0.5 * _tax_sim(a, b, "acat")
    return round(w["weakness"] * s_w + w["pattern"] * s_p + w["asset"] * s_as + w["attribute"] * s_at + w["actor"] * s_ac, 4)


def cmd_scenario():
    g = add_scenario(base_graph())
    ok, dt, ig, _, _ = run_pellet(g)
    assert ok, "cenario inconsistente"
    new = "Incident_New"
    inf = {
        "risk": q(ig, "SELECT ?r WHERE { :Incident_New :hasRiskLevel ?r }"),
        "classes": sorted({r[0] for r in q(ig, "SELECT ?c WHERE { :Incident_New a ?c . FILTER(isIRI(?c)) }")}
                          - {"Thing", "NamedIndividual"}),
        "sharesWeaknessWith": sorted(r[0] for r in q(ig, "SELECT ?j WHERE { :Incident_New :sharesWeaknessWith ?j }")),
        "sharesActorWith": sorted(r[0] for r in q(ig, "SELECT ?j WHERE { :Incident_New :sharesActorWith ?j }")),
        "candidateSolution": sorted(r[0] for r in q(ig, "SELECT ?s WHERE { :Incident_New :candidateSolution ?s }")),
    }
    F = features(ig)
    qf = F.pop(new)
    v6 = sorted(i for i, f in F.items() if f["acat"] == qf["acat"] or f["cwe"] == qf["cwe"])
    ranked = sorted(((sim(qf, f), i, f["sol"]) for i, f in F.items()), key=lambda x: (-x[0], x[1]))[:5]
    vote = Counter(s for _, _, s in ranked[:3]).most_common()
    res = {"env": env_info(), "pellet_seconds": round(dt, 2), "inferences": inf,
           "v6_style_join": {"cases": v6, "solutions": dict(Counter(F[i]["sol"] for i in v6))},
           "v7_top5": [{"score": s, "incident": i, "solution": sol} for s, i, sol in ranked],
           "v7_vote_top3": vote, "policy_expected_solution": "CoA_AccessControlFix"}
    save_json("scenario", res)
    print(json.dumps({k: v for k, v in res.items() if k != "env"}, indent=1, ensure_ascii=False))
    return res

# ---------------------------------------------------------- questoes de competencia


CQS = [
    ("CQ1", "Quais incidentes tem risco Critical (inferido pela R1a)?",
     "SELECT ?i WHERE { ?i a :Incident ; :hasRiskLevel ?r . FILTER(STR(?r) = \"Critical\") }",
     {"Incident_01", "Incident_02", "Incident_04", "Incident_06", "Incident_08", "Incident_11", "Incident_18", "Incident_21", "Incident_22"}),
    ("CQ2", "Quais ativos tem incidentes criticos recorrentes (R3)?",
     "SELECT ?a WHERE { ?a a :RecurrentlyCriticalAsset }",
     {"Asset_Server_1", "Asset_Server_2", "Asset_Gateway_1"}),
    ("CQ3", "Que incidentes partilham a fraqueza do Incident_03 (R5)?",
     "SELECT ?j WHERE { :Incident_03 :sharesWeaknessWith ?j }", {"Incident_17", "Incident_24"}),
    ("CQ4", "Que solucoes candidatas a regra R6 propoe para o Incident_03?",
     "SELECT ?s WHERE { :Incident_03 :candidateSolution ?s }", {"CoA_AccessControlFix", "CoA_Isolate"}),
    ("CQ5", "Que incidentes com risco a confidencialidade (classe definida) envolvem ator interno?",
     "SELECT ?i WHERE { ?i a :ConfidentialityAtRisk ; :hasActor ?a . ?a a :InternalActor }",
     {"Incident_09", "Incident_17", "Incident_21"}),
    ("CQ6", "Que incidentes envolvem fraqueza de controle de acesso?",
     "SELECT ?i WHERE { ?i :involvesVulnerability/:hasWeakness ?w . ?w a :AccessControlWeakness }",
     {"Incident_03", "Incident_09", "Incident_17", "Incident_20", "Incident_24"}),
    ("CQ7", "Que incidentes de injecao no servidor afetaram a confidencialidade?",
     "SELECT ?i WHERE { ?i a :ConfidentialityAtRisk ; :involvesVulnerability/:hasWeakness ?w . ?w a :InjectionWeakness }",
     {"Incident_01", "Incident_04", "Incident_07", "Incident_22"}),
    ("CQ8", "Que vulnerabilidades com CVE ainda nao foram verificadas contra o NVD?",
     "SELECT ?v WHERE { ?v :cveId ?id ; :verificationNote ?n . FILTER(CONTAINS(?n, \"Pendente\")) }",
     {"Vuln_CVE_2023_34362", "Vuln_CVE_2020_11022", "Vuln_CVE_2021_26855"}),
]


def cmd_cq(ig=None):
    if ig is None:
        ok, _, ig, _, _ = run_pellet(base_graph())
    out, passed = [], 0
    for cid, text, sparql, expected in CQS:
        got = {r[0] for r in q(ig, sparql)}
        ok = got == expected
        passed += ok
        out.append({"id": cid, "question": text, "sparql": sparql, "expected": sorted(expected), "got": sorted(got),
                    "pass": ok, "missing": sorted(expected - got), "unexpected": sorted(got - expected)})
        print("%s %s  esperado=%d obtido=%d" % (cid, "PASSOU" if ok else "FALHOU", len(expected), len(got)))
    res = {"passed": passed, "total": len(CQS), "cqs": out}
    save_json("cq", res)
    return res

# ------------------------------------------------------------- testes de regras


def fixture(score_by_id, extra=()):
    """Ontologia so com a TBox + regras e incidentes de teste (cada um com uma vulnerabilidade)."""
    g = base_graph()
    abox = set()
    for s in set(g.subjects(RDF.type, None)):
        for c in g.objects(s, RDF.type):
            if c in (OC.Incident, OC.Case, OC.ThreatAction, OC.Vulnerability):
                abox.add(s)
    for s in abox:
        for t in list(g.triples((s, None, None))):
            g.remove(t)
    for node in list(g.subjects(RDF.type, OWL.AllDifferent)):
        for t in list(g.triples((node, None, None))):
            g.remove(t)
    tests = []
    for tid, score in score_by_id.items():
        inc, vul = OC["T_" + tid], OC["TV_" + tid]
        g.add((inc, RDF.type, OC.Incident))
        g.add((inc, OC.involvesVulnerability, vul))
        g.add((vul, RDF.type, OC.Vulnerability))
        g.add((vul, OC.cvssBaseScore, Literal(str(score), datatype=XSD.decimal)))
        tests.append(inc)
    for t in extra:
        g.add(t)
    return g


def cmd_ruletests():
    cases = []
    # R1: fronteiras das faixas
    bands = {"b100": ("10.0", "Critical"), "b90": ("9.0", "Critical"), "b89": ("8.9", "High"), "b70": ("7.0", "High"),
             "b69": ("6.9", "Medium"), "b40": ("4.0", "Medium"), "b39": ("3.9", "Low"), "b01": ("0.1", "Low")}
    ok, _, ig, _, _ = run_pellet(fixture({k: v[0] for k, v in bands.items()}))
    for k, (score, exp) in bands.items():
        got = sorted(r[0] for r in q(ig, "SELECT ?r WHERE { :T_%s :hasRiskLevel ?r }" % k))
        cases.append({"rule": "R1", "test": "CVSS %s -> %s" % (score, exp), "expected": [exp], "got": got, "pass": got == [exp]})
    # R3/R4/R5/R6: fixture minimo
    X = OC
    ext = [
        (X.TA1, RDF.type, X.Server), (X.TA2, RDF.type, X.Server),
        (X.TW1, RDF.type, X.InjectionWeakness), (X.TW1, X.cweId, Literal("CWE-89")),
        (X.TW2, RDF.type, X.WebClientWeakness), (X.TW2, X.cweId, Literal("CWE-79")),
        (X.TV_p1, X.hasWeakness, X.TW1), (X.TV_p2, X.hasWeakness, X.TW1), (X.TV_n1, X.hasWeakness, X.TW2),
        (X.TV_c1, X.hasWeakness, X.TW2),
        (X.T_p1, X.hasAsset, X.TA1), (X.T_p2, X.hasAsset, X.TA1), (X.T_n1, X.hasAsset, X.TA2), (X.T_c1, X.hasAsset, X.TA2),
        (X.TACT1, RDF.type, X.ExternalActor), (X.TACT2, RDF.type, X.ExternalActor),
        (X.T_p1, X.hasActor, X.TACT1), (X.T_p2, X.hasActor, X.TACT1), (X.T_n1, X.hasActor, X.TACT2), (X.T_c1, X.hasActor, X.TACT2),
        (X.TC1, RDF.type, X.Case), (X.TC1, X.hasProblem, X.T_p2), (X.TC1, X.hasSolution, X.CoA_Patch),
    ]
    g = fixture({"p1": "9.8", "p2": "9.1", "n1": "9.5", "c1": "5.0"}, ext)
    members = [X.T_p1, X.T_p2, X.T_n1, X.T_c1]
    for a, b in itertools.combinations(members, 2):
        g.add((a, OWL.differentFrom, b))
    ok, _, ig, _, _ = run_pellet(g)

    def has(qs):  # ASK: "SELECT *" sem variaveis devolve zero linhas no rdflib
        return bool(ig.query(PFX + qs.replace("SELECT * WHERE", "ASK WHERE").replace("SELECT ?s WHERE", "ASK WHERE")).askAnswer)
    checks = [
        ("R3", "dois incidentes criticos distintos no mesmo ativo -> RecurrentlyCriticalAsset", has("SELECT * WHERE { :TA1 a :RecurrentlyCriticalAsset }"), True),
        ("R3", "um critico + um medio no mesmo ativo -> nao recorrente", has("SELECT * WHERE { :TA2 a :RecurrentlyCriticalAsset }"), False),
        ("R4", "mesmo ator concreto -> sharesActorWith", has("SELECT * WHERE { :T_p1 :sharesActorWith :T_p2 }"), True),
        ("R4", "atores distintos da mesma categoria VERIS -> sem sharesActorWith", has("SELECT * WHERE { :T_p1 :sharesActorWith :T_n1 }"), False),
        ("R4", "simetria declarada em OWL", has("SELECT * WHERE { :T_p2 :sharesActorWith :T_p1 }"), True),
        ("R5", "mesma CWE -> sharesWeaknessWith", has("SELECT * WHERE { :T_p1 :sharesWeaknessWith :T_p2 }"), True),
        ("R5", "CWE diferentes -> sem sharesWeaknessWith", has("SELECT * WHERE { :T_p1 :sharesWeaknessWith :T_n1 }"), False),
        ("R5", "incidente nao partilha fraqueza consigo proprio", has("SELECT * WHERE { :T_p1 :sharesWeaknessWith :T_p1 }"), False),
        ("R6", "fraqueza partilhada com problema de caso -> candidateSolution", has("SELECT * WHERE { :T_p1 :candidateSolution :CoA_Patch }"), True),
        ("R6", "sem fraqueza partilhada -> sem candidateSolution", has("SELECT * WHERE { :T_n1 :candidateSolution ?s }"), False),
        ("DL", "risco Critical inferido -> CriticalRiskIncident (classe definida)", has("SELECT * WHERE { :T_p1 a :CriticalRiskIncident }"), True),
        ("DL", "risco Medium -> nao CriticalRiskIncident", has("SELECT * WHERE { :T_c1 a :CriticalRiskIncident }"), False),
    ]
    for rule, text, got, exp in checks:
        cases.append({"rule": rule, "test": text, "expected": exp, "got": got, "pass": got == exp})
    passed = sum(c["pass"] for c in cases)
    for c in cases:
        print("%-3s %-6s %s" % (c["rule"], "PASSOU" if c["pass"] else "FALHOU", c["test"]))
    res = {"passed": passed, "total": len(cases), "cases": cases}
    save_json("ruletests", res)
    return res

# --------------------------------------------------------------------- mutacoes


def cmd_mutations():
    X = OC
    mutants = [
        ("M1", "Vulnerabilidade tipada tambem como padrao de ataque (disjuncao)", [(X.Vuln_L01, RDF.type, X.AttackPattern)], [], "owl"),
        ("M2", "Ator externo e interno ao mesmo tempo (disjuncao VERIS)", [(X.Actor_FIN_A, RDF.type, X.InternalActor)], [], "owl"),
        ("M3", "Ativo servidor e base de dados ao mesmo tempo", [(X.Asset_Server_1, RDF.type, X.Database)], [], "owl"),
        ("M4", "Segundo CVSS para a mesma vulnerabilidade (propriedade funcional)",
         [(X.Vuln_L01, X.cvssBaseScore, Literal("5.0", datatype=XSD.decimal))], [], "owl"),
        ("M5", "CVSS como texto em vez de decimal", [(X.Vuln_L02, X.cvssBaseScore, Literal("9.1"))],
         [(X.Vuln_L02, X.cvssBaseScore, Literal("9.1", datatype=XSD.decimal))], "any"),
        ("M6", "Incidente sem ator (VERIS A4 incompleto)", [], [(X.Incident_05, X.hasActor, X.Actor_UNK_E)], "shacl"),
        ("M7", "Caso sem solucao registada", [], [(X.Case_07, X.hasSolution, X.CoA_Isolate)], "shacl"),
        ("M8", "Nivel de risco fora do vocabulario", [(X.Incident_05, X.hasRiskLevel, Literal("Severe"))], [], "shacl"),
        ("M9", "CVSS fora do intervalo [0,10]", [(X.Vuln_L13, X.cvssBaseScore, Literal("12.0", datatype=XSD.decimal))],
         [(X.Vuln_L13, X.cvssBaseScore, Literal("3.5", datatype=XSD.decimal))], "shacl"),
        ("M10", "Identificador CVE mal formado", [(X.Vuln_L03, X.cveId, Literal("CVE-23-1"))], [], "shacl"),
    ]
    out = []
    for mid, text, add, remove, expect in mutants:
        g = base_graph()
        for t in remove:
            g.remove(t)
        for t in add:
            g.add(t)
        ok, _, _, _, _ = run_pellet(g)
        conf, nviol, msgs = run_shacl(g)
        detected_owl, detected_shacl = (not ok), (not conf)
        detected = detected_owl or detected_shacl
        out.append({"id": mid, "defect": text, "expected_detector": expect, "pellet_inconsistent": detected_owl,
                    "shacl_violation": detected_shacl, "shacl_messages": msgs, "detected": detected})
        print("%-4s %-9s owl=%s shacl=%s  %s" % (mid, "DETETADO" if detected else "NAO", detected_owl, detected_shacl, text))
    res = {"detected": sum(m["detected"] for m in out), "total": len(out),
           "by_owl": sum(m["pellet_inconsistent"] for m in out), "by_shacl": sum(m["shacl_violation"] for m in out),
           "mutants": out}
    save_json("mutations", res)
    return res

# ------------------------------------------------------------------------ LOOCV


def expected_topk(scored, relevant, k):
    """Precisao esperada no top-k com desempate aleatorio entre pontuacoes iguais."""
    groups = defaultdict(list)
    for s, i in scored:
        groups[s].append(i)
    taken, exp_rel = 0, 0.0
    for s in sorted(groups, reverse=True):
        grp = groups[s]
        rel = sum(1 for i in grp if i in relevant)
        if taken + len(grp) <= k:
            exp_rel += rel
            taken += len(grp)
        else:
            exp_rel += rel * (k - taken) / len(grp)
            taken = k
        if taken >= k:
            break
    return exp_rel / k


def cmd_loocv(ig=None):
    if ig is None:
        ok, _, ig, _, _ = run_pellet(base_graph())
    F = features(ig)
    shares_w = defaultdict(set)
    for a, b in q(ig, "SELECT ?a ?b WHERE { ?a :sharesWeaknessWith ?b }"):
        shares_w[a].add(b)
    ids = sorted(F)
    sol_count = Counter(F[i]["sol"] for i in ids)
    eq_w = {k: 0.2 for k in WEIGHTS}
    strategies = {
        "majority": "classe majoritaria (sempre a solucao mais frequente)",
        "v6_join": "juncao do v6: mesma categoria de ator OU mesma CWE, sem ranking",
        "actor": "so mesmo ator concreto (R4), sem ranking",
        "rule_R6": "so mesma CWE via regra R5/R6, sem ranking",
        "v7_eq": "similaridade v7 com pesos iguais",
        "v7": "similaridade v7 com pesos definidos a priori",
    }
    rows = {k: {"acc1": [], "p3": [], "covered": []} for k in strategies}
    per_query = []
    for qi in ids:
        qf = F[qi]
        others = [i for i in ids if i != qi]
        relevant = {i for i in others if F[i]["sol"] == qf["sol"]}
        majority = Counter(F[i]["sol"] for i in others).most_common(1)[0][0]
        cand_sets = {
            "v6_join": [i for i in others if F[i]["acat"] == qf["acat"] or F[i]["cwe"] == qf["cwe"]],
            "actor": [i for i in others if F[i]["actor"] == qf["actor"]],
            "rule_R6": sorted(shares_w[qi]),
        }
        rec = {"query": qi, "true_solution": qf["sol"], "n_relevant": len(relevant)}
        # majority
        rows["majority"]["acc1"].append(1.0 if majority == qf["sol"] else 0.0)
        rows["majority"]["p3"].append(1.0 if majority == qf["sol"] else 0.0)
        rows["majority"]["covered"].append(1.0)
        for name, cands in cand_sets.items():
            if not cands:
                rows[name]["acc1"].append(0.0)
                rows[name]["p3"].append(0.0)
                rows[name]["covered"].append(0.0)
                continue
            scored = [(1.0, i) for i in cands]
            rows[name]["acc1"].append(expected_topk(scored, relevant, 1))
            rows[name]["p3"].append(expected_topk(scored, relevant, 3))
            rows[name]["covered"].append(1.0)
        for name, w in (("v7", WEIGHTS), ("v7_eq", eq_w)):
            scored = [(sim(qf, F[i], w), i) for i in others]
            rows[name]["acc1"].append(expected_topk(scored, relevant, 1))
            rows[name]["p3"].append(expected_topk(scored, relevant, 3))
            rows[name]["covered"].append(1.0)
            if name == "v7":
                top = sorted(scored, key=lambda x: (-x[0], x[1]))[:3]
                rec["v7_top3"] = [(i, s, F[i]["sol"]) for s, i in top]
        per_query.append(rec)
    summary = {}
    for name in strategies:
        r = rows[name]
        n = len(r["acc1"])
        summary[name] = {"description": strategies[name], "acc1": round(sum(r["acc1"]) / n, 3),
                         "p3": round(sum(r["p3"]) / n, 3), "coverage": round(sum(r["covered"]) / n, 3)}
    # sensibilidade: retirar um componente de cada vez (ablacao)
    ablation = {}
    for comp in WEIGHTS:
        w = dict(WEIGHTS)
        w[comp] = 0.0
        acc = []
        for qi in ids:
            others = [i for i in ids if i != qi]
            relevant = {i for i in others if F[i]["sol"] == F[qi]["sol"]}
            acc.append(expected_topk([(sim(F[qi], F[i], w), i) for i in others], relevant, 1))
        ablation[comp] = round(sum(acc) / len(acc), 3)
    res = {"n_queries": len(ids), "solution_distribution": dict(sol_count), "weights": WEIGHTS,
           "summary": summary, "ablation_acc1_without": ablation, "per_query": per_query,
           "relevance": "caso relevante = mesma solucao registada (a solucao nao entra na similaridade)",
           "exceptions": ["Incident_01", "Incident_03", "Incident_24"]}
    save_json("loocv", res)
    for name, s in summary.items():
        print("%-9s acc@1=%.3f p@3=%.3f cobertura=%.2f" % (name, s["acc1"], s["p3"], s["coverage"]))
    print("ablacao (acc@1 sem o componente):", ablation)
    return res

# -------------------------------------------------------------------- relatorio


def tex(s):
    return str(s).replace("_", "\\_").replace("%", "\\%").replace("&", "\\&")


def write_numbers(cons, scen, cq, rt, mut, lo):
    m = cons["metrics"]
    N = {
        "vSevenHash": cons["env"]["ttl_sha256"][:12], "vSevenTriples": m["triples"], "vSevenClasses": m["classes"],
        "vSevenObjProps": m["object_properties"], "vSevenDataProps": m["data_properties"],
        "vSevenAnnProps": m["annotation_properties"], "vSevenIndividuals": m["individuals"],
        "vSevenIncidents": m["incidents"], "vSevenCases": m["cases"], "vSevenRules": m["swrl_rules"],
        "vSevenDisjoint": m["disjoint_axioms"], "vSevenDefined": m["defined_classes"],
        "envOwlready": cons["env"]["owlready2"], "envRdflib": cons["env"]["rdflib"], "envPython": cons["env"]["python"],
        "hermitOK": "consistente" if cons["hermit_consistent"] else "INCONSISTENTE",
        "hermitUnsat": len(cons["hermit_unsatisfiable_classes"]), "hermitSec": cons["hermit_seconds"],
        "pelletOK": "consistente" if cons["pellet_consistent"] else "INCONSISTENTE", "pelletSec": cons["pellet_seconds"],
        "pelletInferred": cons["pellet_inferred_triples"],
        "shaclOK": "conforme" if cons["shacl_conforms"] else "n\\~ao conforme", "shaclViol": cons["shacl_violations"],
        "scenSec": scen["pellet_seconds"], "scenRisk": ", ".join(r[0] for r in scen["inferences"]["risk"]),
        "scenSharesW": len(scen["inferences"]["sharesWeaknessWith"]), "scenSharesA": len(scen["inferences"]["sharesActorWith"]),
        "scenVsixN": len(scen["v6_style_join"]["cases"]),
        "cqPassed": cq["passed"], "cqTotal": cq["total"], "rtPassed": rt["passed"], "rtTotal": rt["total"],
        "mutDetected": mut["detected"], "mutTotal": mut["total"], "mutOWL": mut["by_owl"], "mutSHACL": mut["by_shacl"],
        "looN": lo["n_queries"],
    }
    for k, v in lo["summary"].items():
        key = {"majority": "Maj", "v6_join": "Vsix", "actor": "Actor", "rule_R6": "Rule", "v7_eq": "Eq", "v7": "Vseven"}[k]
        N["acc" + key] = "%.2f" % v["acc1"]
        N["pthree" + key] = "%.2f" % v["p3"]
        N["cov" + key] = "%.2f" % v["coverage"]
    for comp, val in lo["ablation_acc1_without"].items():
        N["abl" + comp.capitalize()] = "%.2f" % val
    os.makedirs(os.path.join(HERE, "artigo"), exist_ok=True)
    with open(os.path.join(HERE, "artigo", "numbers_v7.tex"), "w", encoding="utf-8") as f:
        f.write("% Gerado por ontocsirt_v7.py - nao editar\n")
        for k, v in N.items():
            val = tex(v) if k not in ("shaclOK",) else v
            if k.startswith(("acc", "pthree", "cov", "abl")) or k.endswith("Sec"):
                val = val.replace(".", "{,}")  # separador decimal em portugues
            f.write("\\newcommand{\\%s}{%s}\n" % (k, val))
    # tabela do cenario
    with open(os.path.join(HERE, "artigo", "tab_scenario.tex"), "w", encoding="utf-8") as f:
        f.write("% Gerado por ontocsirt_v7.py\n\\begin{tabular}{@{}lcl@{}}\n\\toprule\nIncidente & $S(q,c)$ & Solu\\c{c}\\~ao registrada\\\\\n\\midrule\n")
        for r in scen["v7_top5"]:
            f.write("%s & %s & %s\\\\\n" % (tex(r["incident"]), ("%.2f" % r["score"]).replace(".", "{,}"), tex(r["solution"].replace("CoA_", ""))))
        f.write("\\bottomrule\n\\end{tabular}\n")


def cmd_all():
    os.makedirs(EVID, exist_ok=True)
    cons, ig = cmd_consistency()
    scen = cmd_scenario()
    cq = cmd_cq(ig)
    rt = cmd_ruletests()
    mut = cmd_mutations()
    lo = cmd_loocv(ig)
    write_numbers(cons, scen, cq, rt, mut, lo)
    summ = {"env": cons["env"], "consistency": {k: cons[k] for k in ("hermit_consistent", "pellet_consistent", "shacl_conforms")},
            "cq": "%d/%d" % (cq["passed"], cq["total"]), "ruletests": "%d/%d" % (rt["passed"], rt["total"]),
            "mutations": "%d/%d" % (mut["detected"], mut["total"]), "loocv": lo["summary"]}
    save_json("SUMMARY", summ)
    print("\n[ok] evidence_v7/*.json, artigo/numbers_v7.tex, artigo/tab_scenario.tex")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["all", "consistency", "scenario", "cq", "ruletests", "mutations", "loocv"])
    a = ap.parse_args()
    {"all": cmd_all, "consistency": cmd_consistency, "scenario": cmd_scenario, "cq": cmd_cq,
     "ruletests": cmd_ruletests, "mutations": cmd_mutations, "loocv": cmd_loocv}[a.cmd]()


if __name__ == "__main__":
    main()
