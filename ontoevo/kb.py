# -*- coding: utf-8 -*-
"""
kb.py - composicao da base de conhecimento e gravacao dos dados adquiridos.

Base = perfil + extensao + modulo de evolucao + dados adquiridos, com o AllDifferent dos incidentes
reconstruido sobre o conjunto final (R3-R6 precisam de owl:differentFrom).
  perfil "real": OntoCSIRT_v7_real.ttl (base gerada pelo ingest_real_cases.py; ja contem o v7)
  perfil "base": OntoCSIRT_v7.ttl (base do artigo)
Os ficheiros congelados (OntoCSIRT_v7.ttl) e a extensao nunca sao reescritos aqui. Os dados novos vao
para OntoCSIRT_v7_acquired.ttl e so depois de o grafo COMPOSTO passar no portao
(SHACL v7+ingestao+evo, HermiT, Pellet).
"""
import os
import shutil
import time

from rdflib import Graph
from rdflib.namespace import OWL, RDF

import ingest_real_cases as ing
import ontocsirt_v7 as v7
import validar_ingestao as val

OC = v7.OC
HERE = v7.HERE
REAL = os.path.join(HERE, "OntoCSIRT_v7_real.ttl")
ACQUIRED = os.path.join(HERE, "OntoCSIRT_v7_acquired.ttl")
BACKUPS = os.path.join(HERE, "evolution", "backups")
PROFILES = {"real": REAL, "base": v7.TTL}


def bind(g):
    g.bind("", OC)
    g.bind("evo", "http://www.semanticweb.org/ontocsirt/evo#")
    g.bind("dcterms", "http://purl.org/dc/terms/")
    return g


def acquired_graph(path=None):
    g = Graph()
    p = path or ACQUIRED
    if os.path.exists(p):
        g.parse(p, format="turtle")
    return bind(g)


def load(profile="real", include_acquired=True, acquired_path=None):
    """Grafo composto pronto para raciocinio (TBox completa + dados)."""
    if profile not in PROFILES:
        raise ValueError("perfil desconhecido: %s" % profile)
    g = Graph()
    g.parse(PROFILES[profile], format="turtle")
    g = val.with_tbox(g)                       # v7 + extensao atual + modulo de evolucao
    if include_acquired:
        for t in acquired_graph(acquired_path):
            g.add(t)
    rebuild_all_different(g)
    return bind(g)


def rebuild_all_different(g):
    ing.remove_all_different(g)
    return ing.add_all_different(g)


def backup(path, tag):
    if not os.path.exists(path):
        return None
    os.makedirs(BACKUPS, exist_ok=True)
    dst = os.path.join(BACKUPS, "%s.%s.%s" % (os.path.basename(path), time.strftime("%Y%m%d-%H%M%S"), tag))
    shutil.copy2(path, dst)
    return dst


def commit_acquired(new, profile="real", use_pellet=True, acquired_path=None, tag="acquire"):
    """Junta as triplas `new` aos dados adquiridos SE o grafo composto passar no portao.
    Devolve (codigo, relatorio); codigo 0 = gravado (mesmos codigos do validar_ingestao)."""
    full = load(profile, acquired_path=acquired_path)
    for t in new:
        full.add(t)
    rebuild_all_different(full)
    rep = val.validate(full, use_pellet=use_pellet, use_hermit=True)
    code = 0
    if not rep["conforms"]:
        code = 1
    elif not rep["hermit"]["consistent"] or (use_pellet and not rep["pellet"]["consistent"]):
        code = 2
    elif rep["hermit"]["unsatisfiable_classes"]:
        code = 4
    if code == 0:
        path = acquired_path or ACQUIRED
        rep["backup"] = backup(path, tag)
        acq = acquired_graph(path)
        for t in new:
            acq.add(t)
        _drop_all_different(acq)               # o AllDifferent e reconstruido na composicao
        acq.serialize(path, format="turtle")
        rep["written"] = path
    return code, rep


def _drop_all_different(g):
    for b in list(g.subjects(RDF.type, OWL.AllDifferent)):
        for t in list(g.triples((b, None, None))):
            g.remove(t)


def diff(after, before):
    """Triplas novas (sem os nos do AllDifferent, reconstruido na composicao)."""
    out = Graph()
    for t in after:
        if t not in before:
            out.add(t)
    _drop_all_different(out)
    # listas RDF orfas do AllDifferent reconstruido (repete ate nao sobrar cabeca sem dono)
    changed = True
    while changed:
        changed = False
        for s in list(out.subjects(RDF.first, None)):
            if (None, None, s) not in out:
                for t in list(out.triples((s, None, None))):
                    out.remove(t)
                changed = True
    return bind(out)
