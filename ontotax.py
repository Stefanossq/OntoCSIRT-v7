#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ontotax.py - leitura da hierarquia de classes do OntoCSIRT a partir do proprio grafo.

Substitui as listas fixas no codigo (VALUES { :Server :Database ... }, "subclasse DIRETA de :Weakness")
por consultas a hierarquia, para que classes criadas pela evolucao da ontologia (subclasses de 2.o nivel
ou mais) sejam usadas pelo CBR em vez de fazerem o incidente desaparecer da recuperacao.

Facetas taxonomicas usadas pela similaridade (raiz de cada arvore):
  weakness -> :Weakness   asset -> :Asset   actor -> :ThreatActor   pattern -> :AttackPattern
Classes derivadas (cabeca de regra SWRL, p.ex. RecurrentlyCriticalAsset) ou anotadas com
:cbrIgnore true nao sao "tipos" para a similaridade: descrevem um estado inferido, nao a natureza do no.

Similaridade de Wu-Palmer com a raiz da faceta em profundidade 0:
  wp(c1, c2) = 2*prof(LCS) / (prof(c1) + prof(c2)),  e 0 quando o unico antepassado comum e a raiz.
Numa hierarquia de 2 niveis (a do v7) wp e 1 para a mesma categoria e 0 para categorias diferentes,
isto e, a similaridade do artigo e um caso particular desta.
"""
import os
from collections import deque

from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS

OC = Namespace("http://www.semanticweb.org/ontocsirt#")
SWRL = Namespace("http://www.w3.org/2003/11/swrl#")
HERE = os.path.dirname(os.path.abspath(__file__))

FACETS = {"weakness": OC.Weakness, "asset": OC.Asset, "actor": OC.ThreatActor, "pattern": OC.AttackPattern}

_BASE_DERIVED = None


def swrl_head_classes(g):
    """Classes que aparecem como ClassAtom na cabeca de uma regra SWRL (estados inferidos)."""
    out = set()
    for head in g.objects(None, SWRL.head):
        node = head
        while node is not None and node != RDF.nil:
            atom = g.value(node, RDF.first)
            if atom is not None and (atom, RDF.type, SWRL.ClassAtom) in g:
                c = g.value(atom, SWRL.classPredicate)
                if isinstance(c, URIRef):
                    out.add(c)
            node = g.value(node, RDF.rest)
    return out


def _base_derived():
    """Cabecas SWRL do OntoCSIRT_v7.ttl (fonte unica das regras), para grafos que nao trazem as regras."""
    global _BASE_DERIVED
    if _BASE_DERIVED is None:
        g = Graph()
        g.parse(os.path.join(HERE, "OntoCSIRT_v7.ttl"), format="turtle")
        _BASE_DERIVED = frozenset(swrl_head_classes(g))
    return _BASE_DERIVED


class Taxonomy:
    """Hierarquia de classes nomeadas (rdfs:subClassOf entre IRIs) de um grafo.

    Classes EQUIVALENTES (owl:equivalentClass entre nomes, ou ciclos de subClassOf, que o Pellet exporta para
    cada equivalencia) sao colapsadas num so no do grafo-quociente, representado pela raiz de faceta quando ela
    e uma delas (p.ex. :CWE = :Weakness no modulo de bug bounty) e, senao, pelo menor IRI. Sem isto um alias da
    raiz parecia um nivel abaixo dela e duas categorias irmas ganhavam Wu-Palmer 1 em vez de 0."""

    def __init__(self, g):
        self.g = g
        raw = {}
        for c, p in g.subject_objects(RDFS.subClassOf):
            if isinstance(c, URIRef) and isinstance(p, URIRef) and c != p:
                raw.setdefault(c, set()).add(p)
        for a, b in g.subject_objects(OWL.equivalentClass):
            if isinstance(a, URIRef) and isinstance(b, URIRef) and a != b:
                raw.setdefault(a, set()).add(b)
                raw.setdefault(b, set()).add(a)
        self.canon = self._equivalence_classes(raw)
        self.parents = {}
        for c, ps in raw.items():
            cc = self.c(c)
            for p in ps:
                if self.c(p) != cc:
                    self.parents.setdefault(cc, set()).add(self.c(p))
        self.classes = {self.c(c) for c in g.subjects(RDF.type, OWL.Class) if isinstance(c, URIRef)} | set(self.parents)
        ignore = {c for c in g.subjects(OC.cbrIgnore, None) if str(g.value(c, OC.cbrIgnore)).lower() == "true"}
        self.derived = {self.c(x) for x in set(swrl_head_classes(g)) | set(_base_derived()) | ignore}
        self._anc = {}

    @staticmethod
    def _equivalence_classes(raw):
        """Componentes fortemente conexas do grafo de subclasses (Tarjan iterativo) -> representante."""
        index, low, stack, on, canon, counter = {}, {}, [], set(), {}, [0]
        nodes = set(raw) | {p for ps in raw.values() for p in ps}
        roots = set(FACETS.values())
        for start in nodes:
            if start in index:
                continue
            work = [(start, iter(sorted(raw.get(start, ()), key=str)))]
            index[start] = low[start] = counter[0]
            counter[0] += 1
            stack.append(start)
            on.add(start)
            while work:
                v, it = work[-1]
                nxt = next(it, None)
                if nxt is not None:
                    if nxt not in index:
                        index[nxt] = low[nxt] = counter[0]
                        counter[0] += 1
                        stack.append(nxt)
                        on.add(nxt)
                        work.append((nxt, iter(sorted(raw.get(nxt, ()), key=str))))
                    elif nxt in on:
                        low[v] = min(low[v], index[nxt])
                    continue
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[v])
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    if len(comp) > 1:
                        rep = next((x for x in sorted(comp, key=str) if x in roots), min(comp, key=str))
                        for w in comp:
                            canon[w] = rep
        return canon

    def c(self, x):
        """Representante canonico de uma classe (ela propria se nao tiver equivalentes)."""
        return self.canon.get(x, x)

    def ancestors(self, c):
        """{antepassado: distancia} incluindo o proprio c (distancia 0); BFS pela menor distancia."""
        c = self.c(c)
        if c not in self._anc:
            dist, todo = {c: 0}, deque([c])
            while todo:
                x = todo.popleft()
                for p in self.parents.get(x, ()):
                    if p not in dist:
                        dist[p] = dist[x] + 1
                        todo.append(p)
            self._anc[c] = dist
        return self._anc[c]

    def is_under(self, c, root):
        return self.c(root) in self.ancestors(c)

    def depth(self, c, root):
        """Profundidade de c na arvore de root (root = 0); None se c nao estiver sob root."""
        return self.ancestors(c).get(self.c(root))

    def subclasses(self, root, include_root=False):
        r = self.c(root)
        out = {c for c in self.classes if c != r and self.is_under(c, r)}
        return out | ({r} if include_root else set())

    def direct_subclasses(self, c):
        cc = self.c(c)
        return {x for x, ps in self.parents.items() if cc in ps}

    def most_specific(self, classes, root):
        """Classes mais especificas (sob root, nao derivadas) de um conjunto de tipos (representantes canonicos)."""
        r = self.c(root)
        cands = {self.c(c) for c in classes if isinstance(c, URIRef)}
        cands = {c for c in cands if c != r and c not in self.derived and self.is_under(c, r)}
        return sorted((c for c in cands if not any(o != c and self.is_under(o, c) for o in cands)), key=str)

    def types_of(self, ind):
        return {t for t in self.g.objects(ind, RDF.type) if isinstance(t, URIRef)}

    def classify(self, ind, root, fallback_root=True):
        """Tipos mais especificos de um individuo numa faceta; [root] se so for do tipo raiz."""
        ms = self.most_specific(self.types_of(ind), root)
        if not ms and fallback_root and any(self.is_under(t, root) for t in self.types_of(ind)):
            return [self.c(root)]
        return ms

    def depth_map(self, c, root):
        """{antepassado sob root: profundidade a partir de root} - guardado nas features para wu_palmer."""
        if self.depth(c, root) is None:
            return {}
        return {a: self.depth(a, root) for a in self.ancestors(c) if self.is_under(a, root)}

    def wu_palmer(self, c1, c2, root):
        return wu_palmer(self.depth_map(c1, root), self.depth_map(c2, root), c1, c2)


def wu_palmer(dm1, dm2, c1, c2):
    """Wu-Palmer a partir dos mapas {antepassado: profundidade}; 0 se o LCS for a raiz (profundidade 0)."""
    if not dm1 or not dm2 or c1 not in dm1 or c2 not in dm2:
        return 0.0
    common = set(dm1) & set(dm2)
    if not common:
        return 0.0
    lcs = max(dm1[a] for a in common)
    if lcs == 0:
        return 0.0
    return 2.0 * lcs / (dm1[c1] + dm2[c2])


def short(x):
    return str(x).split("#")[-1]


def is_true(v):
    return isinstance(v, Literal) and str(v).lower() == "true"
