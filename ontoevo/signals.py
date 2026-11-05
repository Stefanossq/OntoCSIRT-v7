# -*- coding: utf-8 -*-
"""
signals.py - deteccao DETERMINISTICA de sinais de que a estrutura da ontologia ja nao descreve bem os dados.

Um sinal nao e uma alteracao: e a pergunta que se faz ao Gemini (ou a um analista). Cada sinal traz os
dados que o justificam, para que a proposta possa ser verificada contra eles.

  residual_category        a categoria residual (:residualCategory true) acumula membros
                           -> candidatas a categorias proprias (ancestrais CWE oficiais em comum)
  heterogeneous_category   membros de uma categoria repartem-se por ramos distintos da hierarquia
                           oficial CWE (ChildOf, vista 1000) -> candidatas a subcategorias
  default_asset_type       ativos cujo tipo veio do padrao da heuristica ("sem regra -> Server")
                           -> tipos de ativo em falta
  literal_encoded_relation valores literais que contem identificadores de individuos existentes
                           (p.ex. otherCweIds "CWE-20 CWE-79") -> relacao guardada como texto
  pattern_solution_cooccurrence  num padrao de ataque, os casos convergem para a mesma acao
                           -> relacao ao nivel do padrao (cf. STIX course-of-action "mitigates")
  tactic_partition         padroes ATT&CK da base pertencem a taticas diferentes e nao ha classes
                           por tatica -> subclasses de :AttackPattern ancoradas nas taticas oficiais
"""
import re
from collections import Counter, defaultdict

from rdflib import Literal, URIRef
from rdflib.namespace import OWL, RDF, RDFS

import ontocsirt_v7 as v7
import ontotax

OC = v7.OC
S = v7.short

EVO_NS = "http://www.semanticweb.org/ontocsirt/evo#"
# metadados de proveniencia/justificativa: citam identificadores por natureza (evidencia, rationale, origem
# de um campo) e nao descrevem uma relacao do dominio; nao entram no sinal literal_encoded_relation
PROVENANCE_PROPERTIES = {OC.cweSource, OC.techniqueSource, OC.assetTypeSource, OC.acquisitionRun,
                         OC.solutionRationale, OC.responseStep, OC.retrievedNeighbor, OC.retainedFrom,
                         OC.retainedBy, OC.assetTypeEvidence, OC.verificationNote, OC.cvssSource,
                         OC.kevRequiredAction, OC.solutionProvenance}

ID_PROPERTIES = {OC.cweId: (re.compile(r"CWE-\d+"), OC.Weakness), OC.attackId: (re.compile(r"T\d{4}(?:\.\d{3})?"), OC.AttackPattern),
                 OC.cveId: (re.compile(r"CVE-\d{4}-\d{4,}"), OC.Vulnerability)}


def _members(g, tax, cls, root):
    """Individuos cujo tipo mais especifico (na faceta root) e exatamente cls."""
    out = []
    for ind in set(g.subjects(RDF.type, None)):
        if not isinstance(ind, URIRef):
            continue
        ms = tax.most_specific(tax.types_of(ind), root)
        if ms == [cls]:
            out.append(ind)
    return sorted(out, key=str)


def _cwe_groups(g, members, catalogs, min_group=2):
    """Agrupa CWEs pelos antepassados oficiais; devolve grupos com >= min_group membros e < todos."""
    chains = {}
    for m in members:
        cid = g.value(m, OC.cweId)
        if cid is not None and catalogs is not None and catalogs.cwe:
            chains[S(m)] = [str(cid)] + catalogs.cwe_ancestors(str(cid))
    by_anc, dist = defaultdict(set), defaultdict(int)
    for m, chain in chains.items():
        for k, a in enumerate(chain):          # inclui a propria CWE: CWE-74 pertence ao ramo CWE-74
            by_anc[a].add(m)
            dist[a] += k
    best = {}
    for a, ms in by_anc.items():
        if min_group <= len(ms) < len(chains):
            key = frozenset(ms)                # mesmo conjunto de membros: fica o antepassado mais proximo
            if key not in best or (dist[a], a) < (dist[best[key]], best[key]):
                best[key] = a
    groups = []
    for ms, a in best.items():
        e = catalogs.cwe_entry(a) or {}
        groups.append({"cwe_ancestor": a, "name": e.get("name"), "abstraction": e.get("abstraction"),
                       "members": sorted(ms), "distance": dist[a]})
    # o sub-ramo mais especifico primeiro (menos membros, antepassado mais proximo)
    groups.sort(key=lambda x: (len(x["members"]), x["distance"], x["cwe_ancestor"]))
    return chains, groups


def detect(g, catalogs=None, min_members=2):
    tax = ontotax.Taxonomy(g)
    sig = []

    # 1-2. categorias de fraqueza
    for cls in sorted(tax.subclasses(OC.Weakness), key=str):
        if cls in tax.derived:
            continue
        members = _members(g, tax, cls, OC.Weakness)
        residual = ontotax.is_true(g.value(cls, OC.residualCategory))
        if residual and len(members) >= min_members:
            chains, groups = _cwe_groups(g, members, catalogs)
            sig.append({"id": "residual:%s" % S(cls), "kind": "residual_category", "focus": S(cls), "root": "Weakness",
                        "summary": "%d CWEs na categoria residual %s" % (len(members), S(cls)),
                        "data": {"members": [S(m) for m in members], "cwe_chains": chains, "official_groups": groups}})
        elif not residual and len(members) >= 3 and catalogs is not None and catalogs.cwe:
            chains, groups = _cwe_groups(g, members, catalogs)
            # heterogenea: existe um sub-ramo oficial proprio (>= 2 membros, nao todos) dentro da categoria
            if groups:
                outside = sorted(set(chains) - set(groups[0]["members"]))
                sig.append({"id": "heterogeneous:%s" % S(cls), "kind": "heterogeneous_category", "focus": S(cls),
                            "root": "Weakness",
                            "summary": "%s: %d de %d CWEs sob o ramo oficial %s (%s); fora dele: %s" % (
                                S(cls), len(groups[0]["members"]), len(chains), groups[0]["cwe_ancestor"],
                                groups[0]["name"], ", ".join(outside) or "-"),
                            "data": {"members": [S(m) for m in members], "cwe_chains": chains, "official_groups": groups}})

    # 3. tipo de ativo por omissao
    default = [a for a in g.subjects(OC.assetTypeEvidence, None) if "(padrao)" in str(g.value(a, OC.assetTypeEvidence))]
    if len(default) >= min_members:
        sig.append({"id": "asset-default", "kind": "default_asset_type", "focus": "Asset", "root": "Asset",
                    "summary": "%d ativos com tipo atribuido por omissao (Server)" % len(default),
                    "data": {"assets": [{"asset": S(a), "vendor_product": str(g.value(a, OC.vendorProduct) or g.value(a, RDFS.label))}
                                        for a in sorted(default, key=str)],
                             "asset_types": sorted(S(c) for c in tax.subclasses(OC.Asset) if c not in tax.derived)}})

    # 4. relacoes guardadas como literal
    index = {}
    for p, (rx, cls) in ID_PROPERTIES.items():
        for s, o in g.subject_objects(p):
            index[str(o)] = (s, p, cls)
    hits = defaultdict(list)
    for s, p, o in g:
        if not isinstance(o, Literal) or p in ID_PROPERTIES or p in (RDFS.label, RDFS.comment) \
                or p in PROVENANCE_PROPERTIES or str(p).startswith(EVO_NS):
            continue
        for rx, cls in ID_PROPERTIES.values():
            for tok in rx.findall(str(o)):
                if tok in index and index[tok][0] != s:
                    hits[p].append({"subject": S(s), "literal": str(o), "refers_to": S(index[tok][0]), "id": tok})
                elif catalogs is not None and cls == OC.Weakness and catalogs.cwe_entry(tok):
                    hits[p].append({"subject": S(s), "literal": str(o), "refers_to": None, "id": tok})
    for p, rows in sorted(hits.items(), key=lambda kv: str(kv[0])):
        if len(rows) >= min_members:
            kinds = (g.value(p, RDF.type),)
            sig.append({"id": "literal-relation:%s" % S(p), "kind": "literal_encoded_relation", "focus": S(p), "root": None,
                        "summary": "%s guarda %d referencias a individuos como texto" % (S(p), len(rows)),
                        "data": {"property": S(p), "property_type": S(kinds[0]) if kinds[0] else None,
                                 "subject_types": sorted({S(c) for r in rows for c in tax.types_of(OC[r["subject"]])}),
                                 "rows": rows[:40], "n": len(rows)}})

    # 5. co-ocorrencia padrao -> solucao nos casos
    F = v7.features(g)
    by_ap = defaultdict(list)
    for i, f in F.items():
        if f["sol"]:
            by_ap[f["ap"]].append(f["sol"])
    strong = []
    for ap, sols in sorted(by_ap.items()):
        if len(sols) >= 2:
            sol, n = Counter(sols).most_common(1)[0]
            if n / len(sols) >= 0.75:
                strong.append({"pattern": ap, "solution": sol, "support": n, "cases": len(sols)})
    existing = [S(p) for p in g.subjects(RDF.type, OWL.ObjectProperty)
                if g.value(p, RDFS.domain) == OC.AttackPattern and g.value(p, RDFS.range) in (OC.ResolutionAction, OC.CourseOfAction)]
    if len(strong) >= 2 and not existing:
        sig.append({"id": "cooccurrence:AttackPattern-ResolutionAction", "kind": "pattern_solution_cooccurrence",
                    "focus": "AttackPattern", "root": None,
                    "summary": "%d padroes de ataque com solucao dominante (>=75%% dos casos)" % len(strong),
                    "data": {"pairs": strong, "existing_properties": existing,
                             "note": "solucoes do v7 seguem a politica por categoria de CWE (ver OntoCSIRT_v7.ttl, sec. 7)"}})

    # 6. particao por tatica ATT&CK
    if catalogs is not None and catalogs.attack:
        aps = sorted(g.subjects(OC.attackId, None), key=str)
        by_tactic = defaultdict(list)
        for ap in aps:
            for t in catalogs.technique_tactics(str(g.value(ap, OC.attackId))):
                by_tactic[t].append(S(ap))
        has_tactic_classes = any(c for c in tax.subclasses(OC.AttackPattern) if c not in tax.derived)
        if len(by_tactic) >= 2 and len(aps) >= 3 and not has_tactic_classes:
            sig.append({"id": "tactic-partition:AttackPattern", "kind": "tactic_partition", "focus": "AttackPattern",
                        "root": "AttackPattern",
                        "summary": "%d padroes ATT&CK em %d taticas, sem classes por tatica" % (len(aps), len(by_tactic)),
                        "data": {"by_tactic": {t: sorted(v) for t, v in sorted(by_tactic.items())},
                                 "tactic_names": {t: catalogs.attack["tactics"].get(t) for t in by_tactic}}})
    return sig
