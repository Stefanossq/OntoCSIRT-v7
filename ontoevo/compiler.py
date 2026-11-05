# -*- coding: utf-8 -*-
"""
compiler.py - proposta de alteracao (JSON validado por schemas.OntologyChangeProposal) -> triplas OWL.

O modelo de linguagem nunca escreve Turtle: preenche uma gramatica restrita que este compilador traduz
de forma DETERMINISTICA, com verificacoes estruturais antes de qualquer raciocinador:

  new_class             C subClassOf P (P existente, sob uma raiz permitida, nao derivada por SWRL);
                        rotulos @pt/@en, definicao, proveniencia (evo:*); opcional: disjuncao com as
                        irmas, definicao necessaria e suficiente (P and (prop VALUE ind | prop SOME Cls)),
                        membros (individuos existentes) e :policyResponse (so sob :Weakness)
  new_object_property   P com dominio e contradominio nomeados existentes, caracteristicas OWL 2 DL
                        seguras, inverso opcional e assercoes cujos sujeito/objeto respeitam dominio/contradominio
  classify_individuals  individuos existentes passam a membros de uma classe existente

Evolucao monotona: so se ACRESCENTA. A unica retracao possivel e sair da categoria residual
(:residualCategory true) e so em ficheiros de dados (nunca no OntoCSIRT_v7.ttl congelado).
"""
import re
from dataclasses import dataclass, field

from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS, XSD

import ontocsirt_v7 as v7
import ontotax

OC = v7.OC
EVO = Namespace("http://www.semanticweb.org/ontocsirt/evo#")
S = v7.short

ALLOWED_ROOTS = [OC.Weakness, OC.Asset, OC.AttackPattern, OC.CourseOfAction, OC.ThreatActor, OC.Vulnerability,
                 OC.DetectionSource]
PROTECTED = {OC.Incident, OC.Case, OC.ThreatAction, OC.SecurityState}
# facetas onde o v7 declara particoes disjuntas (um individuo, um so ramo); nas outras (p.ex. taticas
# ATT&CK) um individuo pode pertencer a varias classes irmas e so a disjuncao declarada o impede
PARTITIONED = {OC.Weakness, OC.Asset, OC.ThreatActor}
SAFE_CHARACTERISTICS = {"asymmetric": OWL.AsymmetricProperty, "irreflexive": OWL.IrreflexiveProperty,
                        "transitive": OWL.TransitiveProperty, "symmetric": OWL.SymmetricProperty}


@dataclass
class Compiled:
    proposal_id: str
    kind: str
    adds: Graph = field(default_factory=Graph)
    retracts: list = field(default_factory=list)      # [(s, p, o)] - so tipo residual em dados
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    new_classes: list = field(default_factory=list)
    new_properties: list = field(default_factory=list)
    members: list = field(default_factory=list)

    @property
    def ok(self):
        return not self.errors

    def summary(self):
        return {"proposal_id": self.proposal_id, "kind": self.kind, "ok": self.ok, "errors": self.errors,
                "warnings": self.warnings, "new_classes": self.new_classes, "new_properties": self.new_properties,
                "members": self.members, "triples_added": len(self.adds),
                "retractions": [[S(x) for x in t] for t in self.retracts]}

    def turtle(self):
        g = Graph()
        for t in self.adds:
            g.add(t)
        g.bind("", OC)
        g.bind("evo", EVO)
        return g.serialize(format="turtle")


def _exists(g, name):
    return any(True for _ in g.triples((OC[name], None, None)))


def _is_class(g, iri):
    return (iri, RDF.type, OWL.Class) in g


def _root_of(tax, cls):
    return next((r for r in ALLOWED_ROOTS if tax.is_under(cls, r)), None)


def _frozen_graph():
    g = Graph()
    g.parse(v7.TTL, format="turtle")
    return g


def compile_proposal(p, g, proposal_id, proposed_by):
    """p: OntologyChangeProposal (ou dict); g: base composta atual (kb.load)."""
    from .schemas import OntologyChangeProposal
    if isinstance(p, dict):
        p = OntologyChangeProposal.model_validate(p)
    c = Compiled(proposal_id=proposal_id, kind=p.kind)
    tax = ontotax.Taxonomy(g)
    prov = [(EVO.proposalId, Literal(proposal_id)), (EVO.proposedBy, Literal(proposed_by)),
            (EVO.rationale, Literal(p.rationale)), (EVO.signal, Literal(p.signal_id))]
    prov += [(EVO.evidence, Literal("%s:%s - %s" % (e.source, e.ref, e.note))) for e in p.evidence]
    for e in p.evidence:                                # evidencia "ontology" tem de existir de facto
        if e.source == "ontology" and re.match(r"^[A-Za-z][\w]*$", e.ref) and not _exists(g, e.ref):
            c.errors.append("evidencia refere %s, que nao existe na ontologia" % e.ref)

    if p.kind in ("new_class", "classify_individuals"):
        _class_part(p, g, tax, c, prov)
    elif p.kind == "new_object_property":
        _property_part(p, g, tax, c, prov)
    return c


def _class_part(p, g, tax, c, prov):
    if not p.class_name:
        c.errors.append("class_name obrigatorio")
        return
    C = OC[p.class_name]
    if p.kind == "new_class":
        if _exists(g, p.class_name):
            c.errors.append("%s ja existe na ontologia" % p.class_name)
            return
        if not p.parent or not _is_class(g, OC[p.parent]):
            c.errors.append("superclasse %r inexistente" % p.parent)
            return
        P = OC[p.parent]
        if P in PROTECTED or any(tax.is_under(P, x) for x in PROTECTED):
            c.errors.append("%s pertence ao nucleo protegido (Incident/Case/ThreatAction/SecurityState)" % p.parent)
            return
        root = _root_of(tax, P)
        if root is None:
            c.errors.append("%s nao esta sob uma raiz evoluivel (%s)" % (p.parent, ", ".join(S(r) for r in ALLOWED_ROOTS)))
            return
        if P in tax.derived:
            c.errors.append("%s e uma classe derivada (cabeca de regra SWRL ou cbrIgnore)" % p.parent)
            return
        if not p.label_pt or not p.definition:
            c.errors.append("classe nova exige label_pt e definition")
            return
        c.adds.add((C, RDF.type, OWL.Class))
        c.adds.add((C, RDFS.subClassOf, P))
        c.adds.add((C, RDFS.label, Literal(p.label_pt, lang="pt")))
        if p.label_en:
            c.adds.add((C, RDFS.label, Literal(p.label_en, lang="en")))
        c.adds.add((C, RDFS.comment, Literal(p.definition, lang="pt")))
        for pr, o in prov:
            c.adds.add((C, pr, o))
        c.new_classes.append(p.class_name)
        if p.disjoint_with_siblings:
            for sib in sorted(tax.direct_subclasses(P), key=str):
                if sib not in tax.derived:
                    c.adds.add((C, OWL.disjointWith, sib))
        if p.defined_by:
            _definition(p, g, tax, c, C, P)
        if p.policy_response:
            if root != OC.Weakness:
                c.errors.append("policy_response so se aplica a subclasses de Weakness")
            elif (OC[p.policy_response], RDF.type, OC.ResolutionAction) not in g:
                c.errors.append("policy_response %s nao e uma ResolutionAction" % p.policy_response)
            else:
                c.adds.add((C, OC.policyResponse, OC[p.policy_response]))
        elif root == OC.Weakness:
            # a categoria tem de herdar uma politica de resposta; senao os casos novos ficariam sem solucao
            import ingest_real_cases as ing
            probe = Graph()
            for t in g.triples((None, RDFS.subClassOf, None)):
                probe.add(t)
            for t in g.triples((None, OC.policyResponse, None)):
                probe.add(t)
            probe.add((C, RDFS.subClassOf, P))
            ing._TAX_CACHE.clear()
            try:
                ing.policy_action(p.class_name, "State_Integrity", probe)
            except KeyError:
                c.errors.append("categoria %s nao herda politica de resposta: indique policy_response" % p.class_name)
            finally:
                ing._TAX_CACHE.clear()
    else:
        if not _is_class(g, C):
            c.errors.append("classe %s inexistente" % p.class_name)
            return
        P, root = C, _root_of(tax, C)
        if root is None or C in tax.derived:
            c.errors.append("%s nao e uma classe evoluivel" % p.class_name)
            return
    _members(p, g, tax, c, C, P, _root_of(tax, P))


def _definition(p, g, tax, c, C, P):
    r = p.defined_by
    prop = OC[r.property]
    if (prop, RDF.type, OWL.ObjectProperty) not in g:
        c.errors.append("definicao usa %s, que nao e uma ObjectProperty existente" % r.property)
        return
    if r.kind == "hasValue" and not any(True for _ in g.triples((OC[r.value], RDF.type, None))):
        c.errors.append("definicao: individuo %s inexistente" % r.value)
        return
    if r.kind == "someValuesFrom" and not _is_class(g, OC[r.value]):
        c.errors.append("definicao: classe %s inexistente" % r.value)
        return
    from rdflib import BNode
    from rdflib.collection import Collection
    eq, rest, lst = BNode(), BNode(), BNode()
    c.adds.add((C, OWL.equivalentClass, eq))
    c.adds.add((eq, RDF.type, OWL.Class))
    c.adds.add((rest, RDF.type, OWL.Restriction))
    c.adds.add((rest, OWL.onProperty, prop))
    c.adds.add((rest, OWL.hasValue if r.kind == "hasValue" else OWL.someValuesFrom, OC[r.value]))
    Collection(c.adds, lst, [P, rest])
    c.adds.add((eq, OWL.intersectionOf, lst))


def _members(p, g, tax, c, C, P, root):
    if not p.members:
        return
    frozen = _frozen_graph()
    for m in p.members:
        M = OC[m.individual]
        types = tax.types_of(M)
        if not types:
            c.errors.append("membro %s nao existe" % m.individual)
            continue
        ms = tax.most_specific(types, root) if root is not None else []
        bad = []
        default_ev = g.value(M, OC.assetTypeEvidence)
        for t in ms:
            # mesmo ramo = t e antepassado da classe-alvo C (o membro especializa-se) ou, numa classe
            # existente, descendente dela. Uma IRMA de C sob o mesmo pai (p.ex. OtherWeakness para uma
            # nova categoria sob Weakness) NAO e o mesmo ramo.
            if C == P:      # classify_individuals numa classe existente
                same = t == C or tax.is_under(t, C) or tax.is_under(C, t)
            else:           # classe nova C < P
                same = t == P or tax.is_under(P, t)
            if same:
                continue
            defeasible = ontotax.is_true(g.value(t, OC.residualCategory)) or \
                (root == OC.Asset and default_ev is not None and "(padrao)" in str(default_ev))
            if defeasible:
                # categoria residual ou tipo de ativo atribuido por omissao: pressupostos revogaveis
                if (M, RDF.type, t) in frozen:
                    c.errors.append("%s tem o tipo %s no ficheiro congelado; nao pode ser retirado" % (m.individual, S(t)))
                else:
                    c.retracts.append((M, RDF.type, t))
                    if root == OC.Asset and default_ev is not None:
                        c.retracts.append((M, OC.assetTypeEvidence, default_ev))
                        c.adds.add((M, OC.assetTypeEvidence, Literal("evo:%s (%s)" % (c.proposal_id, m.justification[:120]))))
                continue
            if root in PARTITIONED:
                bad.append(S(t))
        if bad:
            c.errors.append("membro %s pertence a %s (outro ramo); reclassificar entre ramos exigiria retirar um tipo "
                            "nao residual" % (m.individual, ", ".join(bad)))
            continue
        if not ms and not any(tax.is_under(t, root) for t in types if root is not None):
            c.errors.append("membro %s nao e um individuo da arvore de %s" % (m.individual, S(root) if root else "?"))
            continue
        c.adds.add((M, RDF.type, C))
        c.adds.add((M, EVO.classifiedBy, Literal(c.proposal_id)))
        # o modulo de evolucao tem de ser autossuficiente: uma CWE classificada aqui pode vir de um ficheiro
        # de dados que nem sempre e carregado (outro --acquired); sem a identidade, a WeaknessShape falharia
        if root == OC.Weakness:
            for p in (OC.cweId, RDFS.label):
                for v in g.objects(M, p):
                    c.adds.add((M, p, v))
        c.members.append(m.individual)


def _property_part(p, g, tax, c, prov):
    for f in ("property_name", "domain", "range", "label_pt", "definition"):
        if not getattr(p, f):
            c.errors.append("new_object_property exige %s" % f)
    if c.errors:
        return
    if _exists(g, p.property_name):
        c.errors.append("%s ja existe" % p.property_name)
        return
    D, R = OC[p.domain], OC[p.range]
    for x in (D, R):
        if not _is_class(g, x):
            c.errors.append("%s nao e uma classe existente" % S(x))
    chars = set(p.characteristics or [])
    if "symmetric" in chars and "asymmetric" in chars:
        c.errors.append("simetrica e assimetrica ao mesmo tempo")
    if "transitive" in chars and chars & {"asymmetric", "irreflexive"}:
        c.errors.append("OWL 2 DL: propriedade transitiva nao e simples; nao pode ser assimetrica/irreflexiva")
    if "symmetric" in chars and D != R:
        c.errors.append("propriedade simetrica exige dominio = contradominio")
    if c.errors:
        return
    P = OC[p.property_name]
    c.adds.add((P, RDF.type, OWL.ObjectProperty))
    c.adds.add((P, RDFS.domain, D))
    c.adds.add((P, RDFS.range, R))
    c.adds.add((P, RDFS.label, Literal(p.label_pt, lang="pt")))
    if p.label_en:
        c.adds.add((P, RDFS.label, Literal(p.label_en, lang="en")))
    c.adds.add((P, RDFS.comment, Literal(p.definition, lang="pt")))
    for ch in sorted(chars):
        c.adds.add((P, RDF.type, SAFE_CHARACTERISTICS[ch]))
    for pr, o in prov:
        c.adds.add((P, pr, o))
    c.new_properties.append(p.property_name)
    if p.inverse_name:
        if _exists(g, p.inverse_name):
            c.errors.append("%s ja existe" % p.inverse_name)
            return
        Q = OC[p.inverse_name]
        c.adds.add((Q, RDF.type, OWL.ObjectProperty))
        c.adds.add((Q, OWL.inverseOf, P))
        c.adds.add((Q, RDFS.domain, R))
        c.adds.add((Q, RDFS.range, D))
        c.adds.add((Q, RDFS.label, Literal("inverso de: %s" % p.label_pt, lang="pt")))
        c.adds.add((Q, RDFS.comment, Literal("Inversa de %s. %s" % (p.property_name, p.definition), lang="pt")))
        for pr, o in prov:
            c.adds.add((Q, pr, o))
        c.new_properties.append(p.inverse_name)
    for a in p.assertions or []:
        s, o = OC[a.subject], OC[a.object]
        st, ot = tax.types_of(s), tax.types_of(o)
        if not st or not ot:
            c.errors.append("assercao %s -> %s: individuo inexistente" % (a.subject, a.object))
            continue
        if not any(t == D or tax.is_under(t, D) for t in st):
            c.errors.append("assercao: %s nao e do dominio %s" % (a.subject, p.domain))
            continue
        if not any(t == R or tax.is_under(t, R) for t in ot):
            c.errors.append("assercao: %s nao e do contradominio %s" % (a.object, p.range))
            continue
        if "irreflexive" in chars and s == o:
            c.errors.append("assercao reflexiva numa propriedade irreflexiva: %s" % a.subject)
            continue
        c.adds.add((s, P, o))
    if p.assertions and not any(t for t in c.adds.triples((None, P, None))):
        c.warnings.append("nenhuma assercao valida")
