#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
m001 - :kevDateAdded passa de owl:DatatypeProperty (range xsd:date) a owl:AnnotationProperty.

Motivo: xsd:date nao pertence ao mapa de tipos do OWL 2 (OWL 2 Syntax, sec. 4); com o range xsd:date
os ficheiros que copiam a extensao saiam do OWL 2 DL e o HermiT recusava-os. Os valores (literais
xsd:date) nao mudam. Idempotente: so troca a declaracao se ainda for DatatypeProperty.

Uso: python migrations/m001_kevdateadded_annotation.py OntoCSIRT_v7_real.ttl staging_ingest.ttl
"""
import sys

from rdflib import Graph, Namespace
from rdflib.namespace import OWL, RDF, RDFS

OC = Namespace("http://www.semanticweb.org/ontocsirt#")


def migrate(path):
    g = Graph()
    g.parse(path, format="turtle")
    p = OC.kevDateAdded
    if (p, RDF.type, OWL.DatatypeProperty) not in g:
        return False
    g.remove((p, RDF.type, OWL.DatatypeProperty))
    g.remove((p, RDFS.domain, None))
    g.remove((p, RDFS.range, None))
    g.add((p, RDF.type, OWL.AnnotationProperty))
    g.serialize(path, format="turtle")
    return True


if __name__ == "__main__":
    for f in sys.argv[1:]:
        print("%s: %s" % (f, "migrado" if migrate(f) else "ja estava migrado"))
