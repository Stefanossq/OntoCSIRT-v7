#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
m002 - torna o modulo de evolucao autossuficiente: as CWEs classificadas por propostas ja aplicadas
recebem no proprio OntoCSIRT_v7_evo.ttl a sua identidade (:cweId e rdfs:label).

Motivo: EVO-20261103-001 classificou CWE_125/CWE_416/CWE_787, cujo :cweId so existia em
OntoCSIRT_v7_acquired.ttl. Composto com outro ficheiro de dados (p.ex. soar_webhook --acquired outro.ttl)
o modulo deixava essas CWEs sem identificador e a WeaknessShape bloqueava qualquer gravacao.
O compilador passou a copiar a identidade (ontoevo/compiler.py); esta migracao faz o mesmo para o que ja
foi aplicado. Aditiva e idempotente: so acrescenta um bloco com o que falta.

Uso: python migrations/m002_evo_member_identity.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rdflib import Graph, Namespace  # noqa: E402
from rdflib.namespace import RDFS  # noqa: E402

import validar_ingestao as val  # noqa: E402
from ontoevo import kb  # noqa: E402

OC = Namespace("http://www.semanticweb.org/ontocsirt#")
EVO = Namespace("http://www.semanticweb.org/ontocsirt/evo#")


def migrate(evo_path=None, profile="real"):
    evo_path = evo_path or val.EVO
    evo = Graph().parse(evo_path, format="turtle")
    full = kb.load(profile)                                   # base + dados do projeto (onde esta o cweId)
    add = Graph()
    for m in set(evo.subjects(EVO.classifiedBy, None)):
        if (m, OC.cweId, None) in evo:
            continue
        for p in (OC.cweId, RDFS.label):
            for v in full.objects(m, p):
                add.add((m, p, v))
    if not len(add):
        return 0
    kb.backup(evo_path, "m002")
    add.bind("", OC)
    block = add.serialize(format="turtle")
    with open(evo_path, "a", encoding="utf-8") as f:
        f.write("\n# ---------------------------------------------------------------------------\n"
                "# m002: identidade (:cweId, rdfs:label) das CWEs classificadas acima, para o modulo nao\n"
                "# depender de um ficheiro de dados especifico (ver migrations/m002_evo_member_identity.py)\n"
                "# ---------------------------------------------------------------------------\n" + block)
    return len(add)


if __name__ == "__main__":
    print("m002: %d triplas acrescentadas" % migrate())
