# -*- coding: utf-8 -*-
"""
schemas.py - modelos Pydantic das respostas do Gemini.

As listas fechadas (classes de ativo, acoes de resolucao, classes da ontologia) sao construidas EM
TEMPO DE EXECUCAO a partir da ontologia (make_* abaixo): quando a evolucao cria uma subclasse de
:Asset ou uma acao nova, o esquema enviado ao Gemini passa a inclui-la sem alterar codigo.
Os padroes (CVE/CWE/ATT&CK, nomes de IRI) sao validados localmente: o Gemini descarta varias
palavras-chave de JSON Schema (ver gemini.to_gemini_schema).
"""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, create_model, field_validator

CWE_PATTERN = r"^CWE-\d+$"
ATTACK_PATTERN = r"^T\d{4}(\.\d{3})?$"
CLASS_NAME = r"^[A-Z][A-Za-z0-9]{2,60}$"
PROP_NAME = r"^[a-z][A-Za-z0-9]{2,60}$"
IND_NAME = r"^[A-Za-z][A-Za-z0-9_]{1,80}$"


def _literal(values):
    values = tuple(sorted(set(values)))
    if not values:
        raise ValueError("lista fechada vazia")
    return Literal.__getitem__(values)


# ------------------------------------------------------------------ aquisicao de vulnerabilidades
class TechniqueGuess(BaseModel):
    attack_id: str = Field(pattern=ATTACK_PATTERN, description="Identificador MITRE ATT&CK Enterprise, ex. T1190 ou T1059.004")
    role: Literal["exploitation", "impact"] = Field(description="exploitation = tecnica usada para explorar a falha")
    justification: str = Field(min_length=10, max_length=400)


def make_vuln_enrichment(asset_classes, actions):
    """Esquema da analise de uma vulnerabilidade, com as classes de ativo e acoes atuais da ontologia."""
    return create_model(
        "VulnEnrichment",
        cwe_id=(Optional[str], Field(None, pattern=CWE_PATTERN,
                                     description="CWE principal (fraqueza raiz). null se o texto nao permitir decidir.")),
        cwe_justification=(str, Field(min_length=10, max_length=500)),
        techniques=(List[TechniqueGuess], Field(min_length=0, max_length=3)),
        asset_class=(_literal(asset_classes), Field(description="Classe da ontologia que melhor descreve o produto afetado")),
        asset_justification=(str, Field(min_length=10, max_length=400)),
        required_action=(Optional[_literal(actions)], Field(None, description="Acao de resolucao que melhor resume a acao exigida")),
        evidence_quotes=(List[str], Field(min_length=1, max_length=4, description="Trechos LITERAIS do texto fornecido")),
        confidence=(float, Field(ge=0.0, le=1.0)),
    )


# ------------------------------------------------------------------ aquisicao de casos CBR
def make_case_analysis(actions):
    """Adaptacao (reuse) do CBR: o problema ja esta descrito na ontologia (VERIS A4 + CVSS); o modelo
    so escolhe a solucao entre as acoes existentes e justifica-a face aos casos recuperados."""
    return create_model(
        "CaseAnalysis",
        solution=(_literal(actions), Field(description="Acao de resolucao recomendada para o caso")),
        agrees_with_neighbors=(bool, Field(description="A solucao e a mesma do caso recuperado mais proximo?")),
        solution_rationale=(str, Field(min_length=20, max_length=800)),
        response_steps=(List[str], Field(min_length=1, max_length=6, description="Passos concretos de resposta")),
        evidence_quotes=(List[str], Field(min_length=1, max_length=4)),
        confidence=(float, Field(ge=0.0, le=1.0)),
    )


# ------------------------------------------------------------------ evolucao estrutural
class Evidence(BaseModel):
    source: Literal["ontology", "cwe", "attack", "nvd", "kev", "ctid", "signal"]
    ref: str = Field(min_length=1, max_length=120, description="Identificador verificavel (IRI local, CWE-x, Txxxx, id do sinal)")
    note: str = Field(min_length=3, max_length=300)


class MemberAssignment(BaseModel):
    individual: str = Field(pattern=IND_NAME, description="Nome local de um individuo existente")
    justification: str = Field(min_length=10, max_length=300)


class PropertyAssertion(BaseModel):
    subject: str = Field(pattern=IND_NAME)
    object: str = Field(pattern=IND_NAME)


class Restriction(BaseModel):
    """Condicao necessaria e suficiente (classe definida): Parent and (property VALUE individual)
    ou Parent and (property SOME Class). Gramatica restrita: nada de Turtle livre."""
    property: str = Field(pattern=PROP_NAME)
    kind: Literal["hasValue", "someValuesFrom"]
    value: str = Field(pattern=IND_NAME + "|" + CLASS_NAME)


class OntologyChangeProposal(BaseModel):
    kind: Literal["new_class", "new_object_property", "classify_individuals"]
    signal_id: str = Field(min_length=3, max_length=80)
    rationale: str = Field(min_length=30, max_length=1500)
    evidence: List[Evidence] = Field(min_length=1, max_length=12)
    confidence: float = Field(ge=0.0, le=1.0)
    # new_class / classify_individuals
    class_name: Optional[str] = Field(None, pattern=CLASS_NAME)
    parent: Optional[str] = Field(None, pattern=CLASS_NAME, description="Superclasse existente")
    label_pt: Optional[str] = Field(None, min_length=3, max_length=80)
    label_en: Optional[str] = Field(None, min_length=3, max_length=80)
    definition: Optional[str] = Field(None, min_length=20, max_length=600)
    disjoint_with_siblings: Optional[bool] = Field(None, description="Declarar disjuncao com as irmas atuais")
    defined_by: Optional[Restriction] = None
    members: Optional[List[MemberAssignment]] = Field(None, max_length=40)
    policy_response: Optional[str] = Field(None, pattern=IND_NAME, description="CoA herdada pela politica (so subclasses de Weakness)")
    # new_object_property
    property_name: Optional[str] = Field(None, pattern=PROP_NAME)
    domain: Optional[str] = Field(None, pattern=CLASS_NAME)
    range: Optional[str] = Field(None, pattern=CLASS_NAME)
    inverse_name: Optional[str] = Field(None, pattern=PROP_NAME)
    characteristics: Optional[List[Literal["asymmetric", "irreflexive", "transitive", "symmetric"]]] = Field(None, max_length=2)
    assertions: Optional[List[PropertyAssertion]] = Field(None, max_length=60)

    @field_validator("evidence")
    @classmethod
    def _evidence_not_only_signal(cls, v):
        if all(e.source == "signal" for e in v):
            raise ValueError("a evidencia tem de incluir pelo menos uma fonte alem do proprio sinal")
        return v


class ProposalBatch(BaseModel):
    proposals: List[OntologyChangeProposal] = Field(min_length=0, max_length=3)
    no_change_reason: Optional[str] = Field(None, max_length=600,
                                            description="Preencher quando nenhuma alteracao se justifica")
