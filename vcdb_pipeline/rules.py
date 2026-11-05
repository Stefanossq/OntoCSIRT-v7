# -*- coding: utf-8 -*-
"""Registo de todas as regras de mapeamento do pipeline VCDB, com versao e fonte.

Cada regra aplicada a um registo e citada pelo seu ID na proveniencia (``rules_applied``) ou na fila de
revisao (``rule_id``). Mudar o comportamento de uma regra obriga a mudar ``RULES_VERSION``; o hash de
reprodutibilidade inclui esta versao. As fontes [S1]-[S12] estao em docs/vcdb/RODADA1_CONTRATO.md.
"""

RULES_VERSION = "vcdb-pipeline-1 (cve-extract-1, label-1, canonical-1)"

# Fonte VCDB fixada (decisao D1 do contrato)
VCDB_REPO = "vz-risk/VCDB"
VCDB_COMMIT = "f6f98c00f66ab35f5b49977a5852ce94a5bb31d1"
VCDB_JOINED_PATH = "data/joined/vcdb.json.zip"
VCDB_JOINED_GIT_BLOB = "647a5291b127fa706bd29975fef379acd8fbf4ff"
VCDB_JOINED_SHA256 = "e4be5dd432ccfad16520a6b60dd83e9d47c63b0f3352c26c4d43a5dd774c32c0"
VCDB_LICENSE = "CC-BY-SA-4.0"

RULES = {
    # ---------------------------------------------------------------- contrato canonico
    "CANON-KEY-1": {
        "text": "record_key = plus.master_id; master_id repetido -> revisao DUP_MASTER_ID",
        "source": "[S2] plus.master_id; [obs] 10 044 valores unicos em 10 047 registos (decisao D3)"},
    "CANON-KEY-2": {
        "text": "incident_id copiado; repetido -> marca dup_incident_id, sem exclusao",
        "source": "[S2] incident_id obrigatorio; [obs] 23 valores repetidos em 67 registos, contradiz [S4]"},
    "CANON-YEAR-1": {
        "text": "timeline.incident.year fora de [1950, 2050] -> revisao YEAR_OUT_OF_SCHEMA",
        "source": "[S2] timeline.incident.year: minimum 1950, maximum 2050"},
    "CANON-ASSET-1": {
        "text": "asset_class = prefixo de asset.assets[].variety antes de ' - '",
        "source": "[S2] enumeracao asset.assets.variety ('S - Web application', 'M - Documents', ...)"},
    # ---------------------------------------------------------------- extracao de CVEs
    "CVE-EXTRACT-1": {
        "text": "extrair CVE-\\d{4}-\\d{4,} (sem digito a seguir) de action.hacking.cve e action.malware.cve; "
                "deduplicar e ordenar",
        "source": "[S2] action.hacking.cve / action.malware.cve 'CVE(s) exploited', type string; "
                  "[S8] sequencia com 4 ou mais digitos, nao truncar"},
    "CVE-EXTRACT-2": {
        "text": "campo de CVE nao vazio sem nenhum ID valido -> revisao CVE_FIELD_NO_ID (sem correcao automatica)",
        "source": "[obs] 'cve unknown', 'Wordpress', 'CVE 2012-4792', 'Unknown vuln', 'Heartbleed'"},
    "CVE-EXTRACT-3": {
        "text": "IDs em summary/reference/action.hacking.notes so em cve_mentions_text; sem CVE estruturada e "
                "com mencoes -> revisao CVE_ONLY_IN_TEXT",
        "source": "[S2] so os campos .cve sao reservados a CVEs"},
    "CVE-EXTRACT-4": {
        "text": "CVE extraida que o NVD nao devolve (ou ausente da cache em modo offline) -> revisao CVE_NOT_IN_NVD",
        "source": "[S9] cveIds 'will not accept {CVE-IDs} for vulnerabilities not yet received by the NVD'"},
    # ---------------------------------------------------------------- rotulos (decisao D2)
    "LABEL-CVE-1": {"text": "tags com Patch e sem Mitigation -> remediation_documented = patch",
                    "source": "[S9] 'Resource tags are designed to categorize the type of information each "
                              "reference contains'"},
    "LABEL-CVE-2": {"text": "tags com Mitigation e sem Patch -> remediation_documented = mitigation",
                    "source": "[S9] (idem)"},
    "LABEL-CVE-3": {"text": "Patch e Mitigation -> revisao TAG_BOTH",
                    "source": "nenhuma fonte define precedencia entre tags (lacuna L-1)"},
    "LABEL-CVE-4": {"text": "nem Patch nem Mitigation -> remediation_documented = none_tagged (nao significa "
                            "'sem remediacao')",
                    "source": "[S12] 'References for a CVE are provided through the CVE list, the NVD does not "
                              "have direct control over them'"},
    "LABEL-CVE-5": {"text": "Patch/Mitigation so em referencias tambem marcadas 'Broken Link' -> revisao "
                            "TAG_ON_BROKEN_LINK",
                    "source": "efeito de 'Broken Link' sobre a evidencia nao documentado (lacuna L-3)"},
    "LABEL-INC-1": {"text": "todas as CVEs do incidente com o mesmo rotulo -> esse rotulo", "source": "contrato 5.3"},
    "LABEL-INC-2": {"text": "CVEs do incidente com rotulos diferentes, ou alguma em revisao -> revisao "
                            "CVE_SET_DISAGREES",
                    "source": "contrato 5.3; [obs] MOVEit (747 incidentes)"},
    "LABEL-INC-3": {"text": "incidente sem CVE estruturada -> sem rotulo NVD (no_cve)", "source": "contrato 5.3"},
    "KEV-RECORD-1": {"text": "cisaRequiredAction guardado como texto; nao decide o rotulo (decisao D5)",
                     "source": "[S9] campos KEV na resposta; lacuna L-4 (texto livre, sem enumeracao)"},
}

# Codigos da fila de revisao -> regra que os gera
REVIEW_CODES = {
    "DUP_MASTER_ID": "CANON-KEY-1",
    "YEAR_OUT_OF_SCHEMA": "CANON-YEAR-1",
    "CVE_FIELD_NO_ID": "CVE-EXTRACT-2",
    "CVE_ONLY_IN_TEXT": "CVE-EXTRACT-3",
    "CVE_NOT_IN_NVD": "CVE-EXTRACT-4",
    "TAG_BOTH": "LABEL-CVE-3",
    "TAG_ON_BROKEN_LINK": "LABEL-CVE-5",
    "CVE_SET_DISAGREES": "LABEL-INC-2",
}

LABEL_VALUES = ("patch", "mitigation", "none_tagged")
