# Relatorio de cobertura - pipeline VCDB

Gerado por `python -m vcdb_pipeline run`. Regras: `vcdb-pipeline-1 (cve-extract-1, label-1, canonical-1)`. Hash de reprodutibilidade: `d806142bd9cc574aefdf65718f06eac82b254c0ded2b09a9cb0fa9c3bc06393f`.

Fonte: `data/joined/vcdb.json.zip` @ `f6f98c00f66ab35f5b49977a5852ce94a5bb31d1` (sha256 `e4be5dd432ccfad16520a6b60dd83e9d47c63b0f3352c26c4d43a5dd774c32c0`). Licenca dos dados derivados: CC BY-SA 4.0.

## Registos e chaves

| Medida | Valor |
|---|---|
| Registos | 10047 |
| `record_key` (plus.master_id) distintos | 10044 |
| Registos com `incident_id` repetido | 67 |

## Preenchimento dos campos canonicos

| Campo | Preenchidos | % |
|---|---|---|
| `record_key` | 10047 | 100.00 |
| `incident_id` | 10047 | 100.00 |
| `schema_version` | 10047 | 100.00 |
| `security_incident` | 10047 | 100.00 |
| `confidence` | 2818 | 28.05 |
| `summary` | 9528 | 94.83 |
| `reference` | 9564 | 95.19 |
| `year` | 10047 | 100.00 |
| `month` | 7157 | 71.24 |
| `day` | 4398 | 43.77 |
| `actor_categories` | 10047 | 100.00 |
| `actor_varieties` | 9534 | 94.89 |
| `action_categories` | 10047 | 100.00 |
| `action_varieties` | 9815 | 97.69 |
| `action_vectors` | 9806 | 97.60 |
| `asset_varieties` | 10047 | 100.00 |
| `asset_classes` | 10047 | 100.00 |
| `attributes` | 10047 | 100.00 |
| `data_disclosure` | 9372 | 93.28 |
| `discovery` | 5575 | 55.49 |
| `industry_naics` | 10047 | 100.00 |
| `victim_country` | 10047 | 100.00 |
| `campaign_id` | 192 | 1.91 |
| `sub_source` | 1937 | 19.28 |
| `analysis_status` | 9741 | 96.95 |
| `credit_monitoring` | 4928 | 49.05 |
| `cve_raw` | 932 | 9.28 |
| `cves` | 926 | 9.22 |
| `cve_mentions_text` | 5 | 0.05 |

## sub_source (vies de amostragem [S4])

| Valor | Registos |
|---|---|
| None | 8110 |
| phidbr | 1310 |
| priority | 602 |
| covid19 | 25 |

## analysis_status

| Valor | Registos |
|---|---|
| First pass | 4982 |
| Finalized | 2595 |
| Reviewed | 2109 |
| None | 306 |
| Ready for review | 51 |
| Ineligible | 4 |

## schema_version

| Valor | Registos |
|---|---|
| 1.4.0 | 9907 |
| 1.4.1 | 111 |
| 1.3.7 | 26 |
| 1.3.5 | 2 |
| 1.3.6 | 1 |

## security_incident

| Valor | Registos |
|---|---|
| Confirmed | 9966 |
| Suspected | 73 |
| Near miss | 8 |

## credit_monitoring (D4, sem regra de rotulo)

| Valor | Registos |
|---|---|
| None | 5119 |
| Unknown | 4209 |
| Yes | 579 |
| No | 140 |

## CVEs

| Medida | Valor |
|---|---|
| Incidentes com CVE estruturada | 926 |
| CVEs distintas | 31 |
| Conjuntos distintos de CVEs | 20 |
| Incidentes com CVE so no texto | 4 |

Conjuntos mais frequentes (risco de fuga de informacao numa avaliacao futura, contrato 5.4):

| CVEs | Incidentes |
|---|---|
| CVE-2023-34362, CVE-2023-35036, CVE-2023-35708 | 747 |
| CVE-2008-4250, CVE-2009-3129, CVE-2010-3333, CVE-2011-3544, CVE-2012-0158 | 88 |
| CVE-2013-0640, CVE-2013-0641 | 60 |
| CVE-2010-0249 | 11 |
| CVE-2014-0160 | 2 |
| CVE-2017-5638 | 2 |
| CVE-2013-1347, CVE-2013-1493, CVE-2013-2423 | 2 |
| CVE-2019-19781 | 2 |
| CVE-2012-0507 | 1 |
| CVE-2012-4681, CVE-2013-2423 | 1 |

## NVD

| Medida | Valor |
|---|---|
| requests | 1 |
| from_cache | 0 |
| fetched | 31 |
| missing | [] |
| schema_errors | 0 |

## Rotulos por CVE (`remediation_documented`)

| Rotulo | CVEs |
|---|---|
| none_tagged | 14 |
| patch | 13 |
| review:TAG_BOTH | 3 |
| mitigation | 1 |

## Rotulos por incidente

| Estado/valor | Incidentes |
|---|---|
| auto/mitigation | 1 |
| auto/none_tagged | 67 |
| auto/patch | 106 |
| no_cve/None | 9121 |
| review/None | 752 |

## Fila de revisao humana

1517 pendencias em 765 registos.

| Codigo | Pendencias |
|---|---|
| `TAG_BOTH` | 751 |
| `CVE_SET_DISAGREES` | 750 |
| `DUP_MASTER_ID` | 6 |
| `CVE_FIELD_NO_ID` | 6 |
| `CVE_ONLY_IN_TEXT` | 4 |

## Tags NVD x `cisaRequiredAction` do KEV (D5: so medida, nao decide)

| Rotulo pelas tags | cisaRequiredAction | CVEs |
|---|---|---|
| mitigation | Apply updates per vendor instructions. | 1 |
| none_tagged | (fora do KEV) | 3 |
| none_tagged | Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable. | 1 |
| none_tagged | Apply updates per vendor instructions. | 10 |
| patch | (fora do KEV) | 1 |
| patch | Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable. | 2 |
| patch | Apply updates per vendor instructions. | 10 |
| review:TAG_BOTH | (fora do KEV) | 1 |
| review:TAG_BOTH | Apply updates per vendor instructions. | 2 |

## Validacao contra vcdb-merged.json

104 registos com erros de schema (informativo).

*Este produto usa dados da API do NVD, mas nao e endossado nem certificado pelo NVD.*
