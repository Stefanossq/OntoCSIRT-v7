# Pipeline VCDB (Rodada 2)

O pipeline transforma os incidentes reais do VCDB em registos canônicos com rótulos derivados das tags de referência do NVD. Implementa só o que foi aprovado no contrato ([`RODADA1_CONTRATO.md`](RODADA1_CONTRATO.md), decisões D1–D6). **Ainda não integra LLM, CBR nem SHACL.**

```bash
python -m vcdb_pipeline run --offline     # ~2 s; só dados fixados no repositório, sem rede
python -m vcdb_pipeline run               # descarrega o que faltar (VCDB fixado; NVD só para CVEs fora da cache)
python -m vcdb_pipeline run --schema-check  # também valida cada registo contra vcdb-merged.json (~2 min)
python -m vcdb_pipeline rules             # todas as regras, com a fonte de cada uma
python -m pytest -q tests/test_vcdb_pipeline.py
```

## Etapas

| Etapa | Módulo | O que garante |
|---|---|---|
| Download versionado | `download.py` | Só o commit fixado (`rules.VCDB_COMMIT`). O ficheiro é verificado pelo hash de blob do git **e** pelo SHA-256 antes de ser gravado; um hash diferente é erro, e nada fica em disco |
| Parser | `parse.py` | Um único JSON no zip, com raiz em lista (formato de `vcdb_to_joined.py`). A validação contra `vcdb-merged.json` é opcional e informativa |
| Normalização | `normalize.py` | Campos do contrato, copiados sem interpretar. Chave `plus.master_id` (D3). Duplicados vão para revisão, não são removidos |
| Extração de CVEs | `cves.py` | `CVE-EXTRACT-1..3`: só os campos `action.{hacking,malware}.cve`; IDs com 4 ou mais dígitos, sem truncar; valores sem ID vão para revisão, sem correção automática |
| Enriquecimento NVD | `nvd.py` | Pedidos em lotes de até 100 IDs, pausa de 6 s, novas tentativas em 403/429/503. Cache por CVE com envelope de proveniência (URL, datas, versão da API, SHA-256 do objeto); envelope adulterado é recusado |
| Rótulos | `labels.py` | `remediation_documented` ∈ {`patch`, `mitigation`, `none_tagged`} (D2). Os casos ambíguos vão para a fila. `cisaRequiredAction` é guardado, mas não decide (D5) |
| Saídas e hash | `pipeline.py`, `report.py` | JSONL ordenado com LF; `manifest.json` com os hashes das entradas e saídas e o **hash de reprodutibilidade**, que não depende da data de execução |

## Saídas (`data/vcdb/`, CC BY-SA 4.0)

| Ficheiro | Conteúdo | No git |
|---|---|---|
| `manifest.json` | Hash de reprodutibilidade, entradas e saídas | sim |
| `coverage.md`, `coverage.json` | Relatório de cobertura | sim |
| `review_queue.jsonl` | Pendências para revisão humana | sim |
| `vcdb_canonical.jsonl` | Um registo canônico por incidente (17,7 MB) | **não**: `run --offline` regenera-o em ~2 s com o mesmo hash |
| `review_decisions.jsonl` | **Escrito por um humano**; lido na execução seguinte | quando existir |

**Formato de uma decisão** (uma por linha). Só resolve um registo quando cobre **todas** as pendências dele:

```json
{"record_key": "<plus.master_id>", "reason_codes": ["TAG_BOTH", "CVE_SET_DISAGREES"],
 "decision": {"remediation_documented": "patch"}, "decided_by": "Nome", "decided_on": "AAAA-MM-DD", "note": "justificativa"}
```

`{"exclude": true}` no lugar de `remediation_documented` exclui o registo do conjunto rotulado.

## Resultado atual (hash `d806142b…`)

- 10 047 registos; 926 com CVE estruturada; 31 CVEs distintas, todas encontradas no NVD (1 pedido).
- **Rótulos automáticos em 174 incidentes:** `patch` 106, `none_tagged` 67, `mitigation` 1.
  - **Atenção:** `none_tagged` não é "sem remediação". Das CVEs `none_tagged`, 10 têm no KEV a ação "Apply updates per vendor instructions" (relatório de cobertura, secção D5).
- **Fila de revisão:** 1 517 pendências em 765 registos.

  | Código | Pendências |
  |---|---|
  | `TAG_BOTH` | 751 |
  | `CVE_SET_DISAGREES` | 750 (747 do MOVEit) |
  | `DUP_MASTER_ID` | 6 |
  | `CVE_FIELD_NO_ID` | 6 |
  | `CVE_ONLY_IN_TEXT` | 4 |

- **Validação contra `vcdb-merged.json`:** 104 registos falham, sobretudo por campos `plus.*` fora do schema. É informativo e não exclui nada.

Os testes (`tests/test_vcdb_pipeline.py`, 32) cobrem:
- cada regra, com casos positivos e negativos;
- a recusa por hash no download e num envelope NVD adulterado;
- lotes, pausa e novas tentativas do NVD, com sessão simulada;
- a aplicação das decisões humanas;
- o determinismo (duas execuções → os mesmos bytes e o mesmo hash);
- a mudança do hash quando muda a versão das regras;
- a regressão sobre os dados reais fixados.
