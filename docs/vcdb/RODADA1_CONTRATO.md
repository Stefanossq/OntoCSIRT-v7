# VCDB → OntoCSIRT — Rodada 1: inspeção e contrato de dados

**Estado:** D1–D6 aprovadas pelo autor em 2026-11-05 e implementadas em `vcdb_pipeline/` (ver [`README.md`](README.md)) · **Data da inspeção:** 2026-11-05 (UTC)

Cada afirmação traz uma fonte. As fontes estão abreviadas no fim do documento ([S1]…[S12]). Um "**[obs]**" indica uma contagem que medi sobre o ficheiro fixado na secção 1. Nada aqui é um campo ou mapeamento que não esteja numa fonte. As lacunas estão marcadas como **LACUNA**.

---

## 1. Versão fixada da fonte

| Item | Valor | Fonte |
|---|---|---|
| Repositório | `github.com/vz-risk/VCDB`, ramo `master` | [S1] |
| Commit fixado | `f6f98c00f66ab35f5b49977a5852ce94a5bb31d1` (2026-09-30T16:43:20Z) | API do GitHub, `commits/master` |
| Ficheiro de dados | `data/joined/vcdb.json.zip`, último commit `732aaa90…` (2026-07-31, "workflow commit") | API do GitHub, `commits?path=` |
| Integridade | blob git `647a5291…` = `git hash-object` do ficheiro descarregado ✅; SHA-256 `e4be5dd432ccfad16520a6b60dd83e9d47c63b0f3352c26c4d43a5dd774c32c0`; 4 631 957 bytes; contém um único `vcdb_1-of-1.json` (21 541 502 bytes) | medido |
| Schema | `vcdb-merged.json` no mesmo commit, SHA-256 `3ff233db…f21b` | [S2] |
| Licença | CC BY-SA 4.0 (`LICENSE.txt`) | [S3] |

**Consequência da licença.** Tudo o que for derivado do VCDB (o ficheiro canônico, a fila de revisão e futuros `.ttl`) tem de ser publicado em **CC BY-SA 4.0**, com atribuição, num ficheiro separado da ontologia, que é CC BY 4.0 [S3].

## 2. (a) Ficheiros e schema real

### 2.1 Ficheiros relevantes no commit fixado

| Caminho | O que é | Fonte |
|---|---|---|
| `vcdb-merged.json` | Schema + enumerações; "**this is the file incidents are validated against**" | [S4] |
| `vcdb.json`, `vcdb-labels.json` | Schema e rótulos gerados | [S4] |
| `vcdb_diff.json`, `vcdb_diff-labels.json` | Deltas sobre o `verisc.json` do repositório `vz-risk/veris` | [S4] |
| `data/json/{submitted,validated,overridden}/` | Um JSON por incidente, por estágio de validação | [S5] |
| `data/joined/vcdb.json.zip` | JSON único com a lista de incidentes, construído **só** de `validated` + `overridden` | [S4], [S5] |
| `data/joined/NOTE.txt` | O joined **exclui ~5 000 *web skimmers*** descobertos por script, "will therefore bias the dataset" | [S6] |
| `bin/vcdb_to_joined.py` | Junta os JSON; `-r` inclui a subpasta dos *skimmers* | [S4], [S7] |
| `campaigns.md` | Registo dos UUID de `campaign_id` | [S4] |

**Decisão proposta:** usar o `data/joined/vcdb.json.zip`, e não os ficheiros individuais (o repositório tem 1,6 GB). Razões:
- é o artefacto que o próprio VCDB valida e publica [S5];
- herda a exclusão dos *skimmers* recomendada em [S6].

### 2.2 Schema (JSON Schema draft-04, `vcdb-merged.json`)

- **Campos obrigatórios** (`required`): `actor`, `action`, `discovery_method`, `schema_version`, `asset`, `timeline`, `incident_id`, `security_incident`, `summary` [S2].
- **Raiz:** 28 propriedades, `additionalProperties` declarado [S2].
- **Versões nos dados [obs]:** o schema declara 1.4.0 ("This should be 1.4.0 for this schema" [S2]), mas os 10 047 registos têm `1.4.0` (9 907), `1.4.1` (111), `1.3.7` (26), `1.3.5` (2) e `1.3.6` (1).

### 2.3 Problemas de qualidade encontrados nos dados [obs]

| Achado | Medida | Fonte que contradiz ou explica |
|---|---|---|
| **`incident_id` não é único** | 23 valores repetidos em 67 registos; só 2 grupos são cópias idênticas; os outros são incidentes diferentes (p.ex. Envoy Air, Stellantis, iiNet sob `6512BD43…`); 1 `incident_id` tem 5 caracteres | Contradiz [S4] ("keyed by `incident_id` (a UUID, matching its filename)") |
| `plus.master_id` quase único | 10 044 valores em 10 047 registos | [S2] (`plus.master_id`) |
| `corrective_action` vazio | **0 de 10 047** (o campo existe no schema [S2]) | — |
| `cost_corrective_action` | 16 de 10 047 | [S2] |
| Amostragem não aleatória | `plus.sub_source`: `phidbr` 1 310, `priority` 602, `covid19` 25 | [S4]: "Sampling bias is real and intentional in places" |
| Estado de análise | `First pass` 4 982 · `Finalized` 2 595 · `Reviewed` 2 109 · ausente 306 · `Ready for review` 51 · `Ineligible` 4 | Enumeração em [S2] |
| `security_incident` | `Confirmed` 9 966 · `Suspected` 73 · `Near miss` 8 | [S2] |

---

## 3. (b) Contrato canônico proposto, campo por campo

**Unidade:** um registo canônico por registo do joined. Nada é deduplicado silenciosamente.

**Saídas:** `vcdb_canonical.jsonl` (uma linha por incidente, chaves ordenadas) e `review_queue.jsonl`.

| Campo canônico | Origem VERIS (caminho exato) | Tipo / domínio | Regra | Justificativa e fonte |
|---|---|---|---|---|
| `record_key` | `plus.master_id` | UUID (texto) | Chave primária; um valor repetido vai para revisão (`DUP_MASTER_ID`) | Único em 10 044/10 047 [obs]; o `incident_id` não serve (2.3) |
| `incident_id` | `incident_id` | texto | Copiado; um valor repetido gera a marca `dup_incident_id: true`, não uma exclusão | Obrigatório [S2]; não é único [obs] |
| `schema_version` | `schema_version` | texto | Copiado; ≠ `1.4.x` gera um aviso | [S2] |
| `security_incident` | `security_incident` | enum `Confirmed`, `Suspected`, `Near miss`, `False positive` | Copiado | Enumeração [S2] |
| `confidence` | `confidence` | enum `High`, `Medium`, `Low`, `None` ou nulo | Copiado | [S2] |
| `summary` | `summary` | texto | Copiado sem alteração; 519 vazios [obs] ficam vazios | Obrigatório [S2] |
| `reference` | `reference` | texto | Copiado (URL ou ID, sem validação) | "url, incident number, case ID, or other reference" [S2] |
| `year`, `month`, `day` | `timeline.incident.{year,month,day}` | inteiros; `year` obrigatório (1950–2050 no schema) | Copiado; `year` < 1950 vai para revisão (`YEAR_OUT_OF_SCHEMA`) | [S2]; [obs]: há `1971`, `1984`, …, todos ≥ 1950 ✔ (confirmar na implementação) |
| `actor_categories` | chaves de `actor` ⊆ `external`, `internal`, `partner`, `unknown` | lista ordenada | Lista das chaves presentes | [S2] |
| `actor_varieties` | `actor.<cat>.variety[]` | lista de pares `(cat, variety)` | Copiado; enumerações de [S2] | [S2] |
| `action_categories` | chaves de `action` | lista | Copiado | [S2]; [obs]: `hacking` 3 368, `error` 2 681, `misuse` 1 789, `malware` 1 647, `physical` 1 626, `social` 647, `unknown` 287, `environmental` 10 |
| `action_varieties`, `action_vectors` | `action.<cat>.variety[]`, `.vector[]` | listas de pares | Copiado | [S2] |
| `asset_varieties` | `asset.assets[].variety` | lista (p.ex. `S - Web application`) | Copiado; o prefixo antes de `" - "` vai para `asset_class` | Enumeração em [S2]; [obs] |
| `attributes` | chaves de `attribute` ⊆ `confidentiality`, `integrity`, `availability`, `unknown` | lista | Copiado | [S2] |
| `data_disclosure` | `attribute.confidentiality.data_disclosure` | enum do schema | Copiado | [S2] |
| `discovery` | `discovery_method.<ext/int/partner/unknown>.variety[]` | lista de pares | Copiado | Obrigatório [S2] |
| `industry_naics` | `victim.industry` | texto (2–6 dígitos, padrão em [S2]) | Copiado; não é truncado | [S2] |
| `victim_country` | `victim.country[]` | lista | Copiado | [S2] |
| `campaign_id` | `campaign_id` | texto ou nulo | Copiado | [S2]; 192 registos, 13 campanhas [obs] |
| `sub_source` | `plus.sub_source` | texto ou nulo | Copiado; **obrigatório no relatório de cobertura** (viés) | [S4] |
| `analysis_status` | `plus.analysis_status` | enum de [S2] | Copiado | [S2] |
| `cve_raw` | `action.hacking.cve`, `action.malware.cve` | texto livre (lista de `{campo, valor}`) | Copiado literalmente | Os dois campos existem, `type: string` [S2] |
| `cves` | derivado de `cve_raw` | lista ordenada de `CVE-AAAA-NNNN+` | Regra `CVE-EXTRACT-1` (secção 4) | — |
| `cve_mentions_text` | `summary`, `reference`, `action.hacking.notes` | lista | Só informativo; **não** entra em `cves` | 9 + 2 + 1 registos [obs] |
| `labels` | NVD (secção 5) | ver a secção 5 | Regras `LABEL-*` | — |
| `provenance` | — | objeto | Commit e SHA-256 da fonte; versão das regras; para cada CVE, o SHA-256 do registo NVD e o `timestamp` da resposta | — |

**Campos que ficam deliberadamente de fora** (podem entrar depois, por decisão):
- `impact.*`: 57 % `Unknown` e 40 % ausente [obs];
- `timeline.containment`: 11 % preenchido [obs];
- `plus.attribute.confidentiality.credit_monitoring`: `Yes` 579 / `No` 140 [obs].

Este último é um **desfecho de resposta real** registado pelo VCDB [S2] e é candidato a rótulo independente do NVD (decisão D4).

---

## 4. (c) Extração de CVEs e enriquecimento NVD

### 4.1 Onde estão as CVEs [obs]

| Campo | Registos com padrão `CVE-\d{4}-\d{4,}` |
|---|---|
| `action.hacking.cve` | 851 |
| `action.malware.cve` | 163 |
| `summary` | 9 |
| `reference` | 2 |
| `action.hacking.notes` | 1 |

**No total:** 926 incidentes têm pelo menos uma CVE em campo estruturado, com **31 CVEs distintas**. A concentração é extrema:
- **747** incidentes (MOVEit) partilham `CVE-2023-34362; CVE-2023-35036; CVE-2023-35708`, sem `campaign_id` preenchido;
- 88 partilham um conjunto de 5 CVEs;
- 60 partilham 2 CVEs.

### 4.2 Regras de extração (versão `cve-extract-1`)

| ID | Regra | Evidência |
|---|---|---|
| `CVE-EXTRACT-1` | Em `action.hacking.cve` e `action.malware.cve`, extrair todas as ocorrências de `CVE-\d{4}-\d{4,}`, deduplicar e ordenar | O schema diz "CVE(s) exploited", `string` [S2]. Separadores observados: `; `, `, `, `,` e `;`. O formato de ID é o do CVE Program [S8] |
| `CVE-EXTRACT-2` | Valor não vazio **sem** nenhum ID → revisão humana (`CVE_FIELD_NO_ID`), nunca mapeamento automático | [obs]: `cve unknown` (2), `Wordpress`, `CVE 2012-4792` (falta o hífen), `Unknown vuln`, `Heartbleed` |
| `CVE-EXTRACT-3` | IDs em `summary`, `reference` e `notes` não entram em `cves`; vão para `cve_mentions_text`. Se o campo estruturado estiver vazio e houver menções, o registo vai para revisão (`CVE_ONLY_IN_TEXT`) | Fora dos campos que o schema reserva a CVEs [S2] |
| `CVE-EXTRACT-4` | ID extraído que o NVD não devolve → revisão (`CVE_NOT_IN_NVD`) | `cveIds` "will not accept {CVE-IDs} for vulnerabilities not yet received by the NVD" [S9] |

**Não proposto:** corrigir automaticamente `CVE 2012-4792` → `CVE-2012-4792`, ou `Heartbleed` → `CVE-2014-0160`. Seria inferência sem regra da fonte, por isso vai para revisão.

### 4.3 Enriquecimento NVD

| Aspecto | Proposta | Fonte |
|---|---|---|
| Endpoint | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=<lista>` (até 100 IDs por pedido); `cveId` está obsoleto | [S9] |
| Limites | 5 pedidos por 30 s sem chave, 50 com chave (cabeçalho `apiKey`); pausa de 6 s entre pedidos | [S10] |
| Volume | 31 CVEs, ou seja, 1 pedido | [obs] |
| Cache | Um ficheiro por CVE: `cache/vcdb/nvd/<CVE>.json`, com um envelope de proveniência `{request_url, retrieved_at, response_timestamp, nvd_api_version, sha256_of_cve_object, cve: {...}}` | O `timestamp` e a `version` vêm na resposta [obs]. A cache atual do projeto (`cache/nvd/`) guarda só o objeto `cve`, sem data nem URL [obs], por isso **não é reutilizada** |
| Modo offline | `--offline` lê só a cache; uma CVE em falta vai para revisão | Reprodutibilidade |
| Esquema da resposta | Validar contra `cve_api_json_2.0.schema` ("JSON Schema for NVD Vulnerability Data API version 2.2.4"); `reference = {url (obrig.), source, tags: [string]}` | [S11] |
| Campos usados | `references[].tags`, `vulnStatus`, `lastModified`, `cisaRequiredAction` (só presente se estiver no KEV) | [S9], [S11] |
| Aviso | "This product uses data from the NVD API but is not endorsed or certified by the NVD." | [S10] |

**Amostra real** (1 pedido em 2026-11-05T01:57:45Z, guardado em `cache/vcdb/inspecao/nvd_31cves_2026-11-05T015745Z.json`, SHA-256 `0598ce78…ed07c`):
- 31/31 encontradas: 26 `Analyzed`, 5 `Modified`; 26 no KEV.

---

## 5. (d) Tags do NVD → rótulo: evidência e lacunas

### 5.1 O que a fonte diz sobre as tags

- **Função das tags:** "Each reference within this object provides one or more resource tags (e.g., third-party advisory, vendor advisory, technical paper, press/media, VDB entries). Resource tags are **designed to categorize the type of information each reference contains**." [S9]
- **Quem controla as referências:** "References for a CVE are provided through the CVE list, the NVD does not have direct control over them." [S12]
- **Formato:** o schema declara `tags` como `array` de `string`, **sem enumeração** [S11].

**LACUNA L-1.** Não encontrei uma definição oficial publicada de cada tag (o que conta como `Patch` ou `Mitigation`). Procurei nas páginas [S9], [S10] e [S12]. O significado tem de ficar restrito ao nome da tag e à frase de [S9]: a referência **contém** informação desse tipo.

**LACUNA L-2 (a mais importante).** As tags descrevem a **CVE** e os documentos sobre ela, não o que a **vítima fez** no incidente. Nenhuma fonte liga "a CVE tem uma referência `Patch`" a "o CSIRT aplicou um patch". O rótulo tem de ter o nome do que mede: **remediação documentada para a CVE**, e não "resposta tomada". Chamar-lhe `CoA_Patch` na ontologia seria uma afirmação que a fonte não sustenta (decisão D2).

### 5.2 Tags observadas [obs]

Nas 31 CVEs do VCDB:

| Tag | CVEs |
|---|---|
| US Government Resource | 28 |
| Third Party Advisory | 28 |
| Vendor Advisory | 27 |
| Broken Link | 25 |
| VDB Entry | 19 |
| **Patch** | **16** |
| Exploit | 15 |
| Mailing List | 9 |
| Issue Tracking | 7 |
| Product | 5 |
| Not Applicable | 4 |
| **Mitigation** | **4** |
| Permissions Required | 3 |
| Release Notes | 2 |
| Press/Media Coverage | 1 |

Combinações de `Patch`/`Mitigation` por CVE:

| Combinação | CVEs |
|---|---|
| Nenhuma das duas | 14 |
| Só `Patch` | 13 |
| `Patch` + `Mitigation` | 3 |
| Só `Mitigation` | 1 |

### 5.3 Regras propostas (versão `label-1`)

O rótulo é calculado primeiro por CVE e depois agregado por incidente.

| ID | Regra | Saída | Evidência |
|---|---|---|---|
| `LABEL-CVE-1` | Só `Patch` | `remediation_documented = patch` | Nome da tag + [S9] |
| `LABEL-CVE-2` | Só `Mitigation` | `remediation_documented = mitigation` | Nome da tag + [S9] |
| `LABEL-CVE-3` | `Patch` e `Mitigation` | **revisão** (`TAG_BOTH`) | Duas categorias; nenhuma fonte define precedência |
| `LABEL-CVE-4` | Nenhuma das duas | `remediation_documented = none_tagged`. **Não** é "sem remediação": a ausência de tag não prova a ausência de patch | [S12]: as referências vêm da CVE List, não são exaustivas |
| `LABEL-CVE-5` | Tag `Patch` ou `Mitigation` só em referências também marcadas `Broken Link` | **revisão** (`TAG_ON_BROKEN_LINK`) | A tag `Broken Link` aparece em 25/31 CVEs [obs]; o efeito sobre a evidência não está documentado (**LACUNA L-3**) |
| `LABEL-INC-1` | Todas as CVEs do incidente com o mesmo valor | Esse valor | — |
| `LABEL-INC-2` | CVEs do incidente com valores diferentes | **revisão** (`CVE_SET_DISAGREES`) | [obs]: MOVEit = {`none_tagged`, `none_tagged`, revisão}, ou seja, **747 incidentes** em revisão |
| `LABEL-INC-3` | Incidente sem CVE | Sem rótulo NVD (`no_cve`) | 9 121 registos [obs] |

**Fonte secundária, só registada (não decide nesta versão):** o `cisaRequiredAction` do KEV, que vem na resposta do NVD [S9].
- Valores observados: "Apply updates per vendor instructions." e "Apply mitigations per vendor instructions, follow applicable BOD 22-01…" [obs].
- **LACUNA L-4:** é texto livre, sem enumeração publicada. Mapeá-lo exigiria uma regra de texto que a fonte não define. Proponho guardá-lo e medir a concordância com `LABEL-CVE-*` no relatório de cobertura, sem o usar como rótulo.

### 5.4 Viabilidade (números a confirmar na Rodada 2)

- Dos 926 incidentes com CVE: **747** vão para revisão (MOVEit, `LABEL-INC-2`).
- Restam cerca de **179** com rótulo automático, concentrados em poucos conjuntos de CVEs (88 + 60 + 11 + …).
- **Risco de fuga de informação** numa futura avaliação de CBR: incidentes com o mesmo conjunto de CVEs têm o mesmo rótulo por construção. A avaliação terá de agrupar por conjunto de CVEs. Fica registado; não é implementado nesta fase.

---

## 6. Revisão humana: formato da fila

`review_queue.jsonl`, uma linha por pendência:

```json
{"record_key": "...", "rule_id": "...", "reason_code": "...", "evidence": {...}, "rules_version": "...", "decision": null}
```

**Códigos:** `DUP_MASTER_ID`, `YEAR_OUT_OF_SCHEMA`, `CVE_FIELD_NO_ID`, `CVE_ONLY_IN_TEXT`, `CVE_NOT_IN_NVD`, `TAG_BOTH`, `TAG_ON_BROKEN_LINK`, `CVE_SET_DISAGREES`.

**Decisões humanas:** num ficheiro separado (`review_decisions.jsonl`), lido na execução seguinte. O pipeline nunca as escreve.

## 7. Reprodutibilidade e cobertura (a implementar na Rodada 2)

- **Hash de reprodutibilidade:** SHA-256 de `vcdb_canonical.jsonl` + `review_queue.jsonl`, serializados com chaves ordenadas e LF, e calculado em função de:
  - SHA-256 da fonte VCDB;
  - SHA-256 de cada envelope NVD;
  - versão das regras.

  O teste de determinismo corre duas vezes em modo offline e exige o mesmo hash.
- **Relatório de cobertura:**
  - preenchimento de cada campo canônico;
  - distribuição por `sub_source` e `analysis_status`;
  - incidentes com CVE, CVEs distintas e concentração por conjunto;
  - rótulos por regra e pendências por código;
  - concordância entre as tags e o `cisaRequiredAction`.

## 8. Decisões que preciso que aprove

| # | Decisão | Proposta |
|---|---|---|
| D1 | Fonte | `data/joined/vcdb.json.zip` no commit `f6f98c00…`, sem os *web skimmers* |
| D2 | Nome e semântica do rótulo | `remediation_documented` ∈ {`patch`, `mitigation`, `none_tagged`}; **não** mapear para `CoA_*` nesta fase (L-2) |
| D3 | Chave primária | `plus.master_id`; o `incident_id` fica só como atributo |
| D4 | Rótulo independente do NVD | Incluir também `credit_monitoring` (`Yes`/`No`) como segundo rótulo de **resposta real**? Proposta: incluir só no contrato canônico, sem regra de rótulo, até decisão |
| D5 | `cisaRequiredAction` | Registar e medir a concordância, sem decidir (L-4) |
| D6 | Licença dos derivados | CC BY-SA 4.0, em `data/vcdb/` com `LICENSE` próprio |

---

## Fontes

- **[S1]** `https://github.com/vz-risk/VCDB` (API do GitHub: commit `f6f98c00f66ab35f5b49977a5852ce94a5bb31d1`)
- **[S2]** `vcdb-merged.json` @ `f6f98c00` (`cache/vcdb/schema/f6f98c00…/vcdb-merged.json`)
- **[S3]** `LICENSE.txt` @ `f6f98c00` (CC BY-SA 4.0)
- **[S4]** `CLAUDE.md` @ `f6f98c00` (secções "Layout that matters", "The validation pipeline", "Conventions & gotchas")
- **[S5]** `data/json/README` @ `f6f98c00`
- **[S6]** `data/joined/NOTE.txt` @ `f6f98c00`
- **[S7]** `bin/vcdb_to_joined.py` @ `f6f98c00` (argumentos `-i`, `-o`, `-z`, `-r`)
- **[S8]** CVE Program, "CVE ID Syntax Change" (arquivado), `https://www.cve.org/Resources/Media/Archives/OldWebsite/cve/identifiers/syntaxchange.html`, e "Technical Guidance for Handling the New CVE ID Syntax", `…/tech-guidance.html`. A parte sequencial tem 4 ou mais dígitos, e as ferramentas não devem truncar um ID de 5 dígitos para 4. Por isso a expressão regular usa `\d{4,}` e não pode ser seguida de um dígito (âncora `(?!\d)` na implementação)
- **[S9]** NVD, "Vulnerability APIs", `https://nvd.nist.gov/developers/vulnerabilities` (lido em 2026-11-05): parâmetro `cveIds`, objeto `references`, campos do KEV
- **[S10]** NVD, "Start Here", `https://nvd.nist.gov/developers/start-here` (atualizado em 2025-02-25): limites, pausa de 6 s, aviso de uso
- **[S11]** `https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema` ("version 2.2.4"), definição `reference`
- **[S12]** NVD, "Vulnerability Detail Pages", `https://nvd.nist.gov/vuln/vulnerability-detail-pages`, secção "References"
