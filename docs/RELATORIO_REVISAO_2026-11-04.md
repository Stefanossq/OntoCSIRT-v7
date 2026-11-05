# Relatório de revisão e testes — OntoCSIRT v7 (pré-publicação no GitHub)

**Data:** 2026-11-04 · **Ambiente:** Windows 10, Python 3.13.2, OpenJDK 17.0.13 (Temurin), rdflib 7.6.0, Owlready2 0.46, pySHACL 0.40.1, pytest 9.2.0; Docker 29.8.0 (imagem `python:3.12-slim-bookworm` + OpenJDK 17)

**Veredito:** a ontologia **funciona como proposto**, localmente e no contentor Docker:
- é sintaticamente válida;
- é consistente no HermiT e no Pellet;
- é conforme às formas SHACL;
- responde às 8 questões de competência;
- o portão recusa os defeitos injetados;
- o webhook responde como o contrato descreve.

As 6 pendências de repositório encontradas na primeira passagem foram resolvidas antes da publicação (secção 3).

---

## 1. Checklist do que foi testado

Legenda: ✅ passou · ⚠️ passou com ressalva · ❌ falhou · ⏭️ não executado

### 1.1 Sintaxe e estrutura
| # | Verificação | Resultado |
|---|---|---|
| 1 | Todos os 12 ficheiros `.ttl` (raiz, `ontology/`, `tests/fixtures/`) são Turtle válido (rdflib) | ✅ 12/12 |
| 2 | SHA-256 da base do artigo `OntoCSIRT_v7.ttl` = `8c2fc5f00fae…` (o README diz que nunca muda) | ✅ confere |
| 3 | `backup/v7_original_2026-11-03/SHA256SUMS.txt` | ✅ 11/11 OK |
| 4 | Métricas da base: 1323 triplas, 28 classes, 30 propriedades, 8 regras SWRL | ✅ batem com o README |
| 5 | Todas as classes e propriedades do domínio têm `rdfs:label`; todas as classes têm `rdfs:comment` | ✅ (só faltam rótulos em `dcterms:*` e em 3 anotações: `stixType`, `verificationNote`, `verisCategory`) |
| 6 | Cabeçalho `owl:Ontology` com `versionIRI`, `versionInfo`, licença CC BY 4.0, data | ⚠️ `dcterms:creator "Nome do Aluno"` é um marcador por preencher |

### 1.2 Perfil OWL 2 DL (heurísticas, sobre a base, a composição de produção e a de bug bounty)
| # | Verificação | Resultado |
|---|---|---|
| 7 | Nenhuma propriedade declarada como objeto e dado (ou objeto e anotação) ao mesmo tempo | ✅ 0 |
| 8 | Nenhuma propriedade de objeto com literal; nenhuma propriedade de dados com IRI | ✅ 0 |
| 9 | Nenhum predicado usado sem declaração; nenhuma classe usada sem declaração | ✅ 0 |
| 10 | Verificador formal de perfil (OWL API) | ⏭️ não disponível no ambiente; as heurísticas acima não substituem o verificador |

### 1.3 Raciocínio (HermiT e Pellet) e SHACL, por composição
| Composição | Triplas | HermiT | Classes insatisfazíveis | Pellet (+SWRL) | SHACL (todas as formas) |
|---|---|---|---|---|---|
| A. Base do artigo | 1323 | ✅ consistente (1,2 s) | 0 | ✅ consistente (2,8 s) | ✅ conforme |
| B. Base + ext + evo | 1514 | ✅ | 0 | ✅ | ✅ |
| C. Real + ext + evo | 2080 | ✅ | 0 | ✅ | ✅ |
| D. Produção (real + adquiridos + ext + evo) | 2479 | ✅ | 0 | ✅ (5,8 s) | ✅ |
| E. Bug bounty composto | 2570 | ✅ | 0 | ⚠️ consistente; 8 linhas da saída do Pellet descartadas na leitura | ✅ |

A ressalva de E é uma limitação conhecida do Owlready2 0.46: o leitor da saída do Pellet parte literais com vírgulas. O código já conta e descarta essas linhas (`ontocsirt_v7.run_pellet`). A consistência não é afetada, mas 8 triplas inferidas podem faltar nas consultas sobre o módulo de bug bounty.

### 1.4 Questões de competência
| # | Verificação | Resultado |
|---|---|---|
| 11 | CQ1–CQ8 sobre a base inferida pelo Pellet, conjunto obtido = conjunto esperado | ✅ 8/8 |

### 1.5 Testes negativos (o portão tem de recusar)
| # | Defeito injetado | Quem detetou | Resultado |
|---|---|---|---|
| N1 | Incidente sem ator, ação, ativo, atributo nem vulnerabilidade | SHACL (5 violações) | ✅ recusado |
| N2 | CVSS 12,5 e CVE `CVE-24-1` | SHACL (2 violações) | ✅ recusado |
| N3 | `Incident_01` também tipado como `Asset` (classes disjuntas) | HermiT e Pellet: inconsistente | ✅ recusado |
| N4 | Classe subclasse de duas categorias de fraqueza disjuntas | HermiT: `BadClass` insatisfazível | ✅ recusado |
| N5 | Nível de risco `"Catastrophic"` | SHACL | ✅ recusado |
| N6 | Ator interno e externo ao mesmo tempo | HermiT e Pellet: inconsistente | ✅ recusado |
| N7 | `validar_ingestao.py --selftest` (8 casos do projeto, incluindo um que **deve passar**) | SHACL, SHACL-SPARQL, Pellet, HermiT | ✅ 8/8 |

### 1.6 Webhook SOAR (local, sem rede, sobre uma cópia dos dados adquiridos)
| # | Verificação | Resultado |
|---|---|---|
| 12 | `GET /health` | ✅ `{"status":"ok","kb":"OntoCSIRT_v7_real.ttl","incidents":19,"reasoner":"pellet"}` |
| 13 | `POST /alert` sem token e com token errado | ✅ 401 nos dois casos |
| 14 | `POST /alert` com JSON inválido | ✅ 400 `"JSON invalido"` |
| 15 | `POST /alert` válido (CVE-2024-3400, `--no-nvd-enrich`) | ✅ 200, `CoA_Patch`, Pellet consistente, `requires_human_approval: true`, ~4 s |
| 16 | Alerta sem `src_ip` | ✅ recusado: `"src_ip ausente ou invalido"` |
| 17 | O ficheiro `OntoCSIRT_v7_acquired.ttl` do repositório não foi alterado pelos testes | ✅ |
| 18 | `openapi.yaml` é um documento OpenAPI 3.1 válido | ✅ |
| 19 | Enriquecimento NVD ao vivo, local | ⏭️ testado ao vivo só no contentor (D-20); localmente, a suíte pytest cobre-o com registos guardados |
| 20 | Enriquecimento NVD ao vivo no contentor (CVE-2024-3400) | ✅ consultou a API, criou `Vuln_CVE_2024_3400` com CWE-77, `CommandInjectionWeakness` e CVSS 10.0, validou e gravou (`status: written`). Recomendou `CoA_Patch` com risco Critical em 7,7 s |

### 1.6b Docker
| # | Verificação | Resultado |
|---|---|---|
| D1 | `docker build --no-cache` | ✅ 2 min; o teste dos raciocinadores na construção passou (HermiT 0,9 s, Pellet 2,3 s: consistente); imagem de 677 MB |
| D2 | `docker compose up -d`; healthcheck | ✅ `healthy`; publicado só em `127.0.0.1:8088` |
| D3 | `/health`; `/alert` sem token | ✅ 200 e 401 |
| D4 | Alerta com CVE já na base (CVE-2023-34362) | ✅ `Isolate asset`, Critical, Pellet consistente, 4,0 s |
| D5 | Persistência: depois de `docker compose restart`, a CVE-2024-3400 já está no volume | ✅ `nvd_enrichment: null`, 3,8 s |
| D6 | O serviço corre como utilizador sem privilégios e a base do artigo é só de leitura | ✅ `uid=1000(ontocsirt)`; `touch OntoCSIRT_v7.ttl` → `Permission denied` |
| D7 | `verificar_ontologia.py` no contentor | ✅ 40/40 |
| D8 | Suíte pytest no contentor (Linux, com o teste POSIX que no Windows é ignorado) | ✅ **108 passaram, 0 ignorados, 0 falhas** em 7 min 56 s |

### 1.7 Suíte automática do projeto
| # | Verificação | Resultado |
|---|---|---|
| 21 | `python -m pytest -q tests` (sem rede, sem chaves) | ✅ **107 passaram, 1 ignorado, 0 falhas** em 6 min 55 s. O teste ignorado é o de permissões POSIX (`test_nvd_enricher.py:161`), que só corre em Linux, como o README indica. Os ~22 900 avisos são `DeprecationWarning` do rdflib, sem efeito no resultado |
| 21a | Suíte local repetida depois das correções de repositório (secção 3) | ✅ 107 passaram, 1 ignorado, 0 falhas em 7 min 42 s |
| 21b | Os testes não alteraram os ficheiros do projeto (datas de modificação; o SHA da base continua `8c2fc5f00fae…`) | ✅ |
| 22 | Todos os `.py` compilam (`py_compile`) | ✅ |

---

## 2. O que a suíte pytest cobre (por ficheiro)

- `test_v7_regression.py`: números do artigo (CQ 8/8, regras 20/20, mutações 10/10, LOOCV) e o SHA da base.
- `test_ingest_gate.py`, `test_acceptance.py`: portão SHACL + HermiT + Pellet e a aceitação de ponta a ponta.
- `test_cases.py`, `test_enrich.py`, `test_nvd_enricher.py`: aquisição de casos e CVEs; NVD com cache de 24 h, limite de pedidos, timeouts e fallback.
- `test_evolution.py`, `test_taxonomy.py`: evolução estrutural (propor, aprovar, aplicar, reverter) e hierarquia/Wu-Palmer.
- `test_gemini_client.py`: cliente Gemini com respostas simuladas.
- `test_openapi.py`: o contrato contra respostas reais do webhook.
- `test_bugbounty.py`, `test_bugbounty_ingest.py`: módulo OntoBugBounty.
- `test_project_state.py`: o estado real do projeto (a base composta é consistente e conforme e mantém as 8 CQs).

---

## 3. Pendências de repositório (resolvidas antes da publicação)

| Pendência encontrada | O que foi feito |
|---|---|
| E-mail pessoal nos dados de proveniência | Trocado por "Stefano Camargo" em `OntoCSIRT_v7_evo.ttl`, `evolution/CHANGELOG.json`, `evolution/proposals/*.json` e `evolution/backups/`. O e-mail fica só no `.tex` do artigo, como é normal numa submissão |
| Caminhos absolutos do Windows com o nome de utilizador | Trocados por caminhos relativos em `evidence_v7/ingest.json` e `evolution/proposals/*.json`. O código passou a gravá-los relativos (`ontoevo/proposals.py`, `ingest_real_cases.py`) |
| Faltava `LICENSE` | `LICENSE` (MIT, código) e `LICENSE-ONTOLOGIA.md` (CC BY 4.0 e termos das fontes de terceiros em `cache/`) |
| Faltava `.gitignore` | Criado: `.env`, `__pycache__/`, caches de execução, cópias de teste em `evolution/backups/` e as cópias do artigo dentro de `ontology/` |
| Marcador `"Nome do Aluno"` | A base `OntoCSIRT_v7.ttl` não foi alterada, porque o SHA-256 dela está citado no artigo. O autor está no README e em `CITATION.cff` |
| Cópias do artigo em `ontology/` | Ficam no disco, mas fora do repositório (`.gitignore`); a fonte é `artigo/` |

Acrescentados também:
- `verificar_ontologia.py`: checklist de 40 itens para a banca, em cerca de 1 minuto;
- uma secção "Para a banca" no README;
- um workflow de CI (`.github/workflows/testes.yml`), que corre a verificação, a suíte pytest, a imagem Docker e o webhook a cada push.

Depois destas mudanças, a suíte pytest local foi repetida (secção 1.7).

Outras observações (opcionais):
- **IRI** `http://www.semanticweb.org/ontocsirt` é o espaço padrão do Protégé e não resolve. Para uma ontologia pública, considere um IRI persistente (w3id.org) ou GitHub Pages. Mudar o IRI mexe em todos os ficheiros e no SHA da base; pode ficar para uma v8.
- **Dados de terceiros em `cache/`** (KEV, CTID, ATT&CK, CWE, Bugcrowd VRT, NVD): convém um `cache/README.md` com a origem e a licença de cada um (o aviso do NVD já está no README).
- **Comentário histórico** em `OntoCSIRT_v7_evo.ttl`: "rascunho … aguarda revisao" ao lado de "aprovado por … em 2026-11-03". O rascunho foi revisto e aprovado depois; o comentário regista o estado em que a proposta entrou.
- **Ajuda do `--once`** em `soar_webhook.py`: recebe o JSON em linha, não um caminho de ficheiro. Vale dizê-lo no `--help`.
- **Tamanho**: 6,3 MB no total; o maior ficheiro é `cache/kev.json` (1,5 MB). Cabe no GitHub sem LFS.
- **Cópias de trabalho**: `staging_ingest.ttl` e `evolution/backups/` são artefactos de execução. Pode mantê-los como evidência ou ignorá-los no `.gitignore`.

---

## 4. Como reproduzir esta revisão

```bash
python -m pytest -q tests
python validar_ingestao.py --selftest
python ontocsirt_v7.py consistency
python verificar_ontologia.py
docker build -t ontocsirt-webhook:7 . && docker run --rm --entrypoint python ontocsirt-webhook:7 -m pytest -q tests
```

Os scripts independentes usados aqui (análise sintática, composições, testes negativos N1–N6, heurísticas DL) ficaram fora do projeto, na pasta temporária da sessão. Os resultados estão nas tabelas acima.
