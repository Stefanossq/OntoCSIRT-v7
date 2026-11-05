> Conteúdo do README.md anterior (até 2026-11-04), preservado sem alterações: resultados de referência do artigo, módulos de ingestão real, avisos metodológicos sobre os dados do KEV e a primeira descrição do `ontoevo`. Os caminhos referem-se à raiz do projeto. O README atual (raiz) foca a replicação.

# OntoCSIRT v7

Ontologia OWL 2 DL com regras SWRL para análise de incidentes de cibersegurança e recuperação de casos de resposta, com processamento reproduzível e o artigo no template da SBC.

## Conteúdo

| Arquivo | O que é |
|---|---|
| `OntoCSIRT_v7.ttl` | Ontologia (TBox, base de 24 casos e as 8 regras SWRL, que vivem só aqui) |
| `shapes_v7.ttl` | Restrições SHACL de mundo fechado |
| `ontocsirt_v7.py` | Processamento e avaliação (Owlready2 + Pellet + HermiT + rdflib + pySHACL) |
| `evidence_v7/` | Evidências JSON de cada etapa e `SUMMARY.json` |
| `artigo/artigo_ontocsirt_v7.tex` | Artigo (SBC), lê `numbers_v7.tex` e `tab_scenario.tex` gerados pelo script |
| `artigo/refs_v7.bib` | Referências |
| `artigo/sbc-template.sty` | **Reconstrução** do estilo SBC só para medir páginas; substitua pelo oficial |
| `artigo/preview_artigo_ontocsirt_v7.pdf` | Pré-visualização compilada com o estilo reconstruído e `apalike` |
| `OntoCSIRT_v7_ext.ttl` | Extensão só aditiva: `UnknownActor` (VERIS actor.Unknown), 2 categorias de CWE, proveniência KEV/ATT&CK, campos de alerta |
| `shapes_ingest.ttl` | SHACL extra: CVE duplicado, ator duplicado (SHACL-SPARQL), ATT&CK mal formado, proveniência do caso |
| `ingest_real_cases.py` | ETL CISA KEV + CTID (KEV→ATT&CK) + NVD → incidentes e casos |
| `validar_ingestao.py` | Portão SHACL (+Pellet) antes de gravar; `--selftest` injeta 6 defeitos |
| `soar_webhook.py` | Serviço HTTP `POST /alert` para Shuffle/XSOAR: incidente → Pellet → CBR → JSON |
| `OntoCSIRT_v7_real.ttl` | Base gerada pelo ETL: 6 casos herdados + os do KEV da ultima execucao (a atual foi `--limit 3`: 9 casos; os resultados de 40/106 abaixo sao de execucoes anteriores) |
| `OntoCSIRT_v7_evo.ttl` | Modulo de **evolucao estrutural** (TBox aditiva): classes, subclasses e relacoes aprovadas, com proveniencia por axioma |
| `OntoCSIRT_v7_acquired.ttl` | Vulnerabilidades e casos adquiridos pelo `ontoevo` (so gravado depois de SHACL + HermiT + Pellet) |
| `shapes_evo.ttl` | SHACL das classes/propriedades criadas pela evolucao (rotulo, definicao, superclasse, proveniencia, duplicados, nucleo protegido) |
| `ontotax.py` | Hierarquia lida do grafo (tipo mais especifico, Wu-Palmer) usada pelo CBR, SHACL e ingestao |
| `ontoevo/`, `ontocsirt_evolve.py` | Aquisicao de vulnerabilidades e casos CBR e evolucao da ontologia com a API Gemini (ver secao propria) |
| `nvd_enricher.py`, `README_NVD.md` | CVE desconhecida num alerta -> NVD em tempo real (cache 24 h, limite 5/50 pedidos por 30 s) -> ramo validado -> Pellet -> recomendacao; fallback `manual_review` |
| `migrations/` | Migracoes de dados (m001: `kevDateAdded` passa a anotacao - `xsd:date` nao e do OWL 2 DL) |
| `backup/v7_original_2026-11-03/` | Copia dos `.ttl`/`.py` originais com `SHA256SUMS.txt` |
| `tests/` | `python -m pytest tests` (regressao do artigo, portao, Gemini simulado, aquisicao, CBR, evolucao, aceitacao) |

## Como executar

Requisitos: Java 8+, Python 3.10+, `pip install rdflib owlready2 pyshacl`.

```
python ontocsirt_v7.py all
```

Isto regenera `evidence_v7/*.json`, `artigo/numbers_v7.tex` e `artigo/tab_scenario.tex`. Os números do artigo vêm sempre desta execução. Subcomandos: `consistency`, `scenario`, `cq`, `ruletests`, `mutations`, `loocv`.

Para compilar o artigo, coloque o `sbc-template.sty` e o `sbc.bst` oficiais em `artigo/` e rode `pdflatex`, `bibtex`, `pdflatex`, `pdflatex`.

## Resultados da execução de referência

Ambiente: Python 3.13, rdflib 7.6.0, Owlready2 0.25 (Pellet 2.3.1 e HermiT incluídos), OpenJDK 21. SHA-256 do `.ttl` começa por `8c2fc5f00fae`.

- HermiT e Pellet: consistente, 0 classes insatisfazíveis; SHACL conforme.
- Questões de competência: 8/8. Testes de regras: 20/20. Defeitos injetados detetados: 10/10 (4 Pellet, 7 SHACL).
- Leave-one-out (24 casos), Acc@1: classe majoritária 0,29; junção do v6 0,25; similaridade v7 0,69.

Com outra versão do Owlready2 (por exemplo 0.51), os tempos e o número de triplas inferidas podem mudar; volte a correr `all` para o artigo refletir o seu ambiente.

## Pendências antes de submeter

1. Verificar contra o NVD os CVE-2023-34362, CVE-2020-11022 e CVE-2021-26855 (e confirmar o 8,8 do CVE-2023-2065).
2. Trocar autor, filiação e e-mail no `.tex` e o `dcterms:creator` no `.ttl`.
3. Confirmar na fonte as referências marcadas "Dados conforme listados em ..." no `refs_v7.bib`.
4. Declarar o uso de ferramentas de IA, se o evento ou a disciplina o exigir.

## Módulos de ingestão real e SOAR

Requisitos extra: `pip install requests` (o resto já é usado pelo `ontocsirt_v7.py`). Os três módulos importam `ontocsirt_v7.py` (`run_pellet`, `sim`, `FEATURE_Q`, `q`, `base_graph`) e não o alteram: o `OntoCSIRT_v7.ttl` e os números do artigo ficam iguais.

```
python validar_ingestao.py --selftest                 # 6/6 defeitos bloqueados (CVE mal formado, CVE e ator duplicados, CVSS > 10, ATT&CK, CWE em 2 categorias)
python ingest_real_cases.py --limit 40 --pellet       # baixa KEV, mapeamento CTID e NVD; grava OntoCSIRT_v7_real.ttl só se validar
python soar_webhook.py --kb OntoCSIRT_v7_real.ttl --token SEGREDO
curl -X POST http://127.0.0.1:8088/alert -H "X-OntoCSIRT-Token: SEGREDO" -H "Content-Type: application/json" \
     -d '{"src_ip":"1.2.3.4","attack_type":"SQLi","target":"Server_1","cvss":9.1}'
```

NVD: sem chave são 5 pedidos por 30 s (40 CVEs ≈ 5 min na primeira vez; depois vem da pasta `cache/`). Com chave gratuita: `--nvd-api-key` ou a variável `NVD_API_KEY`. Sem rede para o NVD, use um clone do espelho `github.com/fkie-cad/nvd-json-data-feeds` com `--nvd-mirror`.

Shuffle: ação "HTTP" → POST para `/alert`, cabeçalho `X-OntoCSIRT-Token`, corpo com os campos do alerta; ramifique em `requires_human_approval`. Cortex XSOAR: comando `http` (ou integração Generic Webhook) com o mesmo pedido, e use `playbook` da resposta para escolher o sub-playbook.

CI (GitHub Actions), passo antes de aceitar dados novos:
```
- run: pip install rdflib owlready2 pyshacl requests
- run: python validar_ingestao.py staging_ingest.ttl --pellet --report shacl_report.json
```

### Resultados de referência (KEV 2026.10.30, CTID ATT&CK 16.1, NVD pelo espelho FKIE)

- 383 CVEs do KEV têm CWE e técnica de exploração mapeada; com `--limit 40` (estratificado por categoria), 40 ingeridas, 1 recusada (CVE-2021-26855 já era caso herdado), 18 sintéticos retirados. SHACL conforme; Pellet consistente em 6 s.
- Webhook: cerca de 9 s por alerta com a base de 46 incidentes (Pellet + SHACL do alerta). Com 106 incidentes o Pellet passa a ~50 s: para bases grandes use `--reasoner none` ou reduza a base.
- Controlo de circularidade (LOOCV, sem Pellet), 106 casos: com `--label cwe-policy` Acc@1 = 0,97 contra 0,42 da classe majoritária; com `--label kev` Acc@1 = 0,71 contra 0,77 da classe majoritária.

### O que estes dados são e não são

1. Um registo do KEV é um aviso de exploração confirmada, não um incidente de um CSIRT com desfecho. Os casos gerados são casos derivados de dados reais.
2. Com `--label cwe-policy` (padrão, pedido pelo projeto) a solução é gerada pela categoria do CWE, que também entra na similaridade: o 0,97 mede a política, não a recuperação. Não use esse número como resultado.
3. Com `--label kev` os rótulos são independentes mas quase constantes (82 de 106 "aplicar mitigação"), e a similaridade fica abaixo da classe majoritária. A política e o KEV concordam em 0 de 40 casos.
4. O ator é sempre VERIS Unknown (o KEV não identifica atores) e o tipo de ativo vem de uma heurística sobre fornecedor/produto, registada em `assetTypeEvidence`.
5. `confidence` no webhook = similaridade do caso mais próximo × fração ponderada dos vizinhos que concordam. Não é uma probabilidade calibrada; abaixo de `--min-confidence` a resposta pede aprovação humana.

Este produto usa dados da API do NVD, mas não é endossado nem certificado pelo NVD.

## Aquisição e evolução estrutural com a API Gemini (`ontoevo`)

O `OntoCSIRT_v7.ttl` do artigo continua congelado (SHA-256 `8c2fc5f00fae…`, verificado em `tests/`) e os números do artigo não mudam: a similaridade taxonómica (`ontotax`) reduz-se exatamente à original na hierarquia de 2 níveis (LOOCV idêntico, consulta a consulta).

```
pip install -r requirements.txt
export GEMINI_API_KEY=...            # opcional: GEMINI_MODEL (padrão gemini-3.8-flash), ONTOCSIRT_GEMINI_MODE=live|cached|replay
python ontocsirt_evolve.py fetch-catalogs          # CWE 5.0 (MITRE) e ATT&CK 16.1 (STIX) -> cache/catalogs (compactos)
python ontocsirt_evolve.py acquire CVE-2026-111357 # CVE real -> indivíduos OWL (Gemini só preenche lacunas)
python ontocsirt_evolve.py analyze CVE-2026-111357 # analisar vulnerabilidade -> novo caso CBR (retrieve + reuse)
python ontocsirt_evolve.py signals                 # sinais estruturais nos dados
python ontocsirt_evolve.py propose --signal heterogeneous:MemorySafetyWeakness   # agente Gemini
python ontocsirt_evolve.py propose --from-file evolution/examples/memory_buffer_bounds.json --by "Nome"
python ontocsirt_evolve.py list
python ontocsirt_evolve.py approve EVO-20261103-001 --by "Nome"
python ontocsirt_evolve.py apply EVO-20261103-001
python ontocsirt_evolve.py validate                # SHACL + HermiT + Pellet + 8 questões de competência
python soar_webhook.py --kb OntoCSIRT_v7_real.ttl  # + POST /retain: caso aprovado pelo analista
```

**Fluxo.** Fatos vêm sempre de fontes autorizadas (KEV, NVD, CTID, catálogos CWE/ATT&CK). O Gemini (SDK `google-genai`, Interactions API, saída estruturada com esquema Pydantic validado localmente, function calling só de leitura) preenche lacunas (CWE, técnica ATT&CK — 1347 das 1766 CVEs do KEV não têm mapeamento CTID —, tipo de ativo) e cada valor é verificado no catálogo; o CVSS nunca vem do modelo. A evolução estrutural parte de **sinais determinísticos** (categoria residual, sub-ramo oficial CWE dentro de uma categoria, tipos de ativo por omissão, relações guardadas como texto, co-ocorrência padrão→solução, partição por tática ATT&CK); o agente investiga com 8 ferramentas e devolve no máximo 3 propostas numa gramática restrita (classe nova, propriedade de objeto, classificação; classes definidas `P ⊓ ∃p.C` / `P ⊓ ∃p.{i}`), que um compilador determinístico traduz em OWL. Cada proposta passa no portão — SHACL (v7 + ingestão + evo), HermiT (consistência, classes insatisfazíveis, **equivalência inferida = redundância**), Pellet com SWRL, 8 questões de competência do artigo — e só entra no `OntoCSIRT_v7_evo.ttl` depois de **aprovação humana**, com cópia de segurança, `versionInfo evo-N`, `evolution/CHANGELOG.json` e restauro automático se a verificação final falhar. A evolução é monótona; a única retração permitida é sair da categoria residual ou de um tipo de ativo atribuído por omissão, e só em ficheiros de dados.

**Proveniência dos casos.** `solutionProvenance`: `policy:cwe-category-v1`, `kev:requiredAction`, `llm:case-analysis-v1` (hipótese adaptada pelo Gemini sobre os casos recuperados) e `analyst:retain` (ação aprovada por um analista para um alerta real — o único desfecho observado). Na recuperação a solução principal segue esta ordem (registo/analista > fonte/política > LLM); casos `llm:` não devem entrar como verdade em avaliações.

**Limites conhecidos.** As chamadas reais à API Gemini não foram executadas neste ambiente (sem `GEMINI_API_KEY`): o adaptador foi validado contra os tipos do SDK 2.34 e os testes usam respostas simuladas; a primeira execução real deve ser feita com `--gemini-mode live` e revista. O Pellet escala mal com muitos incidentes (R3–R6 são pares); a regressão do portão corre na base do artigo (24 incidentes) para se manter em segundos.
