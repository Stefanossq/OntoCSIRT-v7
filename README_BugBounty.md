# OntoBugBounty — módulo de Bug Bounty e Segurança Ofensiva

Módulo complementar da OntoCSIRT v7 para programas de bug bounty, escopo, recompensas, pesquisadores autorizados, relatórios e padrões de ataque do OWASP Top 10 ligados a CVEs reais.

| Ficheiro | O que é |
|---|---|
| [`ontology/OntoBugBounty.ttl`](ontology/OntoBugBounty.ttl) | TBox + ABox. O bloco de referência no fim (OWASP, CVEs, VRT) é **gerado** por `ingest_bugbounty.py catalog` |
| [`ontology/shapes_bugbounty.ttl`](ontology/shapes_bugbounty.ttl) | Restrições SHACL do módulo (aplicadas junto com as do v7) |
| `ontology/OntoBugBounty_data.ttl` | Programas e escopos reais da HackerOne, gerado por `ingest_bugbounty.py hackerone` (não existe até à primeira execução com credenciais) |
| [`ingest_bugbounty.py`](ingest_bugbounty.py) | `hackerone`, `catalog`, `validate` |
| `tests/test_bugbounty.py`, `tests/test_bugbounty_ingest.py` | Coesão com o v7, regras, SHACL, cliente HackerOne (sem rede) |

## Como o módulo se conecta à OntoCSIRT v7

O módulo usa o mesmo espaço de nomes da OntoCSIRT e **reutiliza** as suas classes e propriedades em vez de as redefinir.
- **`:ThreatActor`:** é o do v7, especializado por `:BlackHat`, `:GrayHat`, `:RedHat`, `:CyberTerrorist`, `:Phisher` e `:InsiderThreat`. A última é subclasse de `:InternalActor`, o que mantém a partição VERIS (Externo/Interno/Parceiro/Desconhecido).
- **`:AttackPattern`:** são os mesmos indivíduos do v7 (`AP_IDOR`, `AP_XSS`, `AP_SQLInjection`…), agora com categoria OWASP, CVEs reais, severidade e faixa de recompensa.
- **`:CWE`:** é um alias de `:Weakness`.
- **`:CVE`:** é uma classe *definida* (`:Vulnerability` com `:cveId`). O raciocinador classifica sozinho as CVEs reais do v7 e deixa de fora as vulnerabilidades sintéticas.
- **`:targetsCWE`:** é subpropriedade de `:relatedWeakness`, por isso as consultas do v7 sobre a fraqueza de um padrão veem os dados do módulo.
- **CVEs:** usam o mesmo `:hasWeakness`, `:cvssBaseScore` e a mesma convenção de IRIs (`Vuln_CVE_AAAA_NNNN`) da ingestão do v7. A mesma CVE vinda do KEV, do NVD em tempo real ou deste módulo é um único indivíduo.
- **Regras:** as duas regras SWRL usam a mesma fronteira CVSS ≥ 9,0 da regra R1a.

Com o módulo carregado, as 8 questões de competência do v7 continuam corretas e a recuperação CBR do artigo fica idêntica, consulta a consulta (`tests/test_bugbounty.py`).

## Decisões de modelagem (e onde divergem do pedido literal)

1. **`:Researcher` não é subclasse de `:ThreatActor`; é uma classe paralela.** Três razões:
   - No VERIS e no STIX, o ator de ameaça é quem causa o incidente, e um teste autorizado dentro do escopo não é incidente.
   - Se fosse subclasse, cada pesquisador entraria nas regras e consultas do v7 sobre atores (R4 `sharesActorWith`, CQ5, a faceta de ator do CBR) e seria contado como ameaça.
   - Os dois usam as mesmas técnicas; a diferença é a **autorização**, uma relação (`:authorizedBy`) e não um tipo.

   `:AuthorizedResearcher ≡ :Researcher ⊓ ∃:authorizedBy.:BugBountyProgram`, e `:participatedIn ⊑ :authorizedBy`: participar de um programa é aceitar os seus termos. As classes **não são disjuntas**, porque a mesma pessoa pode ter os dois papéis (um *gray hat* que depois entra num programa).
2. **`:exploits` → `:patternExploits`.** O `:exploits` do v7 tem domínio `:ThreatAction`, que é disjunto de `:AttackPattern`. Ligar um padrão a uma CVE com ele torna a ontologia **inconsistente**, o que o HermiT confirma em `test_reusing_v7_exploits_on_a_pattern_is_inconsistent`.
3. **Chapéus e outros tipos de ator vêm de dimensões diferentes.** O chapéu é ética/autorização, *CyberTerrorist* é motivação e *Phisher* é técnica. Por isso só `BlackHat`, `GrayHat` e `RedHat` são disjuntos entre si. Não há `WhiteHat` entre as ameaças, porque esse papel é o `:Researcher`.
4. **Plataforma ≠ programa.** `:Platform_HackerOne` e `:Platform_Bugcrowd` são plataformas, e um programa `:hostedOn` uma delas.
5. **Indivíduos de exemplo.** Personas, programas, relatórios e recompensas são **fictícios** (`bb:fictional true`) e usam domínios reservados (`example.com`, `example.org`, `192.0.2.0/24`). Nada no módulo afirma algo sobre pessoas ou programas reais.

## Dados de referência (gerados de fontes reais)

`python ingest_bugbounty.py catalog` regenera o bloco no fim do `OntoBugBounty.ttl` a partir de:

| Fonte | Para quê |
|---|---|
| **OWASP Top 10 2021 e 2025**, pelas vistas 1344 e 1450 do catálogo **CWE 5.0** (MITRE) | 20 `:OWASPCategory` com as CWEs de cada categoria. O OWASP não tem API; o MITRE publica o mapeamento oficial em XML. A vista de 2025 ainda está marcada "RC1" no CWE 5.0 |
| **Bugcrowd VRT** (release 2026-07-08, GitHub) | `:bountyPayout`: mediana inferior das prioridades P1–P5 das variantes da classe. P1–P2 → `"$$$"`, P3 → `"$$"`, P4–P5 → `"$"` |
| **CISA KEV** (2026.10.30) + **NVD API 2.0** | Até 3 CVEs reais por padrão, exploradas (KEV) e com CWE e CVSS confirmados pelo NVD, uma por fornecedor. Se o KEV não chegar a 2, o NVD por `cweId` completa a lista, marcando "exploração não confirmada" |

Resultado atual (`evidence_v7/bugbounty.json`):

| Padrão | CWE | OWASP 2021 / 2025 | CVSS médio → severidade | VRT típico → recompensa | CVEs |
|---|---|---|---|---|---|
| `AP_IDOR` | 639 | A01 / A01 | 5,55 → Medium | P3 → `$$` | CVE-2026-55255 (KEV), CVE-2026-100268 (NVD) |
| `AP_XSS` | 79 | A03 / A05 | 6,10 → Medium | P3 → `$$` | CVE-2026-42897, CVE-2025-48700, CVE-2025-68461 |
| `AP_SQLInjection` | 89 | A03 / A05 | 9,83 → Critical | P1 → `$$$` | CVE-2026-114625, CVE-2026-76461, CVE-2026-9586 |
| `AP_SSRF` | 918 | **A10 / A01** | 8,10 → High | P4 → `$` | CVE-2026-96655, CVE-2026-49869, CVE-2026-83548 |
| `AP_CommandInjection` | 78, 77 | A03 / A05 | 9,20 → Critical | P1 → `$$$` | CVE-2026-110447, CVE-2026-106931, CVE-2026-105134 |
| `AP_Deserialization` | 502 | A08 / A08 | 9,80 → Critical | P1 → `$$$` | CVE-2021-23758, CVE-2026-63077, CVE-2026-50522 |
| `AP_CSRF` | 352 | A01 / A01 | 8,57 → High | P5 → `$` | CVE-2025-62593, CVE-2008-4128, CVE-2023-2533 |
| `AP_CredentialAbuse` | 287 | A07 / A07 | 7,67 → High | P1 → `$$$` | CVE-2026-105133, CVE-2026-42018, CVE-2026-59822 |
| `AP_XXE` (novo) | 611 | A05 / A02 | 8,27 → High | P1 → `$$$` | CVE-2025-58360, CVE-2025-2775, CVE-2023-45727 |

O que os dados mostram:
- **CVSS e bounty medem coisas diferentes.** SSRF e CSRF têm CVSS médio *High*, mas recompensa típica `$`: as CVEs no KEV/NVD são falhas graves em produtos, e o VRT reflete o impacto típico dos relatórios a programas. Por isso o módulo guarda os dois (`:hasSeverity` e `:bountyPayout`) em vez de derivar um do outro.
- **O SSRF mudou de categoria.** Em 2025 deixou de ser categoria própria e passou para *Broken Access Control*.
- **IDOR quase não chega ao KEV.** Só há uma CVE: é uma falha de lógica específica de cada aplicação.
- **Desserialização não tem classe no VRT.** O módulo usa a de RCE, e a nota fica em `bb:derivation`.

## Regras SWRL e o que inferem

| Regra | Corpo → cabeça | Resultado com os dados atuais |
|---|---|---|
| **BB-1** | `Researcher(?r) ∧ uses(?r,?ap) ∧ patternExploits(?ap,?v) ∧ cvssBaseScore(?v,?s) ∧ ?s ≥ 9,0 → EliteResearcher(?r)` | `Researcher_SQLi`, `Researcher_CmdInjection`, `Researcher_Deserialization`, `Researcher_SSRF` |
| **BB-2** | `Report(?rep) ∧ submittedBy(?rep,?r) ∧ EliteResearcher(?r) ∧ reportsPattern(?rep,?ap) ∧ bountyPayout(?ap,"$$$") → status(?rep,"Priority")` | `Report_001` (SQLi) e `Report_003` (injeção de comandos); `Report_002` (XSS, `$$`) não |

**Atenção à BB-1, tal como especificada.** Ela mede a pior CVE do *padrão*, não o pesquisador:
- a persona de SSRF torna-se Elite porque uma das três CVEs de SSRF tem CVSS 10,0;
- a persona **Junior** de desserialização torna-se Elite porque todas as CVEs de desserialização têm 9,8.

A forma `EliteVsDeclaredShape` (aviso, não bloqueia) aponta exatamente essa divergência no grafo inferido. Uma versão que medisse o pesquisador ligaria a regra aos relatórios aceites dele, e não ao padrão:

`Report(?rep) ∧ submittedBy(?rep,?r) ∧ status(?rep,"Resolved") ∧ reportsVulnerability(?rep,?v) ∧ cvssBaseScore(?v,?s) ∧ ?s ≥ 9,0 → EliteResearcher(?r)`

## SHACL (`shapes_bugbounty.ttl`)

| Forma | Garante |
|---|---|
| `BugBountyProgramShape` | ≥ 1 `:Scope` (pedido); nome; ≤ 1 plataforma; `hasMinBounty ≤ hasMaxBounty`; moeda ISO 4217 |
| `ResearcherShape` | exatamente 1 `:hasSkillLevel` em {Junior, Senior, Elite} (pedido) |
| `ReportShape` | exatamente 1 `:submittedTo` para um programa **válido** (`sh:node` da forma do programa: pedido); pesquisador; padrão; estado no vocabulário; o escopo afetado pertence a esse programa |
| `ScopeShape`, `RewardShape` | identificador; tipo; pertence a algum programa; valor e moeda da recompensa |
| `OWASPPatternShape` | ≥ 2 CVEs com `cveId` válido; severidade e recompensa no vocabulário; CVSS médio em [0, 10] |
| `OWASPCategoryShape` | código `Axx:AAAA` e edição |
| `EliteVsDeclaredShape` (aviso) | Elite inferido com nível declarado Junior |

As formas do v7 (`shapes_v7.ttl`, `shapes_ingest.ttl`, `shapes_evo.ttl`) continuam a aplicar-se: as CVEs do módulo precisam de CVSS, CWE e `cveId` bem formado, como qualquer vulnerabilidade da OntoCSIRT.

## Ingestão da HackerOne

### 1. Credenciais

Na HackerOne: **Settings → API Token → Create API token**. O "identifier" é o utilizador da API, e o token só é mostrado uma vez.

```bash
export HACKERONE_USER="o-identificador-do-token"
export HACKERONE_TOKEN="o-token"
```

```powershell
$env:HACKERONE_USER = "o-identificador-do-token"
$env:HACKERONE_TOKEN = "o-token"
```

Não ponha as credenciais em ficheiros do projeto. O `.env` está fora da imagem Docker (`.dockerignore`).

### 2. Executar

```bash
python ingest_bugbounty.py hackerone --dry-run --max-programs 20   # valida sem gravar
python ingest_bugbounty.py hackerone                              # todos os programas públicos -> ontology/OntoBugBounty_data.ttl
python ingest_bugbounty.py validate                               # SHACL + HermiT + Pellet (BB-1/BB-2) + CQs do v7
```

O que o script faz:
- **Autenticação:** HTTP Basic em `https://api.hackerone.com/v1/hackers/programs` e, por programa, em `/hackers/programs/{handle}/structured_scopes`.
- **Paginação:** `page[size]=100`; segue `links.next` até desaparecer (a documentação avisa que `links.last` pode estar antes do fim). Para mais de 10 000 escopos continua com `filter[id__gt]`.
- **Limites:** 600 leituras/min. Um HTTP 429 leva a esperar (`Retry-After`) e tentar de novo; um 401/403 dá uma mensagem clara sobre as credenciais.
- **Transformação:** cada programa vira `:Program_H1_<id>` (`:BugBountyProgram`, `:hostedOn :Platform_HackerOne`, `:programHandle`, `:offersBounties`, `:submissionState`, `:bountyCurrency`). Cada escopo vira `:Scope_H1_<id>` (`:scopeIdentifier`, `:scopeType`, `:eligibleForBounty`, `:eligibleForSubmission`, `:maxSeverity`), ligado por `:hasScope`. O texto da política não é gravado.
- **Validação:** o grafo composto (v7 + extensão + evolução + módulo + dados novos) passa por SHACL e HermiT. **Se falhar, nada é gravado** e as violações são mostradas.
- **Relatório:** `evidence_v7/bugbounty.json` (programas, escopos, recusas com o motivo, pedidos feitos).

### 3. O que a API não dá, e como o script trata

- **Recompensa mínima/máxima.** A Hacker API não publica faixas de recompensa (só `offers_bounties`). `:hasMinBounty`/`:hasMaxBounty` entram apenas por `--bounties`, um JSON com a fonte de cada valor:
  ```json
  {"programa-handle": {"min": 100, "max": 20000, "currency": "USD", "source": "https://hackerone.com/programa-handle (política, 2026-11-04)"}}
  ```
- **Programas privados.** A API do *hacker* devolve também os programas privados para que o utilizador foi convidado, e a sua existência e escopo são em geral confidenciais pelos termos do programa. Por omissão **só entram programas públicos** (`state == "public_mode"`); `--include-private` muda isso e avisa.
- **Programas sem escopo estruturado** são recusados (a SHACL exige ≥ 1 `:Scope`), com o motivo no relatório, em vez de bloquearem a ingestão inteira.

## Outras fontes avaliadas

| Fonte | Decisão |
|---|---|
| **Bugcrowd — VRT** (GitHub, aberto) | **Integrado** no `catalog`: fundamenta `:bountyPayout` |
| **Bugcrowd — API** (`api.bugcrowd.com`, token da organização, v1.1.0 de maio de 2026) | Não integrado. É a API do *dono* do programa (programas, alvos e submissões da própria organização) e não lista programas públicos. Seria a fonte natural de `:Report` para quem administra um programa; sem credenciais não foi possível verificar o esquema atual |
| **OWASP** | Sem API. **Integrado** pelas vistas OWASP do catálogo CWE (MITRE), que é a forma oficial e legível por máquina do mapeamento |
| **Hack The Box** | Não integrado. Não tem API documentada oficialmente (só coleções da comunidade), e o conteúdo são laboratórios de treino, não programas de bug bounty |

## Validação e testes

```bash
python ingest_bugbounty.py validate
python -m pytest -q tests/test_bugbounty.py tests/test_bugbounty_ingest.py
```

Os testes cobrem:
- a inconsistência do `:exploits` do v7 num padrão;
- SHACL, HermiT e Pellet do módulo;
- as 8 questões de competência e a recuperação do v7 inalteradas com o módulo;
- a autorização sem papel de ameaça;
- a classe definida `:CVE`;
- as disjunções (chapéus, ameaça interna × ator externo);
- as regras BB-1/BB-2, com os resultados esperados recalculados a partir dos dados;
- o aviso de nível divergente;
- a coerência de severidade e recompensa com as fontes;
- 8 defeitos SHACL bloqueados;
- o cliente HackerOne: paginação, autenticação, 429, 401, programas privados, sem escopo, tabela de recompensas e escrita bloqueada pelo SHACL.

**Limite:** o cliente HackerOne foi testado com respostas que seguem a estrutura documentada da API, **não contra a API real**: não havia credenciais neste ambiente. A primeira execução real deve ser feita com `--dry-run`.
