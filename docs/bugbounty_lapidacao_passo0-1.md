# Lapidação do módulo de bug bounty — Passo 0 (inspeção) + Passo 1 (proposta)

Data: 2026-11-04 · Todas as URLs abaixo foram acessadas em **2026-11-04**.
Nada foi implementado. Nenhum ficheiro `.ttl` foi alterado. Nada foi commitado.

---

## (a) Inventário do módulo atual

### Ficheiros e commit

| Ficheiro | Linhas | Blob git | Último commit que o tocou |
|---|---|---|---|
| `ontology/OntoBugBounty.ttl` | 843 | `a5778aa5a525388212c0f3376590b3b036d99646` | `0c02035` (LF), criado em `dad9d16` |
| `ontology/shapes_bugbounty.ttl` (SHACL, fora do escopo desta fase) | 88 | `14ce8618a11aeafcc5f6123f7dd188ffc00ccf9d` | idem |

HEAD: `de491d4ff9c97fd675730366f65340243f6fd06e` (branch `main`). Os dois ficheiros estão limpos face ao HEAD.

**Não existem** `bugbounty_core.ttl` nem `hunter_tools.ttl`. Também não há `OntoBugBounty_data.ttl` (o carregador aceita-o como opcional). No repositório não há nada sobre ferramentas do hunter (Shodan, Censys, Nuclei, Nmap).

Composição usada pelo carregador (`ingest_bugbounty.compose`): `OntoCSIRT_v7.ttl` + `_ext` + `_evo` + `OntoBugBounty.ttl`, sem `owl:imports`. Namespace `:` = `http://www.semanticweb.org/ontocsirt#` (o mesmo do v7).

### Classes (17, todas `owl:Class`)

"Disj." = disjunta de. "Top v7" = `Incident, ThreatAction, AttackPattern, Asset, SecurityState, Vulnerability, Weakness, DetectionSource, CourseOfAction, Case`. Nenhuma classe do módulo tem restrição de cardinalidade.

| Classe | Superclasse / definição | Disjunção | Uso (domínio / contradomínio / SWRL / indivíduos) |
|---|---|---|---|
| `:BugBountyPlatform` | — | top v7 + todas as classes BB + `:ThreatActor` | range de `hostedOn`; 2 indivíduos (HackerOne, Bugcrowd) |
| `:BugBountyProgram` | — | idem | domínio de `hasScope, hostedOn, hasMin/MaxBounty, bountyCurrency, offersBounties, programHandle, submissionState`; range de `authorizedBy, participatedIn, submittedTo`; 2 indivíduos fictícios |
| `:Scope` | — | idem (incl. `:Asset`) | domínio de `scopeIdentifier, scopeType, eligibleForBounty, eligibleForSubmission, maxSeverity`; range de `hasScope, affectsScope, targets(∪)`; 4 indivíduos |
| `:Reward` | — | idem | domínio de `rewardAmount, rewardCurrency`; range de `hasReward`; 1 indivíduo |
| `:Report` | — | idem | domínio de `submittedBy, submittedTo, reportsPattern, reportsVulnerability, affectsScope, hasReward, status`; SWRL BB-2; 3 indivíduos |
| `:OWASPCategory` | — | idem | domínio de `owaspCode, owaspEdition, cweGroupingId, includesWeakness`; 20 indivíduos (gerados) |
| `:Researcher` | — | top v7 + classes BB (**não** disjunta de `:ThreatActor`, de propósito) | domínio de `authorizedBy, participatedIn, hasSkillLevel, uses(∪), targets(∪)`; SWRL BB-1/BB-2; 6 indivíduos |
| `:AuthorizedResearcher` | ≡ `Researcher ⊓ ∃authorizedBy.BugBountyProgram` | — | classe definida, os 6 pesquisadores são inferidos nela |
| `:EliteResearcher` | ⊑ `:Researcher` | — | cabeça da regra BB-1 |
| `:BlackHat` | ⊑ `:ThreatActor` | `GrayHat, RedHat` | sem indivíduos |
| `:GrayHat` | ⊑ `:ThreatActor` | `BlackHat, RedHat` | sem indivíduos |
| `:RedHat` | ⊑ `:ThreatActor` | `BlackHat, GrayHat` | sem indivíduos |
| `:CyberTerrorist` | ⊑ `:ThreatActor` | — | sem indivíduos |
| `:Phisher` | ⊑ `:ThreatActor` | — | sem indivíduos |
| `:InsiderThreat` | ⊑ `:InternalActor` (v7) | — | sem indivíduos |
| `:CWE` | ≡ `:Weakness` (alias) | — | — |
| `:CVE` | ≡ `Vulnerability ⊓ ∃cveId.xsd:string` | — | classe definida |

**Não existe `:WhiteHat`.** O papel de white hat é coberto implicitamente por `:Researcher`/`:AuthorizedResearcher`.

### Propriedades de objeto (16)

| Propriedade | Domínio → Contradomínio | Características | Asserções |
|---|---|---|---|
| `:uses` | `ThreatActor ⊔ Researcher` → `AttackPattern` | — | 6 (BB-1) |
| `:targets` | `ThreatActor ⊔ Researcher` → `Asset ⊔ Scope` | — | 2 |
| `:patternExploits` | `AttackPattern` → `Vulnerability` | — | 26 (BB-1) |
| `:targetsCWE` | `AttackPattern` → `Weakness` | ⊑ `:relatedWeakness` (v7) | 10 |
| `:owaspCategory` | `AttackPattern` → `OWASPCategory` | — | 18 |
| `:includesWeakness` | `OWASPCategory` → `Weakness` | — | 28 |
| `:authorizedBy` | `Researcher` → `BugBountyProgram` | — | 0 diretas (vem por subpropriedade) |
| `:participatedIn` | `Researcher` → `BugBountyProgram` | ⊑ `:authorizedBy` | 7 |
| `:hostedOn` | `BugBountyProgram` → `BugBountyPlatform` | Functional | 2 |
| `:hasScope` | `BugBountyProgram` → `Scope` | — | 4 |
| `:submittedBy` | `Report` → `Researcher` | — | 3 (BB-2) |
| `:submittedTo` | `Report` → `BugBountyProgram` | Functional | 3 |
| `:reportsPattern` | `Report` → `AttackPattern` | — | 3 (BB-2) |
| `:reportsVulnerability` | `Report` → `Vulnerability` | — | **0** |
| `:affectsScope` | `Report` → `Scope` | — | 3 |
| `:hasReward` | `Report` → `Reward` | — | 1 |

### Propriedades de dados (23) e de anotação (4)

Todas sem características (nenhuma é `Functional`): `hasSeverity`, `meanCvss`, `bountyPayout`, `vrtPriorityTypical`, `vrtPriorityBest` (em `AttackPattern`); `hasSkillLevel` (`Researcher`); `status` (`Report`, usada na BB-2); `hasMinBounty`, `hasMaxBounty`, `bountyCurrency`, `offersBounties`, `programHandle`, `submissionState` (`BugBountyProgram`); `scopeIdentifier`, `scopeType`, `eligibleForBounty`, `eligibleForSubmission`, `maxSeverity` (`Scope`); `rewardAmount`, `rewardCurrency` (`Reward`); `owaspCode`, `owaspEdition`, `cweGroupingId` (`OWASPCategory`).
Anotação: `bb:dataSource`, `bb:derivation`, `bb:vrtNode`, `bb:fictional`.

Duas regras SWRL: **BB-1** (pesquisador que domina um padrão com CVE de CVSS ≥ 9,0 → `EliteResearcher`) e **BB-2** (relatório de elite sobre padrão `$$$` → `status "Priority"`).

## (b) Resultado do HermiT (estado atual)

Script de inspeção só de leitura (na scratchpad, não no repositório); usa `v7.run_hermit` do projeto (Owlready2 + HermiT, Java 17.0.13).

| Composição | Triplas | Consistente | Classes insatisfatíveis | Tempo |
|---|---|---|---|---|
| v7 + ext + evo + OntoBugBounty | 2570 | **sim** | **0** | 1,9 s |
| idem + `OntoBugBounty_data.ttl` (não existe; mesmo grafo) | 2570 | sim | 0 | — |

- **Ciclos** `rdfs:subClassOf` / `rdfs:subPropertyOf` (classes nomeadas): **nenhum**.
- **Axiomas órfãos** (termos referenciados pelo módulo sem declaração na composição): **nenhum**. Nenhum indivíduo sem tipo.
- **Propriedades declaradas sem uso nos dados**: `:authorizedBy` (normal, alimentada por `:participatedIn`), `:reportsVulnerability` (sem uso), `:programHandle` e `:submissionState` (preenchidas apenas por `ingest_bugbounty.py hackerone`). Não são defeitos.
- **Achado relevante para o Passo 1:** `:relatedWeakness` (v7, linha 149) tem `rdfs:domain :AttackPattern`. Qualquer nova propriedade com domínio `Program` ou `Report` declarada como subpropriedade dela tornaria a ontologia **inconsistente** (`AttackPattern` é disjunta de `BugBountyProgram`/`Report`).

---

## (c) Lacunas e mudanças propostas

Convenções: **A** = adicionar (não quebra nada), **M** = alterar um termo existente, **L** = lacuna (sem fonte; vai para a secção d).
Arquivo-alvo sugerido: `ontology/bugbounty_refined.ttl` (composto depois de `OntoBugBounty.ttl`) e `ontology/hunter_tools.ttl`. Nenhuma remoção é proposta.

### C1. BugBountyProgram

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte (URL + data) | Impacto downstream | Risco |
|---|---|---|---|---|---|---|---|
| P1 | Público / Privado | Não modelado. A ingestão H1 só filtra `state == public_mode` e descarta o resto | **A**: classe enumerada `:ProgramVisibility` = {`:Visibility_Public`, `:Visibility_Private`} (`owl:oneOf` + `AllDifferent`); `:hasVisibility` Functional; `BugBountyProgram ⊑ hasVisibility exactly 1 ProgramVisibility`; `:PublicProgram ≡ Program ⊓ hasVisibility value Public`, `:PrivateProgram` análogo; `PublicProgram` disjunta de `PrivateProgram` | Para a HackerOne, um programa é *ou* público *ou* privado num dado momento (começa privado e pode passar a público). A YesWeHack descreve a mesma dicotomia | https://docs.hackerone.com/en/articles/8368948-private-vs-public-programs (2026-11-04); YesWeHack, G-Cloud 15 Service Definition: https://assets.applytosupply.digitalmarketplace.service.gov.uk/g-cloud-15/documents/723920/539484723838229-service-definition-document-2025-12-15-1335.pdf (2026-11-04) | A ingestão H1 *poderia* gravar `hasVisibility Public` (alteração de código, só se aprovada). Os 2 programas fictícios ficam sem valor: pelo mundo aberto, `exactly 1` não gera inconsistência | Baixo. A visibilidade muda no tempo, mas a ontologia guarda um retrato do momento |
| P2 | Managed / Self-managed | Não modelado | **A**: `:ProgramManagementModel` = {`:Managed`, `:SelfManaged`} + `:hasManagementModel` Functional (`max 1`, não `exactly 1`: a API H1 não expõe este dado); `:ManagedProgram`, `:SelfManagedProgram` definidas e disjuntas | A Bugcrowd apresenta as duas opções como alternativas (no self-managed, a organização controla escopo, regras, comunicação e recompensas) | https://www.bugcrowd.com/glossary/bug-bounty-program-bbp/ (2026-11-04); https://www.intigriti.com/blog/business-insights/bug-bounty-diy-the-pros-and-cons-of-managing-vulnerability-disclosure-in-house (2026-11-04) | Nenhum (dado novo, opcional) | **Médio**: as fontes são de marketing de fornecedor, não documentação técnica, e "managed" significa coisas diferentes em cada plataforma (ver d-11) |
| P3 | Solo / Colaborativo | Não modelado | **L para o nível de programa.** Alternativa com fonte, no nível do **relatório**: `:CollaborativeReport ≡ Report ⊓ ≥2 submittedBy.Researcher`; `:SoloReport ≡ Report ⊓ ≤1 submittedBy.Researcher`; disjuntas | Nas plataformas, colaboração é um recurso do *relatório* (até 10 colaboradores, bounty dividido por pesos), não um tipo de programa | https://docs.hackerone.com/en/articles/8457618-collaboration (2026-11-04); https://www.intigriti.com/blog/product-updates/introducing-report-collaboration-split-these-bounties (2026-11-04) | `:submittedBy` passa a admitir vários valores (já admite, não é Functional). BB-2 não muda | Baixo. Pelo mundo aberto, `SoloReport` só é inferido se houver fecho; é aceitável |

### C2. Scope

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P4 | In-scope / Out-of-scope | `:eligibleForSubmission` (boolean, não Functional) | **A**: `:InScopeItem ≡ Scope ⊓ eligibleForSubmission value true`; `:OutOfScopeItem ≡ Scope ⊓ eligibleForSubmission value false`; disjuntas. **M**: `:eligibleForSubmission` passa a `owl:FunctionalProperty`. O nome evita "Asset" porque `:Scope` é disjunto de `:Asset` no módulo; o rótulo pode ser "In-scope asset"@en | Na HackerOne, cada ativo entra "in scope or out of scope" | https://docs.hackerone.com/en/articles/8593105-asset-details-and-scoping (2026-11-04) | Os escopos atuais e os ingeridos da H1 são classificados automaticamente. SHACL não muda | **Médio**: equiparar `eligible_for_submission=false` a "fora do escopo" é uma decisão de mapeamento que a doc da H1 não afirma literalmente (verificar na referência da API) |
| P5 | Tipos de ativo | `:scopeType` em string livre ("URL", "CIDR", "WILDCARD") | **A**: classes definidas por valor de `:scopeType`: `:WebApplicationScope` {URL, Domain, Wildcard}, `:MobileAppScope` {iOS App Store, TestFlight, .ipa, Android Play Store, .apk}, `:NetworkScope` {CIDR, IP Address}, `:HardwareScope` {Hardware/IoT}, `:SourceCodeScope` {Source code}. Opcionais, por existirem na H1: `:ExecutableScope`, `:SmartContractScope`, `:AIModelScope` | Os tipos vêm da lista oficial da HackerOne | https://docs.hackerone.com/organizations/asset-types.html (2026-11-04) | Os valores gravados pela ingestão vêm do enum da API (`GOOGLE_PLAY_APP_ID`, `SOURCE_CODE`…); só encontrei essa lista numa fonte secundária (https://docs.anysite.io/api-reference/hackerone/hackeroneprogramsscopes, 2026-11-04) | Médio: é preciso confirmar os literais exatos do enum. **`API` vai para revisão (d-3)**: a doc oficial da H1 não tem o tipo API |
| P6 | Wildcard vs. específico | Wildcard só como string | **A**: `:WildcardScope ≡ Scope ⊓ scopeType value "WILDCARD"`; `:SpecificScope ≡ Scope ⊓ ¬WildcardScope`; disjuntas. **M**: `:scopeType` passa a Functional (sem isso, `SpecificScope` nunca seria inferida) | Na H1, Wildcard é "a way to specify multiple domains or subdomains", diferente de Domain/URL | https://docs.hackerone.com/organizations/asset-types.html (2026-11-04) | O `Scope_DemoSaaS_Wildcard` é classificado sozinho | Baixo. Hoje todos os escopos têm um único `scopeType` |

### C3. Reward

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P7 | Monetário / Não-monetário | `:Reward` com `rewardAmount`/`rewardCurrency` | **A**: `:MonetaryReward ≡ Reward ⊓ ∃rewardAmount.xsd:decimal`; `:NonMonetaryReward ⊑ Reward` (agradecimento, swag, hall of fame), disjunta da anterior; `:rewardKind` (string) opcional | Para a HackerOne, os programas podem oferecer "thanks, swag, and/or bounties" | https://www.hackerone.com/hackers/how-to-start-hacking (2026-11-04); https://docs.bugcrowd.com/researchers/receiving-rewards/getting-rewarded/ (2026-11-04) | `Reward_001` passa a `MonetaryReward` por inferência | Baixo. Pontos de reputação **não** são recompensas do programa (ver P15) |
| P8 | BountyTable / RewardRange | Faixa só no programa (`hasMinBounty`/`hasMaxBounty`/`bountyCurrency`) | **A**: `:BountyTable` (`Program hasBountyTable`), `:BountyTableEntry` com `forSeverity exactly 1 SeverityRating`, `entryMinAmount max 1`, `entryMaxAmount max 1`, `entryCurrency max 1`. `RewardRange` é o próprio `BountyTableEntry` (rótulo alternativo), para não duplicar. As propriedades atuais do programa ficam como estão | A H1 categoriza os bounties da tabela pela severidade. A Bugcrowd define faixas por prioridade P1–P5 (VRT) | https://docs.hackerone.com/organizations/bounty-tables.html (2026-11-04); https://docs.bugcrowd.com/researchers/receiving-rewards/getting-rewarded/ (2026-11-04); https://www.bugcrowd.com/blog/setting-up-your-program-reward-ranges/ (2026-11-04) | Novo; não afeta BB-1/BB-2 | Médio: a Bugcrowd indexa por prioridade, não por CVSS, e por isso é preciso `forPriority` opcional (P9b) |

### C4. Risco / Severidade

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P9 | Escala CVSS | `:hasSeverity` (string, em `AttackPattern`) e `:maxSeverity` (string minúscula, em `Scope`) | **A**: classe enumerada `:SeverityRating` = {`:Severity_None` (rótulo alternativo "Info"), `:Severity_Low`, `:Severity_Medium`, `:Severity_High`, `:Severity_Critical`} + `AllDifferent` + anotação das faixas (0,0 / 0,1–3,9 / 4,0–6,9 / 7,0–8,9 / 9,0–10,0); `:hasSeverityRating` Functional (domínio `Report ⊔ Scope ⊔ AttackPattern ⊔ BountyTableEntry`). As strings atuais ficam (retrocompatibilidade) | A Tabela 22 do CVSS v4.0 define estes cinco níveis. "Info" não é termo do CVSS: equivale a "None". A H1 usa os mesmos descritores | https://www.first.org/cvss/v4.0/specification-document (2026-11-04); https://docs.hackerone.com/organizations/bounty-tables.html (2026-11-04) | A R1 do v7 usa 4 faixas, sem None; é compatível, porque None só cobre 0,0. Não altera regras | Baixo. Fica a duplicação string/objeto, a documentar (a ligação por regra fica para depois, se aprovada) |
| P9b | Prioridade VRT (opcional) | `vrtPriorityTypical/Best` (string "P1"…"P5") | **A**: `:VRTPriority` = {P1…P5} + `:forPriority` (em `BountyTableEntry`) | A taxonomia VRT da Bugcrowd usa P1–P5 | https://bugcrowd.com/vulnerability-rating-taxonomy (cache local `cache/catalogs/bugcrowd_vrt.json`, versão 2026-07-08); https://docs.bugcrowd.com/researchers/receiving-rewards/getting-rewarded/ (2026-11-04) | Nenhum | Baixo |

### C5. Disclosure

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P10 | Política de divulgação | Não modelado (`Report` só tem comentário "divulgação coordenada") | **A**: `:DisclosurePolicy` = {`:CoordinatedDisclosure`, `:FullDisclosure`, `:NonDisclosure`} + `AllDifferent`; `Program hasDisclosurePolicy max 1` | CVD segundo o CERT/CC; "disclosure disabled" na H1 = não-divulgação | https://certcc.github.io/CERT-Guide-to-CVD/tutorials/terms/cvd (2026-11-04); https://docs.hackerone.com/organizations/disclosure.html (2026-11-04); ISO/IEC 29147:2018 (só o escopo, texto pago) https://committee.iso.org/standard/72311.html (2026-11-04) | Nenhum | **Médio**: a definição de *full disclosure* clássica (divulgação imediata, haja correção ou não) só a encontrei em fonte secundária (d-5) |
| P11 | Abrangência do disclosure do relatório (H1) | — | **A**: `:ReportDisclosureScope` = {`:FullReportDisclosure`, `:LimitedReportDisclosure`} em `Report` | Na H1, "Full" vs. "Limited" diz respeito ao **conteúdo** divulgado do relatório, não à política. Sem esta separação, confundir-se-ia com P10 | https://docs.hackerone.com/hackers/disclosure.html (2026-11-04) | Nenhum | Baixo. Só existe na H1 (documentar) |
| P12 | DisclosureTimeline | — | **A**: `:DisclosureTimeline` com `daysToDisclosure` (xsd:integer), `postPatchDays` (xsd:integer), `inTheWildDays` (opcional); `Program hasDisclosureTimeline max 1`. Indivíduos de referência: H1 padrão (30 dias após Resolved, sem objeção), Project Zero (90+30; 7 para exploração ativa), CERT/CC (45) | Prazos públicos documentados | https://hackerone.com/disclosure-guidelines (2026-11-04); https://projectzero.google/vulnerability-disclosure-policy.html (2026-11-04); CERT/CC 45 dias, citado em https://securityaffairs.com/116921/security/project-zero-updates-vulnerability-disclosure-policy.html (2026-11-04) | Nenhum | Médio: as diretrizes da H1 aparecem como v1.3 (2026-07-27), a reconfirmar; o valor de 45 dias do CERT/CC vem de fonte secundária e é preciso a página do próprio CERT/CC |

### C6. Duplicate

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P13 | Original vs. duplicata | Só `:status "Duplicate"` possível (string) | **A**: `:duplicateOf` (`Report → Report`, Functional, Irreflexive, Asymmetric); `:DuplicateReport ≡ Report ⊓ ∃duplicateOf.Report`; `:OriginalReport ⊑ Report`; `OriginalReport` disjunta de `DuplicateReport` | H1: duplicata = já reportado ou conhecido, atribuída ao original. Bugcrowd: é obrigatório indicar o original. Intigriti: ligação ao "parent" obrigatória | https://docs.hackerone.com/hackers/report-states.html (2026-11-04); https://docs.bugcrowd.com/customers/submission-management/submission-status (2026-11-04); https://kb.intigriti.com/en/articles/5191201-handling-submissions (2026-11-04) | Nenhum nos dados atuais | Médio: na Bugcrowd o original pode estar **fora** da plataforma, e nesse caso o range `Report` é restritivo (usar anotação para o original externo) |
| P14 | DuplicateStatus | — | **Nenhuma classe nova** (proposta: não criar). O estado continua em `:status`; a classe `DuplicateReport` cobre a semântica | A Bugcrowd faz a duplicata herdar o estado do original; na H1, Duplicate é um estado fechado. Não há conceito transversal de "estado de duplicata" | idem P13 | — | Vai para revisão (d-7) |

### C7. Hat + reputação

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P15a | WhiteHat | Ausente | **A**: `:WhiteHat ⊑ :Researcher`; `AllDisjointClasses(WhiteHat, GrayHat, BlackHat)`; `WhiteHat` disjunta de `RedHat`. **Não** a tornar ≡ `AuthorizedResearcher` | White hat = autorizado; black hat = sem autorização e malicioso; gray hat = acesso não autorizado com intenção de ajudar | Falk, C. (2004) *Gray Hat Hacking: Morally Black and White*, CERIAS TR 2004-20, https://www.cerias.purdue.edu/assets/pdf/bibtex_archive/2004-20.pdf (2026-11-04) | CBR e CQ do v7 inalterados (`WhiteHat` não é `ThreatActor`) | **Alto, decisão tua (d-8)**: o módulo diz que a mesma pessoa pode ser gray hat e pesquisador. Com a disjunção, um indivíduo declarado `WhiteHat` e `GrayHat` torna a ontologia inconsistente |
| P15b | RedHat | Existe, disjunta de Black/Gray | **Manter** (preservar), mas assinalar como sem fonte académica | — | Não encontrei fonte | — | Revisão (d-4) |
| P16 | Reputação | `:hasSkillLevel` "Junior/Senior/Elite" (declarado, sem fonte) | **A**: `:ResearcherProfile` (perfil por plataforma: `Researcher hasProfile`, `onPlatform exactly 1 BugBountyPlatform`) com `reputationPoints`, `signal`, `impact` (xsd:decimal, max 1). **L**: níveis novice/intermediate/expert/elite | A H1 mede reputação, Signal e Impact (números e percentis); a Intigriti mede pontos de reputação; a Bugcrowd, pontos e rank. **Nenhuma usa a escala novice→elite** | https://docs.hackerone.com/hackers/reputation.html (2026-11-04); https://docs.hackerone.com/hackers/signal-and-impact.html (2026-11-04); https://kb.intigriti.com/en/articles/3379630-leaderboard-reputation-and-streak (2026-11-04); https://docs.bugcrowd.com/researchers/managing-account/performance-metrics/rank (2026-11-04) | `hasSkillLevel` + SHACL `ResearcherShape` ficam como estão | Baixo para os números; os níveis vão para revisão (d-2) |

### C8. Platform

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P17 | Plataformas | `:BugBountyPlatform` com HackerOne e Bugcrowd | **A** indivíduos: `Platform_YesWeHack`, `Platform_Intigriti`, `Platform_Immunefi`, `Platform_Vulbox` (漏洞盒子), `Platform_Butian` (补天). Manter o nome `:BugBountyPlatform`, com rótulo "Platform". `Platform_Seebug` só após revisão (d-6) | Plataformas existentes, com documentação pública | YesWeHack https://yeswehack.com/programs/yes-we-hack (2026-11-04); Intigriti https://kb.intigriti.com/en/articles/3379382-submission-lifecycle (2026-11-04); Immunefi https://immunefi.com/severity-classification-systems/ (2026-11-04); Butian https://www.butian.net/ e https://www.qianxin.com/product/detail/pid/452 (奇安信, 2026-11-04); Vulbox/斗象科技 https://www.secrss.com/articles/8945 (2026-11-04) | Nenhum (o `hostedOn` Functional mantém-se) | Baixo para os ocidentais. Para Vulbox há fontes de imprensa chinesa, não a página oficial (vulbox.com não foi lida) |

### C9. Ligação com vulnerabilidades / CWE

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P18 | `targetsVulnerability` | `AP_IDOR→CWE_639`, `AP_XSS→CWE_79`, `AP_SQLInjection→CWE_89` já existem via `:targetsCWE`; `reportsVulnerability` sem uso | **A**: `:targetsVulnerability` com domínio `Report` (e `BugBountyProgram`, ver risco) e range `:Weakness`. **Não** a declarar ⊑ `:relatedWeakness` | Uma ontologia de vulnerabilidades ancorada na CWE é prática estabelecida (SEPSES; modelo semântico ATT&CK–CAPEC–CWE) | CWE 5.0 (cache local `cache/catalogs/cwe.json`, 2026-10-28); Kiesling et al. 2019, ISWC, https://link.springer.com/doi/10.1007/978-3-030-30796-7_13 (2026-11-04); Brazhuk, arXiv:2112.04231, https://arxiv.org/pdf/2112.04231 (2026-11-04) | Se fosse ⊑ `relatedWeakness`, o domínio `AttackPattern` do v7 faria do programa um `AttackPattern`, logo **inconsistência** (disjunção) | Médio: o significado no nível do *programa* ("classes de fraqueza aceites") não está fundamentado (d-9) |
| P19 | Subvariantes CWE | Só CWE-79/89/639 | **Não adicionar agora** (instrução tua). Lista pronta, tirada do catálogo local CWE 5.0: 79 → 80, 81, 83, 84, 85, 86, 87; 89 → 564; 639 → 566 | Nota: XSS refletido/armazenado/DOM **não** são nós CWE, mas nós VRT (já em `bb:vrtNode`) | `cache/catalogs/cwe.json` (CWE 5.0, 2026-10-28) | — | Decisão (d-10) |

### C10. Ferramentas do hunter (novo ficheiro `ontology/hunter_tools.ttl`)

| # | Item | Estado atual | Mudança proposta | Justificativa | Fonte | Impacto | Risco |
|---|---|---|---|---|---|---|---|
| P20 | Classes | Inexistente | **A**: `:HunterTool` (disjunta dos tipos de topo do v7 e das classes BB); `:ReconTool`, `:ScanningTool`, `:ThreatIntelSource` ⊑ `HunterTool`, **não** disjuntas entre si (o Nuclei consulta Shodan/Censys via *uncover*) | Fases de descoberta (§4.1), identificação de portas/serviços (§4.2) e varredura de vulnerabilidades do NIST SP 800-115; reconhecimento passivo (T1596.005) vs. ativo (T1595) do ATT&CK | NIST SP 800-115, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf (2026-11-04); https://attack.mitre.org/techniques/T1596/005/ (2026-11-04); ATT&CK 16.1 (cache local `cache/catalogs/attack-16.1.json`) | `compose()` e `verificar_ontologia.py` teriam de incluir o ficheiro novo | Baixo |
| P21 | Indivíduos | — | `Tool_Shodan`, `Tool_Censys` (ReconTool; T1596.005); `Tool_Nmap` (ScanningTool; descoberta de rede e auditoria, T1595.001); `Tool_Nuclei` (ScanningTool; scanner por templates, T1595.002); `TI_CISA_KEV`, `TI_NVD` (ThreatIntelSource; já usadas como `bb:dataSource`) | Cada ferramenta tem documentação pública | https://attack.mitre.org/techniques/T1596/005/ (Shodan, Censys); https://nmap.org/ (descrição citada por espelhos; a página oficial não foi lida diretamente); https://docs.projectdiscovery.io/ (Nuclei); https://www.cisa.gov/known-exploited-vulnerabilities-catalog (2026-11-04) | Nenhum | Baixo. Confirmar a página oficial do nmap.org antes de citar |
| P22 | Propriedades | — | `:usesTool` (`Researcher ⊔ ThreatActor` → `HunterTool`); `:discovers` (`ReconTool` → `Scope ⊔ Asset`); `:tests` (`ScanningTool` → `Weakness`); `:informs` (`ThreatIntelSource` → `Vulnerability`); anotação `bb:attackTechnique` ("T1596.005"…) | O `:uses` atual tem range `AttackPattern`. Reutilizá-lo para ferramentas classificaria a ferramenta como `AttackPattern`, que é disjunta de `HunterTool`, logo inconsistência | idem P20; Chu & Lisitsa 2020 (ICISSP), https://www.scitepress.org/Papers/2020/91710/ (2026-11-04) | Nenhum | Baixo |

### Fundamentação na literatura (parcial, não como ontologia pronta)

| Camada | Trabalho | Fonte |
|---|---|---|
| Economia de bug bounty | Finifter, Akhawe & Wagner (2013), *An Empirical Study of Vulnerability Rewards Programs*, USENIX Security, pp. 273–288 | https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/finifter |
| Economia de bug bounty | Maillart, Zhao, Grossklags & Chuang (2017), *Given enough eyeballs…*, J. Cybersecurity 3(2):81–90, doi:10.1093/cybsec/tyx008 | https://arxiv.org/abs/1608.03445 |
| Economia, **China** | Zhao, Grossklags & Liu (2015), *An Empirical Study of Web Vulnerability Discovery Ecosystems*, CCS, pp. 1105–1117, doi:10.1145/2810103.2813704, sobre **Wooyun** (乌云) vs. HackerOne | https://dblp.org/rec/conf/ccs/ZhaoGL15.html |
| Ontologia de vulnerabilidades (CWE) | Kiesling et al. (2019), SEPSES KG, ISWC, LNCS 11779:198–214 | https://link.springer.com/doi/10.1007/978-3-030-30796-7_13 |
| ATT&CK / threat intel | Brazhuk, modelo semântico ATT&CK–CAPEC–CWE (OWL) | https://arxiv.org/pdf/2112.04231 |
| Processo de pentest | Chu & Lisitsa (2020), *Ontology-based Automation of Penetration Testing*, ICISSP; Stepanova et al. (2015), doi:10.1145/2799979.2799995 | https://www.scitepress.org/Papers/2020/91710/ |
| Ética (Hat) | Falk (2004), CERIAS TR 2004-20 | https://www.cerias.purdue.edu/assets/pdf/bibtex_archive/2004-20.pdf |
| Chinesa, pentest | Artigo do *Journal of Beihang University* (2023), biblioteca de ontologia de padrões de vulnerabilidade de software aplicada a pentest, doi:10.13700/j.bh.1001-5965.2022.0783 | https://bhxb.buaa.edu.cn/bhzk/en/article/doi/10.13700/j.bh.1001-5965.2022.0783 |
| Chinesa, KG de vulnerabilidades | 《融合双模态感知的漏洞知识图谱构建与补全方法》 (电子学报), KG sobre CVE/CWE/CAPEC/ATT&CK | https://www.ejournal.org.cn/ (PDF encontrado na pesquisa) |
| Chinesa, plataformas de 众测 | 《基于临时团队的信息安全众测平台知识共享演化博弈研究》 (科技管理研究), modelo teórico, não empírico | https://kjglyj.ijournals.cn/kjglyj/article/abstract/20190729009 |

Formulação sugerida para o artigo (com a ressalva pedida): *"Não identificamos uma ontologia OWL consolidada de bug bounty na literatura internacional ou chinesa indexada que consultámos. Os trabalhos existentes cobrem vulnerabilidades (CWE/CVE), threat intelligence (ATT&CK) e o processo de pentest, mas não o programa de recompensa como um todo."* A busca foi feita na web aberta, não em CNKI/Wanfang/Scopus. Essa limitação deve constar do texto.

---

## (d) Itens para revisão humana (falta de fonte ou decisão de modelação)

1. **Solo/Colaborativo como tipo de programa**: não há fonte. Proposta alternativa no nível do relatório (P3).
2. **Níveis novice/intermediate/expert/elite**: nenhuma plataforma os usa. O `hasSkillLevel` "Junior/Senior/Elite" atual também não tem fonte (manter ou rever?).
3. **Tipo de ativo `API`**: ausente da doc oficial da H1; só aparece numa fonte secundária do enum da API.
4. **`:RedHat`**: sem fonte académica encontrada. Manter (preserva o que existe) ou remover?
5. **Definição de `:FullDisclosure`** (divulgação imediata): só encontrei fonte secundária. É preciso uma primária (p. ex. CERT/CC Guide, secção de terminologia).
6. **Seebug**: é base de vulnerabilidades e troca de PoC (知道创宇), não claramente uma plataforma de bug bounty. Classificar como `BugBountyPlatform` ou noutra classe? Vulbox/Butian: confirmar nas páginas oficiais (vulbox.com e butian.net, esta última aberta só via pesquisa).
7. **DuplicateStatus**: proponho não criar (P14). Confirmas?
8. **Disjunção WhiteHat/GrayHat/BlackHat vs. o desenho atual** (uma pessoa pode ter os dois papéis): a disjunção pedida proíbe isso no nível do indivíduo.
9. **`targetsVulnerability` no nível do programa**: que significa? Classes de fraqueza aceites, excluídas, ou só no relatório?
10. **Subvariantes CWE** (80–87, 564, 566): incluir já ou adiar?
11. **Managed/Self-managed**: fontes de fornecedor (marketing). Aceitas como suficiente?
12. **Metadados dos artigos chineses** (autores, ano, volume): não verificados em CNKI; é preciso confirmar antes de citar.
13. **Reconfirmar**: versão das diretrizes de disclosure da H1 (v1.3, 2026-07-27), número de níveis do Immunefi v2.3 (4 vs. 5, fontes divergentes), literais do enum `asset_type` da API H1, os 45 dias do CERT/CC na fonte primária.

## (e) Pergunta

**Aprovas as mudanças listadas para o Passo 2?** (Podes aprovar por número: P1…P22, e decidir os itens d-1…d-13.)
