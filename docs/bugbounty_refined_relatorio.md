# Relatório de mudanças — lapidação do módulo de bug bounty (Passo 2)

Data: 2026-11-04 · Aprovação: "Aprovo P1–P22" · Proposta: [bugbounty_lapidacao_passo0-1.md](bugbounty_lapidacao_passo0-1.md)
Fontes acessadas em 2026-11-04 (URLs em `dcterms:source` de cada termo e na proposta).
**Nada commitado nem enviado.**

## Diff

Só há dois ficheiros novos. Nenhum ficheiro existente foi alterado (`OntoBugBounty.ttl` e `shapes_bugbounty.ttl` estão intactos face ao HEAD `de491d4`). Nenhum código Python foi tocado.

```
?? ontology/bugbounty_refined.ttl   (1018 triplas)  P1–P19
?? ontology/hunter_tools.ttl        (162 triplas)   P20–P22
```

Os dois ficheiros compõem-se depois de `OntoBugBounty.ttl`, sem `owl:imports`. Desde a revisão de 2026-11-06 estão ligados a `ingest_bugbounty.compose()` e a `verificar_ontologia.py` (ver "Revisão para entrega", no fim).

## Resultados do raciocinador

| Composição | Triplas | HermiT | Insatisfatíveis |
|---|---|---|---|
| v7 + ext + evo + OntoBugBounty (base, bb-1) | 2570 | consistente | 0 |
| base + bugbounty_refined | 3588 | consistente | 0 |
| base + hunter_tools | — | consistente | 0 |
| base + ambos | 3747 | **consistente** | **0** |

- **Pellet + SWRL:** consistente. As regras BB-1 e BB-2 dão os mesmos resultados com e sem os ficheiros novos (4 `EliteResearcher`, 6 `AuthorizedResearcher`, `Report_001` e `Report_003` prioritários, 32 CVE).
- **CQ1–CQ8 do v7:** iguais ao esperado na base e na composição completa.
- **SHACL existente** (v7 + ingestão + evo + bug bounty) sobre a composição completa: conforme, 0 violações. Nenhuma forma SHACL nova foi escrita.
- **Classificação automática (HermiT)** dos indivíduos existentes:
  - `Scope_DemoFintech_App` e `_Api` → `InScopeItem`, `WebApplicationScope`, `SpecificScope`;
  - `Scope_DemoFintech_Net` → `InScopeItem`, `NetworkScope` (inferido `NetworkScope ⊑ SpecificScope`);
  - `Scope_DemoSaaS_Wildcard` → `InScopeItem`, `WildcardScope`;
  - `Reward_001` → `MonetaryReward`;
  - com 2 pesquisadores declarados distintos, `Report_002` → `CollaborativeReport`;
  - com `duplicateOf`, `Report_003` → `DuplicateReport`.
- **Testes negativos** (cada um deve tornar a ontologia inconsistente; os 10 deram inconsistente):
  1. WhiteHat e GrayHat no mesmo indivíduo;
  2. `duplicateOf` reflexivo;
  3. original e duplicata ao mesmo tempo;
  4. programa público e privado;
  5. managed e self-managed;
  6. escopo dentro e fora;
  7. recompensa não monetária com valor;
  8. duas severidades no mesmo relatório;
  9. ferramenta ligada por `:uses`;
  10. `targetsVulnerability` como subpropriedade de `relatedWeakness`.

  Os testes 9 e 10 confirmam as justificativas de P22 e de P18.
- **Testes positivos** (consistentes): relatório colaborativo; programa com visibilidade, gestão, política e prazos; relatório → CWE-89; pesquisador usa Nuclei e Shodan descobre escopo.
- **Suíte existente** (`python -m pytest -q tests`): ver secção final.

Estas verificações estão agora no repositório, em `tests/test_bugbounty_refined.py` (ver "Revisão para entrega").

## Termos adicionados

**bugbounty_refined.ttl:** 33 classes, 14 propriedades de objeto, 10 de dados, 27 indivíduos, 4 anotações (`bb:proposal`, `bb:sourceAccessed`, `bb:reviewNote`, `bb:cvssRange`).
**hunter_tools.ttl:** 4 classes, 4 propriedades de objeto, 6 indivíduos, 1 anotação (`bb:attackTechnique`).
**Termos existentes alterados** (só adições de axiomas, sem remoções):
- `:eligibleForSubmission` e `:scopeType` passam a `owl:FunctionalProperty`;
- `:BugBountyProgram ⊑ hasVisibility exactly 1 ProgramVisibility`;
- `:BugBountyPlatform` ganha o rótulo "Platform"@en;
- `:BlackHat` e `:GrayHat` ganham `dcterms:source` (Falk 2004);
- `:RedHat` e `:hasSkillLevel` ganham `bb:reviewNote`.

**Removido:** nada.

| # | Termos | Axiomas principais | Fonte |
|---|---|---|---|
| P1 | `ProgramVisibility` {`Visibility_Public`, `Visibility_Private`}, `hasVisibility`, `PublicProgram`, `PrivateProgram` | `oneOf` + `AllDifferent`; Functional; `Program ⊑ =1 hasVisibility`; classes definidas por `hasValue`; disjuntas | HackerOne (privados vs. públicos); YesWeHack (G-Cloud SDD) |
| P2 | `ProgramManagementModel` {`Management_Managed`, `Management_SelfManaged`}, `hasManagementModel`, `ManagedProgram`, `SelfManagedProgram` | `oneOf`; Functional (≤1, opcional); disjuntas | Bugcrowd (glossário); Intigriti (blog). `reviewNote`: fonte de fornecedor |
| P3 | `CollaborativeReport`, `SoloReport` | `≥2 submittedBy.Researcher` / `≤1`; disjuntas | HackerOne (Collaboration); Intigriti (report collaboration) |
| P4 | `InScopeItem`, `OutOfScopeItem` | `eligibleForSubmission value true/false`; disjuntas; Functional | HackerOne (asset details and scoping). `reviewNote`: mapeamento a confirmar |
| P5 | `WebApplicationScope`, `MobileAppScope`, `NetworkScope`, `HardwareScope`, `SourceCodeScope`, `ExecutableScope`, `SmartContractScope`, `AIModelScope` | definidas por literais de `scopeType`; `AllDisjointClasses`. **Sem `API` e sem `Domain`** | HackerOne (asset types); enum: anysite.io (secundária, `reviewNote`) |
| P6 | `WildcardScope`, `SpecificScope` | `scopeType value "WILDCARD"` / `Scope ⊓ ¬WildcardScope`; `scopeType` Functional | HackerOne (asset types) |
| P7 | `MonetaryReward`, `NonMonetaryReward`, `rewardKind` | `≡ Reward ⊓ ∃rewardAmount`; disjuntas | Bugcrowd (cash rewards); HackerOne ("thanks, swag, and/or bounties") |
| P8 | `BountyTable`, `BountyTableEntry` (= RewardRange), `hasBountyTable`, `hasEntry`, `forSeverity`, `entryMin/MaxAmount`, `entryCurrency` | `Entry ⊑ =1 forSeverity.SeverityRating`; valores Functional | HackerOne (bounty tables); Bugcrowd (reward ranges) |
| P9 | `SeverityRating` {None (Info), Low, Medium, High, Critical}, `hasSeverityRating` | `oneOf` + `AllDifferent`; Functional; faixas em `bb:cvssRange` | FIRST CVSS v4.0 (Tabela 22); HackerOne |
| P9b | `VRTPriority` {P1…P5}, `forPriority` | `oneOf` + `AllDifferent`; Functional | Bugcrowd VRT |
| P10 | `DisclosurePolicy` {`CoordinatedDisclosure`, `FullDisclosure`, `NonDisclosure`}, `hasDisclosurePolicy` | `oneOf` + `AllDifferent`; Functional | CERT/CC CVD Guide; HackerOne (disclosure); ISO/IEC 29147 (escopo). `FullDisclosure`: `reviewNote` |
| P11 | `ReportDisclosureScope` {`FullReportDisclosure`, `LimitedReportDisclosure`}, `hasReportDisclosureScope` | `oneOf`; Functional | HackerOne (hacker disclosure) |
| P12 | `DisclosureTimeline`, `hasDisclosureTimeline`, `daysToDisclosure`, `postPatchDays`, `inTheWildDays`; indivíduos `Timeline_HackerOneDefault` (30 após Resolved), `Timeline_ProjectZero` (90/30/7), `Timeline_CERTCC` (45) | Functional; xsd:integer | HackerOne disclosure guidelines; Project Zero; CERT/CC via fonte secundária (`reviewNote`) |
| P13 | `duplicateOf`, `DuplicateReport`, `OriginalReport` | Functional, Irreflexive, Asymmetric; `DuplicateReport ≡ Report ⊓ ∃duplicateOf.Report`; disjuntas | HackerOne (report states); Bugcrowd (submission status); Intigriti (handling submissions) |
| P14 | — (sem `DuplicateStatus`, como aprovado) | — | — |
| P15a | `WhiteHat` | `⊑ Researcher`; `AllDisjointClasses(WhiteHat, GrayHat, BlackHat)`; `WhiteHat ⊥ RedHat` | Falk (2004), CERIAS TR 2004-20 |
| P15b | `RedHat` mantida | `reviewNote` (sem fonte) | — |
| P16 | `ResearcherProfile`, `hasProfile`, `onPlatform`, `reputationPoints`, `signal`, `impact` | `Profile ⊑ =1 onPlatform.BugBountyPlatform`; valores Functional | HackerOne (reputation; signal and impact); Intigriti (reputation); Bugcrowd (rank) |
| P17 | `Platform_YesWeHack`, `Platform_Intigriti`, `Platform_Immunefi`, `Platform_Vulbox` (漏洞盒子), `Platform_Butian` (补天). **Seebug não entrou** | indivíduos de `BugBountyPlatform` | páginas das plataformas; Vulbox via secrss.com (`reviewNote`) |
| P18 | `targetsVulnerability` | domínio `Report ⊔ BugBountyProgram`, contradomínio `Weakness`; **não** ⊑ `relatedWeakness` | CWE 5.0; SEPSES (Kiesling et al. 2019); Brazhuk (arXiv:2112.04231) |
| P19 | — (subvariantes só em comentário) | — | catálogo CWE 5.0 local |
| P20 | `HunterTool`, `ReconTool`, `ScanningTool`, `ThreatIntelSource` | subclasses não disjuntas; `HunterTool` disjunta dos tipos de topo, de `ThreatActor` e das classes BB | NIST SP 800-115; ATT&CK T1596.005; Chu & Lisitsa (2020) |
| P21 | `Tool_Shodan`, `Tool_Censys` (T1596.005), `Tool_Nmap` (T1595.001), `Tool_Nuclei` (T1595.002), `TI_CISA_KEV`, `TI_NVD` | indivíduos + `bb:attackTechnique` | shodan.io, censys.com, nmap.org, docs.projectdiscovery.io (todas lidas em 2026-11-04); KEV: a página deu 403, cita-se `refs_v7.bib` |
| P22 | `usesTool`, `discovers`, `tests`, `informs` | domínios e contradomínios conforme a proposta | idem P20 |

## O que ficou pendente (não implementado, por estar em revisão na proposta)

Itens d-1 a d-13 da proposta. No ficheiro, cada um está marcado com `bb:reviewNote` quando toca num termo existente.

1. **Disjunção White/Gray/Black (d-8):** implementada como aprovaste. Consequência: um mesmo indivíduo não pode ser `WhiteHat` e `GrayHat` (verificado). O comentário de `:Researcher` no bb-1 ainda diz que a mesma pessoa pode ter os dois papéis. Isso continua válido para `Researcher`/`ThreatActor`, mas já não para `WhiteHat`/`GrayHat`.
2. **`BountyTableEntry ⊑ =1 forSeverity`:** é exatamente o que aprovaste. Nas tabelas da Bugcrowd, indexadas por prioridade, a linha fica sem severidade conhecida, o que o mundo aberto tolera.
3. **Integração no carregador:** feita na revisão de 2026-11-06. Continua por fazer que a ingestão da HackerOne grave `hasVisibility` (P1); é uma alteração opcional ao código de ingestão.

## Suíte de testes existente

`python -m pytest -q tests`, em 2026-11-04: **139 passed, 1 skipped**, 0 falhas (6 min 34 s). Os warnings são DeprecationWarning do rdflib, como antes.
Atenção: a suíte não carrega os ficheiros novos, porque estes ainda não estão em `compose()`. Ela só prova que nada existente foi quebrado. A cobertura dos ficheiros novos vem da validação descrita acima.

Nota: durante a sessão, o HEAD avançou para `5f8cf59` (commit do pipeline VCDB, feito fora desta sessão). Esse commit não toca em `ontology/`, no v7, em `ingest_bugbounty.py` nem nos testes de bug bounty.

## Revisão para entrega (2026-11-06)

Corrigido no branch `bugbounty-lapidacao-bb2`:
1. **Ligação:** `ingest_bugbounty.compose()` (constantes `REFINED` e `HUNTER`) e `verificar_ontologia.py` (composição "modulo OntoBugBounty") carregam os dois ficheiros.
2. **Testes no repositório:** `tests/test_bugbounty_refined.py`, com 24 testes:
   - os ficheiros carregados pelo `compose()`;
   - HermiT consistente e 0 classes insatisfatíveis;
   - fonte, proposta e rótulo em cada termo;
   - no máximo um `rdfs:label` por língua;
   - nenhum termo do bb-1 redefinido;
   - classificação automática dos escopos, da recompensa, do relatório colaborativo e da duplicata;
   - 11 defeitos recusados pelo HermiT (os 10 anteriores e `HunterTool` disjunta de `SeverityRating`);
   - 4 usos válidos que se mantêm consistentes.
3. **Rastreabilidade:** cada classe/propriedade passa a ter `dcterms:source` e `bb:sourceAccessed`, e cada termo `bb:proposal`. Foi acrescentado um bloco no fim de cada TTL, sem axiomas lógicos novos. `signal`/`impact` citam só a HackerOne; `ThreatIntelSource`/`informs` citam o KEV e o NVD.
4. **Rótulos:** "Info" (`Severity_None`) e "Reward range" (`BountyTableEntry`) passam a `skos:altLabel`.
5. **Disjunção:** `HunterTool` passa a ser disjunta das classes de valor do bb-2.
6. **Documentação:** secção bb-2 no `README_BugBounty.md`; contagem de testes no `README.md` e no `verificar_ontologia.py` (estava em 108); nota do nmap.org na proposta.

Resultados:
- `python -m pytest -q tests`: **163 passed, 1 skipped** (7 min 35 s);
- `python verificar_ontologia.py`: **TUDO OK, 42/42**, incluindo HermiT, Pellet e SHACL do módulo com os ficheiros novos e as CQ1–CQ8.

Em aberto (não bloqueiam a entrega, mas devem ser declarados):
- os itens d-1 a d-13 da proposta (decisões humanas e fontes secundárias, marcados com `bb:reviewNote`);
- a gravação de `hasVisibility` pela ingestão HackerOne.
