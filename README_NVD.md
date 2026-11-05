# Enriquecimento NVD em tempo real no webhook SOAR

Quando um alerta chega ao `POST /alert` com um `cve` que **não existe** na ontologia, o webhook:

1. verifica a base com SPARQL (`ASK { ?v a :Vulnerability ; :cveId "CVE-…" }`);
2. consulta a **NVD API 2.0** (ou a cache local de 24 h);
3. cria o ramo `Vulnerability` + `Weakness` (CVE, CVSS, CWE) com o vocabulário do OntoCSIRT;
4. valida o ramo no grafo completo com **SHACL** (`shapes_v7.ttl` + `shapes_ingest.ttl` + `shapes_evo.ttl`) e **HermiT**;
5. grava-o no disco, no ficheiro de dados (`--acquired`, por omissão `OntoCSIRT_v7_acquired.ttl`), e recarrega a base;
6. corre o **Pellet** com as regras SWRL (risco R1, fraqueza partilhada R5, solução candidata R6) e a recuperação CBR;
7. devolve a ação recomendada ao SOAR.

Se não for possível (NVD fora do ar, CVE inexistente, registo incompleto), devolve um **fallback de revisão manual** em vez de inventar uma recomendação.

O código está em `nvd_enricher.py` (classe `NVDEnricher`) e em `soar_webhook.py` (`Engine.cve_in_kb`, `Engine.enrich_cve`, início de `Engine.handle`).

> O `OntoCSIRT_v7.ttl` (base do artigo) **nunca é alterado**: o `NVDEnricher` recusa-o como destino. Os ramos novos vão para o ficheiro de dados, que o webhook carrega junto com a base.

---

## 1. Configurar a chave da API do NVD

Sem chave a API pública aceita **5 pedidos por 30 s**; com chave, **50 por 30 s**. A chave é gratuita: <https://nvd.nist.gov/developers/request-an-api-key>.

```bash
# Linux / macOS / Git Bash
export NVD_API_KEY="a-sua-chave"
```

```powershell
# Windows PowerShell (sessão atual)
$env:NVD_API_KEY = "a-sua-chave"
# permanente para o utilizador
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "a-sua-chave", "User")
```

Também pode passar `--nvd-api-key` ao webhook. A chave vai só no cabeçalho `apiKey` do pedido ao NVD e não é registada em lado nenhum.

O limite é aplicado por **janela deslizante de 30 s, partilhada por todas as threads do webhook**.

**Orçamento de tempo:** `--nvd-max-wait` (por omissão 35 s) limita o passo NVD **inteiro**: as esperas pelo limite, os pedidos e as novas tentativas. O timeout de cada pedido é reduzido ao que resta do orçamento. Se ele se esgotar, o alerta recebe o fallback em vez de ficar à espera; o tempo de raciocínio (Pellet) vem depois e não conta para este limite.

## 2. Arrancar o webhook

```bash
python soar_webhook.py --kb OntoCSIRT_v7_real.ttl --token SEGREDO
```

| Opção | Por omissão | Efeito |
|---|---|---|
| `--acquired` | `OntoCSIRT_v7_acquired.ttl` | ficheiro de dados onde os ramos novos são gravados (e lido no arranque) |
| `--nvd-api-key` | `$NVD_API_KEY` | 50 pedidos/30 s em vez de 5 |
| `--nvd-cache-hours` | `24` | validade da cache |
| `--nvd-max-wait` | `35` | tempo máximo do passo NVD (esperas, pedidos e novas tentativas) antes do fallback |
| `--no-nvd-enrich` | — | desliga o enriquecimento (comportamento anterior) |

## 3. Como funciona a cache

- **Onde fica:** `cache/nvd_<CVE>.json`, por exemplo `cache/nvd_CVE-2024-3400.json`.
- **Conteúdo:** `{"cve_id", "fetched_at" (epoch), "found", "record"}`, em que `record` é o registo NVD tal como veio da API.
- **Validade:** 24 h para CVEs encontradas. Para respostas "não encontrada" a validade é só de 1 h: uma CVE acabada de reservar costuma aparecer no NVD pouco depois.
- **Dentro da validade** o NVD não é consultado (a resposta do webhook mostra `"nvd": {"source": "cache", "age_seconds": …}`).
- **Fora da validade** volta a consultar e reescreve o ficheiro (escrita atómica).
- **Ficheiro corrompido:** é ignorado e substituído na consulta seguinte.
- **Forçar nova consulta:** apague o ficheiro (`rm cache/nvd_CVE-2024-3400.json`).
- **Outra cache:** a de investigação do ETL (`cache/nvd/`, usada por `ingest_real_cases.py`) é separada e não expira, para os resultados do artigo serem reprodutíveis.

## 4. Testar manualmente com `curl`

Com o webhook a correr (secção 2), envie um alerta com uma CVE que ainda não esteja na base:

```bash
curl -s -X POST http://127.0.0.1:8088/alert \
  -H "X-OntoCSIRT-Token: SEGREDO" -H "Content-Type: application/json" \
  -d '{"src_ip":"198.51.100.23","attack_type":"cmdi","target":"Gateway_1","cve":"CVE-2024-3400","attribute":"confidentiality","alert_id":"TESTE-1"}'
```

Resposta (resumida; execução real em 2026-11-04 sobre `OntoCSIRT_v7_real.ttl`). Na primeira consulta `nvd.source` é `"api"`; nas seguintes, dentro das 24 h, é `"cache"` com a idade em segundos:

```json
{
 "action": "Apply patch",
 "action_iri": "CoA_Patch",
 "playbook": "open_patch_ticket",
 "risk_level": "Critical",
 "confidence": 0.359,
 "requires_human_approval": true,
 "nvd_enrichment": {
  "vulnerability": "Vuln_CVE_2024_3400", "cwe": "CWE-77", "category": "CommandInjectionWeakness",
  "cvss": 10.0, "cvss_version": "3.1", "vuln_status": "Analyzed", "status": "written",
  "nvd": {"source": "api", "attempts": 1, "rate_limit_wait_seconds": 0.0},
  "gate": {"shacl_conforms": true, "hermit": {"consistent": true, "unsatisfiable_classes": []}}
 },
 "assumptions": ["CVE-2024-3400 adquirida do NVD em tempo real (api): CVSS 10.0, CWE-77",
                 "CWE da vulnerabilidade CVE-2024-3400 na base: CWE-77"]
}
```

- `risk_level` vem do Pellet (regra R1a: CVSS ≥ 9.0 → Critical).
- O CVSS vem do NVD, nunca do alerta nem de um modelo.
- `requires_human_approval` é `true` porque a confiança está abaixo de `--min-confidence` (0,5).

Repita o mesmo pedido com outro `alert_id`: agora `nvd_enrichment` é `null` (a CVE já está na base) e a resposta é mais rápida. Para confirmar a gravação:

```bash
grep -A8 "Vuln_CVE_2024_3400" OntoCSIRT_v7_acquired.ttl
python ontocsirt_evolve.py validate      # SHACL + HermiT + Pellet + questões de competência da base completa
```

O enriquecimento também corre sem webhook:

```bash
python nvd_enricher.py CVE-2024-3400 --kb OntoCSIRT_v7_real.ttl --out OntoCSIRT_v7_acquired.ttl
```

## 5. O que acontece quando algo falha (fallback)

Em todos os casos abaixo, o webhook responde **HTTP 200** com `"action": "manual_review"`, `"requires_human_approval": true` e `"fallback": true`, e **nada é gravado**. No Shuffle/XSOAR, ramifique em `requires_human_approval` (ou em `fallback`) para um passo de triagem manual.

| Situação | `nvd.error` | `reason` |
|---|---|---|
| Timeout (5 s de ligação / 20 s de leitura), sem rede, NVD fora do ar (5xx) ou limite de pedidos excedido (403/429) depois de 3 tentativas com espera crescente | `nvd_unavailable` | `CVE nao encontrado na base e API NVD indisponivel` |
| O passo NVD (esperas, pedidos e novas tentativas) passaria de `--nvd-max-wait` (35 s) | `nvd_unavailable` | idem |
| A CVE não existe no NVD (ou ainda não foi publicada) | `cve_not_found` | `CVE nao encontrado na base nem no NVD` |
| O registo não tem CVSS 3.x/4.0 (p.ex. `Awaiting Analysis`), não tem CWE (e o alerta não indica `cwe`), ou o ramo não passa no SHACL/HermiT | `enrichment_rejected` | `CVE nao encontrado na base e o registo do NVD nao permite criar o ramo` |

Exemplo (NVD inacessível):

```json
{
 "alert_id": "TESTE_2",
 "action": "manual_review",
 "action_iri": null,
 "playbook": "manual_triage",
 "confidence": 0.0,
 "requires_human_approval": true,
 "reason": "CVE nao encontrado na base e API NVD indisponivel",
 "fallback": true,
 "nvd": {"cve": "CVE-2024-3400", "error": "nvd_unavailable", "detail": "NVD inacessivel (sem rede ou API fora do ar): ConnectionError"}
}
```

`detail` diz a causa exata, para o analista ou para os registos do SOAR. Com a cache válida, uma queda do NVD não afeta CVEs consultadas nas últimas 24 h.

Se o NVD não atribuir CWE e o alerta trouxer `"cwe": "CWE-…"`, essa CWE é usada e marcada com `:cweSource "alerta (o NVD nao atribui CWE)"`. A CWE deduzida de `attack_type` nunca é usada para criar o ramo.

## 6. Testes

```bash
python -m pytest tests/test_nvd_enricher.py -q
```

Os testes não usam a rede: uma sessão HTTP falsa serve registos NVD reais de `tests/fixtures/nvd/`, e um relógio falso cobre a cache de 24 h, a cache negativa de 1 h e o limite de 5 pedidos/30 s. Cobrem também timeout, falta de rede, 503 seguido de sucesso, 404, registo sem CVSS, a recusa do `OntoCSIRT_v7.ttl` como destino, o fallback do webhook e alertas com CVE já conhecida, que não chamam o NVD.

*Este produto usa dados da API do NVD, mas não é endossado nem certificado pelo NVD.*
