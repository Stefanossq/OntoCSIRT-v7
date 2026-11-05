# Licença da ontologia e dos dados

- **Código** (`*.py`, `ontoevo/`, `tests/`, `migrations/`, `Dockerfile`, `openapi.yaml`): licença MIT, em [`LICENSE`](LICENSE).
- **Ontologia, formas SHACL e dados RDF** (`*.ttl`, `ontology/*.ttl`) e **documentação**: [Creative Commons Atribuição 4.0 Internacional (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/), como declara o cabeçalho `dcterms:license` de cada ontologia.

## Dados de terceiros em `cache/` e nos ficheiros de dados

| Fonte | Ficheiros | Termos |
|---|---|---|
| CISA Known Exploited Vulnerabilities | `cache/kev.json` | Domínio público (governo dos EUA) |
| NIST NVD | `cache/nvd/`, `cache/nvd_cwe/`, `tests/fixtures/nvd/` | Este produto usa dados da API do NVD, mas não é endossado nem certificado pelo NVD |
| MITRE ATT&CK | `cache/catalogs/attack-16.1.json` | © The MITRE Corporation; reproduzido com atribuição, segundo os termos de uso do ATT&CK |
| MITRE CWE | `cache/catalogs/cwe.json` | © The MITRE Corporation; termos de uso do CWE |
| Center for Threat-Informed Defense (KEV → ATT&CK) | `cache/ctid_kev_attack.json` | Apache-2.0 |
| Bugcrowd Vulnerability Rating Taxonomy | `cache/catalogs/bugcrowd_vrt.json` | Apache-2.0 |
| VERIS Community Database (VCDB) | `cache/vcdb/`, `data/vcdb/` (derivados) | CC BY-SA 4.0; os derivados mantêm a mesma licença ([`data/vcdb/LICENSE.md`](data/vcdb/LICENSE.md)) |
