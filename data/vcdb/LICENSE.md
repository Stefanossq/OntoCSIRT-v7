# Licença dos dados desta pasta

Os ficheiros em `data/vcdb/` são **derivados do VERIS Community Database (VCDB)**:
- origem: `https://github.com/vz-risk/VCDB`, commit `f6f98c00f66ab35f5b49977a5852ce94a5bb31d1`, ficheiro `data/joined/vcdb.json.zip`;
- licença: [Creative Commons Atribuição-CompartilhaIgual 4.0 Internacional (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

Pela cláusula de compartilhamento pela mesma licença, estes derivados são distribuídos também em **CC BY-SA 4.0**. É uma licença diferente da CC BY 4.0 da ontologia (ver `LICENSE-ONTOLOGIA.md` na raiz).

**O que foi alterado:** os registos foram reorganizados num esquema canônico, sem mudar os valores, e receberam rótulos derivados das tags de referência do NVD. As regras estão em `vcdb_pipeline/rules.py` e o contrato em `docs/vcdb/RODADA1_CONTRATO.md`.

Os rótulos usam dados da API do NVD. *This product uses data from the NVD API but is not endorsed or certified by the NVD.*
