"""ontoevo - aquisicao de vulnerabilidades, de casos CBR e evolucao estrutural do OntoCSIRT com o Gemini.

Modulos:
  gemini     adaptador da API Gemini (Interactions API): saida estruturada, function calling, cache/replay
  schemas    modelos Pydantic das respostas e das propostas de alteracao da ontologia
  kb         composicao da base (v7/real + extensao + evolucao + dados adquiridos) e gravacao
  catalogs   catalogos de referencia (CWE oficial, ATT&CK) para verificar o que o modelo propoe
  enrich     aquisicao de vulnerabilidades (KEV + NVD + CTID; o Gemini preenche lacunas verificadas)
  cases      aquisicao de casos CBR (analise de vulnerabilidade, retencao de alertas resolvidos)
  signals    deteccao deterministica de sinais estruturais nos dados
  agent      agente de evolucao (function calling so de leitura + verificacao a seco)
  compiler   proposta -> triplas OWL (deterministico, gramatica restrita)
  evogate    portao da evolucao: SHACL, HermiT, Pellet, questoes de competencia
  proposals  ciclo de vida das propostas (pendente -> aprovada -> aplicada) e aplicacao no OWL
"""
