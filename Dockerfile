# OntoCSIRT v7 - webhook SOAR (POST /alert, POST /retain, GET /health) com Pellet/HermiT (Java 17).
# Debian bookworm: tem openjdk-17 nos repositorios oficiais (o trixie ja nao).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Java para o Pellet e o HermiT incluidos no Owlready2 (o mkdir evita a falha do postinst em imagens slim)
RUN mkdir -p /usr/share/man/man1 \
 && apt-get update \
 && apt-get install -y --no-install-recommends openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/* \
 && java -version

WORKDIR /app
COPY requirements.txt .
# o Owlready2 0.46 so e distribuido em codigo-fonte (sdist) e compila um modulo C: gcc so durante o pip
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && pip install -r requirements.txt \
 && apt-get purge -y --auto-remove gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# Teste de fumo dos raciocinadores na construcao: HermiT e Pellet sobre a base do artigo. Uma combinacao
# Java/Owlready2 incompativel (p.ex. Owlready2 0.51 com Java 17) falha AQUI, e nao no primeiro alerta;
# o /health do servico nao chama o Java e por isso nao a detetaria.
RUN python -c "import ontocsirt_v7 as v7; g = v7.base_graph(); h = v7.run_hermit(g); p = v7.run_pellet(g); \
assert h[0] and not h[2] and p[0], 'raciocinadores falharam'; \
print('HermiT %.1fs, Pellet %.1fs: consistente' % (h[1], p[1]))"

# /app/data: ficheiro de dados gravado pelo enriquecimento NVD e pelo /retain (volume no docker-compose);
# semeado com a base adquirida do repositorio. OntoCSIRT_v7.ttl (artigo) fica so de leitura na imagem.
RUN useradd --create-home --uid 1000 ontocsirt \
 && mkdir -p /app/data /app/cache /app/evolution/backups \
 && if [ -f OntoCSIRT_v7_acquired.ttl ]; then cp OntoCSIRT_v7_acquired.ttl /app/data/; fi \
 && chown -R ontocsirt:ontocsirt /app/data /app/cache /app/evolution \
 && chmod a-w /app/OntoCSIRT_v7.ttl

USER ontocsirt
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8088/health', timeout=4).status == 200 else 1)"

# O token vem de ONTOCSIRT_TOKEN (obrigatorio no docker-compose); a chave do NVD de NVD_API_KEY.
ENTRYPOINT ["python", "soar_webhook.py"]
CMD ["--kb", "OntoCSIRT_v7_real.ttl", "--acquired", "/app/data/OntoCSIRT_v7_acquired.ttl", "--host", "0.0.0.0", "--port", "8088"]
