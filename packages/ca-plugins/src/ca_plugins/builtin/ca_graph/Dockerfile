# Plugin ca-graph (G-09). ADR-0004, ADR-0005, ADR-0007, ADR-0020; licenze e SBOM: deploy/docker/LICENSES-SBOM.md.
# Contesto di build: preparato da deploy/docker/stage-context.sh (vedi context.sources), che aggiunge
# `ca_graph/` da packages/ca-graph. Costruire con deploy/docker/build-image.sh, firmare solo con
# deploy/docker/sign-local.sh. Nessun push a registri esterni (D-0005 aperta); nessuna licenza del
# prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# Solo linux/amd64. Le dipendenze (tree-sitter e tre grammatiche, wheel pronte) sono in
# requirements.lock con gli hash SHA-256: pip rifiuta tutto cio' che non coincide.

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY requirements.lock /requirements.lock
RUN python -m venv --without-pip /opt/venv \
 && pip --python /opt/venv/bin/python install --no-cache-dir --require-hashes --no-deps \
        --only-binary=:all: -r /requirements.lock \
 && mkdir /deps-licenses \
 && cd /opt/venv/lib/python3.12/site-packages \
 && for d in *.dist-info; do \
        find "$d" -type f \( -ipath '*/licenses/*' -o -iname 'LICEN*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) \
            -exec cp --parents {} /deps-licenses/ \; ; \
    done

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-ca-graph" \
      org.opencontainers.image.description="Plugin ca-graph di Code Analyzer: grafo dei moduli con tree-sitter" \
      ca.engines="tree-sitter"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV. `PYTHONPATH` rende importabile `ca_graph.treesitter`, copiato dal contesto.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/ca-plugin:/opt/venv/lib/python3.12/site-packages

COPY --from=build /opt/venv /opt/venv
COPY --chmod=0755 ca_graph /opt/ca-plugin/ca_graph
COPY --chmod=0644 ca_graph_adapter.py /opt/ca-plugin/ca_graph_adapter.py

# File di licenza (I-05): THIRD-PARTY-NOTICES.md, /licenses/tree-sitter/ e i testi delle dipendenze.
COPY licenses/ /licenses/
COPY --from=build /deps-licenses /licenses/deps
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses /opt/ca-plugin

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/ca_graph_adapter.py"]
