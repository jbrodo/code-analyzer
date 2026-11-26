# Plugin eslint (P-02). ADR-0004, ADR-0005, ADR-0007, ADR-0026; licenze e SBOM: deploy/docker/LICENSES-SBOM.md.
# Contesto di build: questa directory. Costruire con deploy/docker/build-image.sh, firmare solo con
# deploy/docker/sign-local.sh. Nessun push a registry esterni (D-0005 aperta); nessuna licenza del
# prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest)
# perche' l'adattatore e' Python come quelli degli altri plugin. Node arriva dall'immagine ufficiale
# `node:24-trixie-slim`, per digest, sulla stessa release di Debian. Le dipendenze di Node sono in
# package-lock.json con l'integrita' di ogni pacchetto: `npm ci` rifiuta cio' che non coincide, e
# `--ignore-scripts` impedisce a qualunque pacchetto di eseguire codice durante la build.
# Solo linux/amd64.

FROM --platform=linux/amd64 node:24-trixie-slim@sha256:af02d57b57719b9657a45199a79264a9437940cd55b3c7b3fc99615654f124a0 AS build
WORKDIR /opt/ca-plugin
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --no-fund --no-update-notifier \
 && mkdir /deps-licenses \
 && cd node_modules \
 && find . -maxdepth 3 -type f \( -iname 'LICEN*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) \
        -exec cp --parents {} /deps-licenses/ \;

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-eslint" \
      org.opencontainers.image.description="Plugin eslint di Code Analyzer: qualita' del codice JS, TS e TSX in SARIF 2.1.0" \
      ca.engines="eslint"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_ENV=production

COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=build /opt/ca-plugin/node_modules /opt/ca-plugin/node_modules
COPY --chmod=0644 eslint.config.mjs eslint.benchmark.config.mjs eslint_adapter.py /opt/ca-plugin/

# File di licenza (I-05): THIRD-PARTY-NOTICES.md, /licenses/eslint/ e i testi delle dipendenze di
# Node (/licenses/deps/, raccolti dai pacchetti installati). Verificati da image-gate.sh.
COPY licenses/ /licenses/
COPY --from=build /deps-licenses /licenses/deps
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses /opt/ca-plugin

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/eslint_adapter.py"]
