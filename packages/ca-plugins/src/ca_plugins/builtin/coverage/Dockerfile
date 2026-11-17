# Plugin coverage (P-05). ADR-0004, ADR-0005, ADR-0007, ADR-0026; licenze e SBOM: deploy/docker/LICENSES-SBOM.md.
# Contesto di build: questa directory. Costruire con deploy/docker/build-image.sh, firmare solo con
# deploy/docker/sign-local.sh. Nessun push a registri esterni (D-0005 aperta); nessuna licenza del
# prodotto (D-0015).
#
# Nessun motore di terzi e nessuna dipendenza Python: l'adattatore usa solo la libreria standard.
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# Solo linux/amd64.

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-coverage" \
      org.opencontainers.image.description="Plugin coverage di Code Analyzer: copertura di riga da report LCOV e Cobertura in SARIF 2.1.0" \
      ca.engines=""

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --chmod=0644 coverage_adapter.py /opt/ca-plugin/coverage_adapter.py

# File di licenza (I-05): THIRD-PARTY-NOTICES.md e il testo dell'interprete. Nessun motore.
COPY licenses/ /licenses/
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/coverage_adapter.py"]
