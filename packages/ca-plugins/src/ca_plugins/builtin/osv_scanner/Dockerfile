# Plugin osv-scanner (P-02, P-03). ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0015; licenze e SBOM:
# deploy/docker/LICENSES-SBOM.md. Contesto di build: questa directory. Costruire con
# deploy/docker/build-image.sh, firmare solo con deploy/docker/sign-local.sh. Nessun push a registry
# esterni (D-0005 aperta); nessuna licenza del prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# Solo linux/amd64: e' l'unico artefatto di osv-scanner di cui V-01 ha registrato l'SHA-256.
# Il database non e' nell'immagine: lo scarica `sync` (feeds.sync_command) in /feeds (ADR-0006).

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS fetch
# osv-scanner v2.7.0 (V-01): ADD --checksum fa fallire la build se l'SHA-256 non coincide.
ADD --checksum=sha256:160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b \
    https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 /osv-scanner

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-osv-scanner" \
      org.opencontainers.image.description="Plugin osv-scanner di Code Analyzer: vulnerabilita' delle dipendenze, SARIF" \
      ca.engines="osv-scanner"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=fetch --chmod=0755 /osv-scanner /usr/local/bin/osv-scanner
COPY --chmod=0644 osv_scanner_adapter.py /opt/ca-plugin/osv_scanner_adapter.py

# File di licenza (I-05): verificati dopo la build da deploy/docker/image-gate.sh.
COPY licenses/ /licenses/
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/osv_scanner_adapter.py"]
