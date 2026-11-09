# Plugin trivy (P-04, P-05). ADR-0004, ADR-0005, ADR-0006, ADR-0007, ADR-0015; licenze e SBOM:
# deploy/docker/LICENSES-SBOM.md. Contesto di build: questa directory. Costruire con
# deploy/docker/build-image.sh, firmare solo con deploy/docker/sign-local.sh. Nessun push a registry
# esterni (D-0005 aperta); nessuna licenza del prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# Solo linux/amd64: e' l'unico artefatto di trivy di cui V-01 ha registrato l'SHA-256.
# Il database non e' nell'immagine: lo scarica `sync` (feeds.sync_command) in /feeds (ADR-0006).

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS fetch
# trivy v0.76.2 (V-01): ADD --checksum fa fallire la build se l'SHA-256 non coincide.
ADD --checksum=sha256:bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf \
    https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz /trivy.tar.gz
RUN mkdir /trivy && tar -xzf /trivy.tar.gz -C /trivy trivy

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-trivy" \
      org.opencontainers.image.description="Plugin trivy di Code Analyzer: vulnerabilita' delle dipendenze e configurazioni IaC del workspace, SARIF" \
      ca.engines="trivy"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=fetch --chmod=0755 /trivy/trivy /usr/local/bin/trivy
COPY --chmod=0644 trivy_adapter.py /opt/ca-plugin/trivy_adapter.py

# File di licenza (I-05): verificati dopo la build da deploy/docker/image-gate.sh.
COPY licenses/ /licenses/
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/trivy_adapter.py"]
