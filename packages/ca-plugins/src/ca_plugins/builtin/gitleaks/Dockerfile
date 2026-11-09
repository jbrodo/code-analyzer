# Plugin gitleaks (P-07). ADR-0004, ADR-0005, ADR-0007, ADR-0012, ADR-0015; licenze e SBOM:
# deploy/docker/LICENSES-SBOM.md. Contesto di build: questa directory. Costruire con
# deploy/docker/build-image.sh, firmare solo con deploy/docker/sign-local.sh. Nessun push a registry
# esterni (D-0005 aperta); nessuna licenza del prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# Solo linux/amd64: e' l'unico artefatto di gitleaks di cui V-01 ha registrato l'SHA-256.

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS fetch
# gitleaks v8.30.1 (V-01): ADD --checksum fa fallire la build se l'SHA-256 non coincide.
ADD --checksum=sha256:551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb \
    https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz /gitleaks.tar.gz
# Configurazione predefinita dello stesso tag, passata con --config: il `.gitleaks.toml` del
# repository analizzato non viene mai letto. Hash calcolato sul file del tag v8.30.1.
ADD --checksum=sha256:e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf \
    https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml /gitleaks.toml
RUN mkdir /gitleaks && tar -xzf /gitleaks.tar.gz -C /gitleaks gitleaks

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-gitleaks" \
      org.opencontainers.image.description="Plugin gitleaks di Code Analyzer: segreti nella storia git, SARIF oscurato" \
      ca.engines="gitleaks"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# git: gitleaks lo invoca per leggere la storia. Pacchetto Debian non fissato per versione (il
# digest della base fissa solo l'indice): voce aperta, vedi THIRD-PARTY-NOTICES.md.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

COPY --from=fetch --chmod=0755 /gitleaks/gitleaks /usr/local/bin/gitleaks
COPY --from=fetch --chmod=0644 /gitleaks.toml /opt/ca-plugin/gitleaks.toml
COPY --chmod=0644 gitleaks_adapter.py /opt/ca-plugin/gitleaks_adapter.py

# File di licenza (I-05): THIRD-PARTY-NOTICES.md e /licenses/gitleaks/ (MIT, dal tag v8.30.1).
COPY licenses/ /licenses/
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/gitleaks_adapter.py"]
