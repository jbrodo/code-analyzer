# Plugin syft (P-01). ADR-0004, ADR-0005, ADR-0007, ADR-0015; licenze e SBOM: deploy/docker/LICENSES-SBOM.md.
# Contesto di build: questa directory. Costruire con deploy/docker/build-image.sh, firmare solo con
# deploy/docker/sign-local.sh. Nessun push a registry esterni (D-0005 aperta); nessuna licenza del
# prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# L'immagine I-01 non e' pubblicata e non ha un digest di registry: si riparte dalla sua base e se ne
# ripetono i passi (HOME, /licenses, utente).
# Solo linux/amd64: e' l'unico artefatto di syft di cui V-01 ha registrato l'SHA-256.

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS fetch
# syft v1.57.0 (V-01): ADD --checksum fa fallire la build se l'SHA-256 non coincide. Niente `latest`.
ADD --checksum=sha256:9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704 \
    https://github.com/anchore/syft/releases/download/v1.57.0/syft_1.57.0_linux_amd64.tar.gz /syft.tar.gz
RUN mkdir /syft && tar -xzf /syft.tar.gz -C /syft syft

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-syft" \
      org.opencontainers.image.description="Plugin syft di Code Analyzer: SBOM CycloneDX 1.7 del workspace" \
      ca.engines="syft"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner),
# nessun controllo degli aggiornamenti di syft (nessuna rete). Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SYFT_CHECK_FOR_APP_UPDATE=false

COPY --from=fetch --chmod=0755 /syft/syft /usr/local/bin/syft
COPY --chmod=0644 syft_adapter.py /opt/ca-plugin/syft_adapter.py

# File di licenza (I-05): THIRD-PARTY-NOTICES.md e /licenses/syft/; il testo di CPython viene dalla
# distribuzione stessa. Verificati dopo la build da deploy/docker/image-gate.sh.
COPY licenses/ /licenses/
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/syft_adapter.py"]
