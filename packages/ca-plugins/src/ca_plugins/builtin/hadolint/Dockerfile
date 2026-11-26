# Plugin hadolint (P-04). ADR-0004, ADR-0005, ADR-0007, ADR-0026; licenze e SBOM: deploy/docker/LICENSES-SBOM.md.
# Contesto di build: questa directory. Costruire con deploy/docker/build-image.sh, firmare solo con
# deploy/docker/sign-local.sh. Nessun push a registri esterni (D-0005 aperta); nessuna licenza del
# prodotto (D-0015).
#
# hadolint 2.15.1 e' un binario statico dai rilasci del progetto (V-01), scaricato con
# `ADD --checksum`: la build fallisce se l'SHA-256 non coincide. Il testo della licenza del motore
# si scarica allo stesso modo dal tag del sorgente, e non e' copiato nel repository.
# Solo uso interno (D2-14, 2026-11-17): distribuire questa immagine richiede, oltre al testo della
# licenza, l'offerta della sorgente (tag v2.15.1, commit 2eece55955ced00200be9729e9728cb7dacca505,
# https://github.com/hadolint/hadolint). Base: python:3.12-slim-trixie per digest. Solo linux/amd64.

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS fetch
ADD --checksum=sha256:c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507 \
    https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64 /hadolint
ADD --checksum=sha256:589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2 \
    https://raw.githubusercontent.com/hadolint/hadolint/v2.15.1/LICENSE /LICENSE
RUN chmod 0755 /hadolint

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-hadolint" \
      org.opencontainers.image.description="Plugin hadolint di Code Analyzer: Dockerfile in SARIF 2.1.0" \
      ca.engines="hadolint"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=fetch /hadolint /usr/local/bin/hadolint
COPY --chmod=0644 hadolint_adapter.py /opt/ca-plugin/hadolint_adapter.py

# File di licenza (I-05): THIRD-PARTY-NOTICES.md, /licenses/hadolint/LICENSE dal tag del sorgente
# e il testo dell'interprete. Verificati da image-gate.sh.
COPY licenses/ /licenses/
COPY --from=fetch /LICENSE /licenses/hadolint/LICENSE
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/hadolint_adapter.py"]
