# Immagine base dei plugin (I-01). ADR-0004, ADR-0007.
# Contiene solo l'interprete Python per gli adattatori: gli scanner e gli
# adattatori li aggiunge l'immagine di ciascun plugin, derivata da questa.
#
# Base: python:3.12-slim-trixie (Debian 13, Python 3.12), indice multi-architettura.
# Il digest e' quello letto da registry-1.docker.io (Docker-Content-Digest) il
# 2026-11-08; per aggiornarlo: deploy/docker/plugin-base/README.md.
# Python 3.12: serve a scancode-toolkit 32.5.0 (wheel cp312, V-01).
FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-base" \
      org.opencontainers.image.description="Base dei plugin di Code Analyzer: Python standard, utente non root"

# Root file system in sola lettura a run time (ADR-0004): niente .pyc, e HOME in
# /tmp (tmpfs rw,noexec,nosuid montato dal runner). Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# File di licenza (I-05, ADR-0015): COPY fallisce se la cartella manca; il testo
# della licenza di CPython viene dalla distribuzione stessa. Verificato dopo la
# build da deploy/docker/image-gate.sh. Nessuna licenza del prodotto (D-0015).
COPY licenses/ /licenses/
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

# Gli adattatori leggono /workspace e scrivono /out; li crea il runner (mount).
WORKDIR /workspace

# Stesso UID:GID che impone il profilo hardened-container (V-07, ADR-0004).
USER 65534:65534
