# Plugin scancode (P-06). ADR-0004, ADR-0005, ADR-0007, ADR-0015; licenze e SBOM: deploy/docker/LICENSES-SBOM.md.
# Contesto di build: questa directory. Costruire con deploy/docker/build-image.sh, firmare solo con
# deploy/docker/sign-local.sh. Nessun push a registry esterni (D-0005 aperta); nessuna licenza del
# prodotto (D-0015).
#
# Base: stesso indice di deploy/docker/plugin-base/Dockerfile (python:3.12-slim-trixie, per digest).
# Solo linux/amd64. Le dipendenze sono in requirements.lock con gli hash SHA-256 di ogni wheel
# (scancode-toolkit 32.5.0, V-01): pip rifiuta tutto cio' che non coincide. Il lock fissa anche
# `pluggy` 1.6.0: scancode 32.5.0 non si avvia con pluggy 1.7 (V-07).

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
    done \
 && mkdir /scancode-about \
 && find . -name '*.ABOUT' -type f -exec cp --parents {} /scancode-about/ \;

FROM --platform=linux/amd64 python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="code-analyzer-plugin-scancode" \
      org.opencontainers.image.description="Plugin scancode di Code Analyzer: rilevazione delle licenze dei file, SARIF 2.1.0" \
      ca.engines="scancode"

# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp (tmpfs del runner).
# Nessun segreto in ENV.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# libgomp1: richiesta da libarchive (extractcode) per caricarsi. Pacchetto Debian non fissato per
# versione (il digest della base fissa solo l'indice): voce aperta, vedi THIRD-PARTY-NOTICES.md.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv
COPY --chmod=0644 scancode_adapter.py /opt/ca-plugin/scancode_adapter.py

# File di licenza (I-05): THIRD-PARTY-NOTICES.md, /licenses/scancode/ e i testi delle dipendenze Python
# (/licenses/deps/, raccolti dai dist-info delle versioni fissate). Verificati da image-gate.sh.
COPY licenses/ /licenses/
COPY --from=build /deps-licenses /licenses/deps
# I componenti di terzi di scancode (anche copyleft) sono documentati dai file .ABOUT della wheel.
COPY --from=build /scancode-about /licenses/scancode/about
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.12/LICENSE.txt /licenses/python/LICENSE.txt \
 && chmod -R a=rX /licenses

WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python", "/opt/ca-plugin/scancode_adapter.py"]
