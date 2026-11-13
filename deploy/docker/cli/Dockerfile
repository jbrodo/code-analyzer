# Immagine CLI (I-01). ADR-0004 (emendamento per I-03, M-11), ADR-0005; licenze e SBOM:
# deploy/docker/LICENSES-SBOM.md. Costruire solo con deploy/docker/cli/build-cli-image.sh, che
# prepara il contesto: i wheel di package-cli.sh (manifest con digest), requirements.txt con hash
# e il file LICENSE del progetto. Nessun push a registry esterni (D2-16).
#
# Contiene la CLI, cosign e il client del runtime. Nessun plugin: sono container fratelli, avviati
# dal daemon dell'host attraverso il socket montato. Uso e privilegio del socket: README.md.
#
# Solo linux/amd64: e' l'unico binario di cosign di cui e' registrato l'SHA-256.

# Client Docker 28.5.2, dall'immagine ufficiale fissata per digest (indice letto il 2026-11-13).
FROM --platform=linux/amd64 docker:28.5.2-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker

FROM --platform=linux/amd64 python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS fetch
# cosign v3.1.4: stesso SHA-256 di .github/actions/e2e-tools. ADD --checksum fa fallire la build.
ADD --checksum=sha256:424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa \
    https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 /cosign

# Base: python:3.14-slim-trixie (la CLI richiede Python 3.14), indice letto il 2026-11-13.
FROM --platform=linux/amd64 python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

LABEL org.opencontainers.image.title="code-analyzer-cli" \
      org.opencontainers.image.description="CLI di Code Analyzer: orchestra i plugin come container fratelli" \
      ca.engines="cosign,docker"

# CA_CLI_IMAGE: la CLI pretende CA_HOST_WORKSPACE, CA_HOST_WORK e CA_HOST_CACHE (M-11).
# Root file system in sola lettura a run time: niente .pyc, HOME in /tmp. Nessun segreto in ENV.
ENV CA_CLI_IMAGE=1 \
    COSIGN=/usr/local/bin/cosign \
    HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dipendenze con hash da uv.lock, poi i tre wheel del progetto senza risolvere altro.
COPY requirements.txt /build/requirements.txt
COPY dist/ /build/dist/
RUN pip install --require-hashes --only-binary :all: -r /build/requirements.txt \
 && pip install --no-deps --no-index /build/dist/*.whl \
 && rm -rf /build

COPY --from=fetch --chmod=0755 /cosign /usr/local/bin/cosign
COPY --from=docker --chmod=0755 /usr/local/bin/docker /usr/local/bin/docker

# File di licenza (I-05): cosign e docker dal repository, il progetto dal suo LICENSE, le
# dipendenze Python dai file di licenza delle wheel installate.
COPY licenses/ /licenses/
COPY LICENSE /licenses/code-analyzer/LICENSE
RUN mkdir -p /licenses/python \
 && cp /usr/local/lib/python3.14/LICENSE.txt /licenses/python/LICENSE.txt \
 && python - <<'PY'
import pathlib, shutil
site = pathlib.Path("/usr/local/lib/python3.14/site-packages")
for info in sorted(site.glob("*.dist-info")):
    name = info.name.split("-")[0]
    if name in {"pip", "ca_core", "ca_plugins", "ca_cli"}:
        continue
    found = [p for p in info.rglob("*") if p.is_file()
             and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))]
    for path in found:
        target = pathlib.Path("/licenses/deps", name)
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, target / path.name)
PY
RUN chmod -R a=rX /licenses \
 && mkdir -p /ca/workspace /ca/work /ca/cache /ca/output /ca/keys

WORKDIR /ca/workspace
# L'uid dei plugin e' rifiutato dalla CLI: chi lancia deve passare --user "$(id -u):$(id -g)".
USER 65534:65534
ENTRYPOINT ["code-analyzer"]
