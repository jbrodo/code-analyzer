#!/usr/bin/env bash
# I-05: costruisce l'immagine di sviluppo del server (API e SPA) dai wheel del workspace. Nessun push.
# Richiede uv, bun 1.4.4 e docker.
#
# Uso: deploy/docker/server/build-dev-image.sh [nome:tag]     (default: ca-server-dev:local)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
IMAGE="${1:-ca-server-dev:local}"

CONTEXT="$(mktemp -d)"
trap 'rm -rf "$CONTEXT"' EXIT
cp "$HERE/Dockerfile" "$CONTEXT/"
mkdir "$CONTEXT/dist"
for package in ca-core ca-api; do
  (cd "$ROOT" && uv build --quiet --package "$package" --out-dir "$CONTEXT/dist")
done
rm -f "$CONTEXT"/dist/*.tar.gz
# Dipendenze di terzi con hash, dal lock del repository.
(cd "$ROOT" && uv export --quiet --frozen --no-dev --package ca-api --no-emit-workspace \
  --format requirements-txt --output-file "$CONTEXT/requirements.txt")

# La SPA, con la configurazione di sviluppo di `web/public/config.json` (l'IdP finto sulla porta
# 9000 di loopback): serve per aprire la UI su http://127.0.0.1:8000 con lo stack del compose.
(cd "$ROOT/web" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)
cp -a "$ROOT/web/dist" "$CONTEXT/web"

docker build -q -t "$IMAGE" "$CONTEXT"
