#!/usr/bin/env bash
# I-05: costruisce l'immagine di sviluppo del server dai wheel del workspace. Nessun push.
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

docker build -q -t "$IMAGE" "$CONTEXT"
