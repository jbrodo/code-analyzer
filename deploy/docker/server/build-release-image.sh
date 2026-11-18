#!/usr/bin/env bash
# I-03: costruisce l'immagine di RILASCIO del server (API + SPA) e ne controlla licenze e SBOM.
# Nessun push, nessuna firma.
#
# Uso: deploy/docker/server/build-release-image.sh <nome:tag> <cartella-sbom>
# Richiede: uv, bun 1.4.4 (come `web/package.json`), docker; per l'SBOM, syft (SYFT=/percorso).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
IMAGE="${1:-}"; OUT="${2:-}"
die() { echo "errore: $*" >&2; exit 2; }
[ -n "$IMAGE" ] && [ -n "$OUT" ] || die "uso: $0 <nome:tag> <cartella-sbom>"

CONTEXT="$(mktemp -d)"
trap 'rm -rf "$CONTEXT"' EXIT
cp "$HERE/Dockerfile.release" "$CONTEXT/Dockerfile"
cp "$HERE/collect_licenses.py" "$CONTEXT/"
cp -a "$HERE/licenses" "$CONTEXT/licenses"
cp "$ROOT/LICENSE" "$CONTEXT/LICENSE"

mkdir "$CONTEXT/dist"
for package in ca-core ca-api; do
  (cd "$ROOT" && uv build --quiet --package "$package" --out-dir "$CONTEXT/dist")
done
rm -f "$CONTEXT"/dist/*.tar.gz
(cd "$ROOT" && uv export --quiet --frozen --no-dev --package ca-api --no-emit-workspace \
  --format requirements-txt --output-file "$CONTEXT/requirements.txt")

# La SPA: dal lock congelato, senza la configurazione di sviluppo (l'IdP finto): quella
# dell'ambiente si monta a run time.
(cd "$ROOT/web" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)
cp -a "$ROOT/web/dist" "$CONTEXT/web"
rm -f "$CONTEXT/web/config.json"
node "$HERE/collect_web_licenses.mjs" "$ROOT/web" "$CONTEXT/licenses"

docker build -q -t "$IMAGE" "$CONTEXT" >/dev/null
exec "$HERE/../image-gate.sh" "$IMAGE" "$OUT"
