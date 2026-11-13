#!/usr/bin/env bash
# I-01: costruisce l'immagine CLI dal pacchetto di package-cli.sh e ne controlla licenze e SBOM.
# Nessun push, nessuna firma.
#
# Uso: deploy/docker/cli/build-cli-image.sh <cartella-pacchetto> <nome:tag> <cartella-sbom>
#   <cartella-pacchetto>  uscita di package-cli.sh: usa dist/*.whl (manifest con digest)
# Stampa il percorso dell'SBOM. Ambiente: come image-gate.sh (SYFT).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PACKAGE="${1:-}"; IMAGE="${2:-}"; OUT="${3:-}"
die() { echo "errore: $*" >&2; exit 2; }
[ -n "$PACKAGE" ] && [ -n "$IMAGE" ] && [ -n "$OUT" ] || die "uso: $0 <cartella-pacchetto> <nome:tag> <cartella-sbom>"
for package in ca_core ca_plugins ca_cli; do
  ls "$PACKAGE"/dist/"$package"-*.whl >/dev/null 2>&1 || die "wheel $package assente in $PACKAGE/dist"
done

CONTEXT="$(mktemp -d)"
trap 'rm -rf "$CONTEXT"' EXIT
cp -a "$HERE/Dockerfile" "$HERE/licenses" "$CONTEXT/"
cp "$ROOT/LICENSE" "$CONTEXT/LICENSE"
mkdir "$CONTEXT/dist"
cp "$PACKAGE"/dist/ca_core-*.whl "$PACKAGE"/dist/ca_plugins-*.whl "$PACKAGE"/dist/ca_cli-*.whl "$CONTEXT/dist/"
# Dipendenze di terzi con hash, dal lock del repository: mai risolte durante la build.
(cd "$ROOT" && uv export --quiet --frozen --no-dev --package ca-cli --no-emit-workspace \
  --format requirements-txt --output-file "$CONTEXT/requirements.txt")

docker build -q -t "$IMAGE" "$CONTEXT" >/dev/null
exec "$HERE/../image-gate.sh" "$IMAGE" "$OUT"
