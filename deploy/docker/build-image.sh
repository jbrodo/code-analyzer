#!/usr/bin/env bash
# I-05: build locale (nessun push, nessuna firma) seguita dal controllo di
# image-gate.sh. La build fallisce se mancano file di licenza o SBOM.
# Uso: deploy/docker/build-image.sh <contesto> <nome:tag> <cartella-sbom>
# Stampa il percorso dell'SBOM. Ambiente: come image-gate.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTEXT="${1:-}"; IMAGE="${2:-}"; OUT="${3:-}"
[ -d "$CONTEXT" ] && [ -n "$IMAGE" ] && [ -n "$OUT" ] || { echo "uso: $0 <contesto> <nome:tag> <cartella-sbom>" >&2; exit 2; }
STAGED="$("$HERE/stage-context.sh" "$CONTEXT")"
[ "$STAGED" = "$CONTEXT" ] || trap 'rm -rf "$STAGED"' EXIT
docker build -q -t "$IMAGE" "$STAGED" >/dev/null
"$HERE/image-gate.sh" "$IMAGE" "$OUT"
