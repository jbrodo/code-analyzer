#!/usr/bin/env bash
# I-04: prova di impacchettamento con chiave di test. ADR-0005, D-0005 (fino al primo rilascio).
# Controlla licenze e SBOM di ogni plugin (build-image.sh), firma e pubblica sul registry locale
# (sign-local.sh), scrive il digest nei manifest di una COPIA del codice e ne costruisce i wheel.
# Il repository non viene modificato.
#
# Uso: deploy/docker/package-cli.sh <cartella-di-uscita>
#
# Ambiente: COSIGN, SYFT, CA_KEY_DIR (obbligatoria, fuori dal repository), CA_REGISTRY_PORT.
# Il registry deve essere attivo: docker compose -f deploy/compose/registry.yaml up -d --wait
#
# In uscita: dist/ (wheel), venv/ (installazione pulita, bin/code-analyzer), cosign.pub, images.txt.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILTIN="packages/ca-plugins/src/ca_plugins/builtin"
PORT="${CA_REGISTRY_PORT:-5055}"

die() { echo "errore: $*" >&2; exit 2; }
log() { echo "[package-cli] $*" >&2; }

OUT="${1:-}"
[ -n "$OUT" ] || die "uso: $0 <cartella-di-uscita>"
[ -n "${CA_KEY_DIR:-}" ] || die "CA_KEY_DIR mancante: la chiave pubblica va distribuita con il pacchetto"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
[ -z "$(ls -A "$OUT")" ] || die "la cartella di uscita non e' vuota: $OUT"
case "$OUT/" in "$ROOT"/*) die "la cartella di uscita e' dentro il repository" ;; esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -a "$ROOT/packages" "$ROOT/pyproject.toml" "$ROOT/uv.lock" "$WORK/"
find "$WORK/packages" -name __pycache__ -type d -prune -exec rm -rf {} +

for manifest in "$WORK/$BUILTIN"/*/plugin.yaml; do
  folder="$(basename "$(dirname "$manifest")")"
  context="$ROOT/$BUILTIN/$folder"
  name="$(awk '$1 == "name:" { print $2; exit }' "$manifest")"
  version="$(awk '$1 == "version:" { print $2; exit }' "$manifest")"
  log "$name: licenze e SBOM"
  gate="localhost/ca-package-gate-$name:$version"
  "$HERE/build-image.sh" "$context" "$gate" "$OUT/sbom/$name" >/dev/null
  docker rmi -f "$gate" >/dev/null
  log "$name: firma"
  ref="$("$HERE/sign-local.sh" "$context" "ca-plugins/$name" "$version" | tail -n 1)"
  image="127.0.0.1:$PORT/ca-plugins/$name:$version@${ref##*@}"
  sed -i -E "s|^image: .*|image: $image|" "$manifest"
  echo "$name $image" >> "$OUT/images.txt"
done

log "wheel"
for package in ca-core ca-plugins ca-graph ca-cli; do
  (cd "$WORK" && uv build --quiet --wheel --package "$package" --out-dir "$OUT/dist")
done

log "installazione pulita"
(cd "$WORK" && UV_PROJECT_ENVIRONMENT="$OUT/venv" uv sync --quiet --frozen --no-dev --no-editable --package ca-cli)
cp "$CA_KEY_DIR/cosign.pub" "$OUT/cosign.pub"

# I manifest installati devono superare la forma impacchettata (digest obbligatorio): -I, fuori dal repo.
count="$(cd "$OUT" && "$OUT/venv/bin/python" -I -c \
  'from ca_cli.composition import packaged_manifests as m; print(len(m()))')"
[ "$count" = "$(wc -l < "$OUT/images.txt")" ] || die "manifest impacchettati: $count"
log "pronto: $OUT/venv/bin/code-analyzer ($count plugin)"
