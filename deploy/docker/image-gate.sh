#!/usr/bin/env bash
# I-05: ogni immagine deve avere file di licenza e un SBOM associato.
# ADR-0015, doc/PROJECT.md §7.3 e §15, doc/verifiche/scanner-fase-1.md (V-02, V-03).
#
# Uso: deploy/docker/image-gate.sh <immagine> <cartella-sbom>
#   <immagine>      riferimento di un'immagine gia' presente in locale (tag o ID)
#   <cartella-sbom> dove scrivere l'SBOM CycloneDX 1.7 (creata se manca)
# Stampa su stdout solo il percorso dell'SBOM.
#
# Codici di uscita: 0 ok; 2 uso o strumento mancante; 3 licenze mancanti o non
# valide; 4 SBOM non prodotto o non valido. Non costruisce, non fa push, non firma.
#
# Ambiente:
#   SYFT              percorso di syft (default: quello nel PATH), versione fissata
#   CA_SYFT_SHA256    se impostato, SHA-256 atteso del binario syft
#
# Licenze richieste (convenzione in deploy/docker/LICENSES-SBOM.md):
#   /licenses/THIRD-PARTY-NOTICES.md          non vuoto
#   /licenses/<motore>/ per ogni motore nell'etichetta ca.engines (virgole), con
#     almeno un file LICENSE*, COPYING* o NOTICE* non vuoto; per scancode anche
#     NOTICE e almeno un file *.ABOUT (componenti di terzi, V-02)
# La licenza del prodotto non e' dichiarata (D-0015): l'etichetta
# org.opencontainers.image.licenses e' vietata.
set -euo pipefail

SYFT_VERSION="1.57.0"
IMAGE="${1:-}"; OUT_DIR="${2:-}"

die() { local c="$1"; shift; echo "errore: $*" >&2; exit "$c"; }
log() { echo "[image-gate] $*" >&2; }

[ -n "$IMAGE" ] && [ -n "$OUT_DIR" ] || die 2 "uso: $0 <immagine> <cartella-sbom>"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die 2 "immagine non presente in locale: $IMAGE"

SYFT_BIN="${SYFT:-$(command -v syft || true)}"
[ -n "$SYFT_BIN" ] && [ -x "$SYFT_BIN" ] ||
  die 2 "syft $SYFT_VERSION non trovato (questo script non installa nulla): indicalo con SYFT=/percorso/syft"
if [ -n "${CA_SYFT_SHA256:-}" ]; then
  [ "$(sha256sum "$SYFT_BIN" | cut -d' ' -f1)" = "$CA_SYFT_SHA256" ] || die 2 "SHA-256 di syft diverso da CA_SYFT_SHA256"
fi
"$SYFT_BIN" version 2>/dev/null | grep -Eq "^Version:[[:space:]]+$SYFT_VERSION\$" ||
  die 2 "syft non riporta la versione $SYFT_VERSION"

WORK="$(mktemp -d)"; CID=""
trap '[ -z "$CID" ] || docker rm -f "$CID" >/dev/null 2>&1; chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

# --- licenze -----------------------------------------------------------------
label() { docker image inspect -f "{{index .Config.Labels \"$1\"}}" "$IMAGE"; }

[ -z "$(label org.opencontainers.image.licenses)" ] ||
  die 3 "etichetta org.opencontainers.image.licenses presente: la licenza del prodotto non e' dichiarata (D-0015)"

# Lettura senza eseguire l'immagine: container creato e mai avviato.
CID="$(docker create --network none "$IMAGE" /nonexistent 2>/dev/null)" || die 2 "docker create fallito"
mkdir "$WORK/fs"
docker cp "$CID:/licenses" - 2>/dev/null | tar -x --no-same-owner --no-same-permissions -C "$WORK/fs" 2>/dev/null ||
  die 3 "/licenses assente nell'immagine"
LIC="$WORK/fs/licenses"
[ -d "$LIC" ] && [ ! -L "$LIC" ] || die 3 "/licenses non e' una cartella"

nonempty() { find "$1" -maxdepth "${3:-1}" -type f -name "$2" -size +0 2>/dev/null | grep -q .; }

nonempty "$LIC" THIRD-PARTY-NOTICES.md || die 3 "/licenses/THIRD-PARTY-NOTICES.md assente o vuoto"

ENGINES="$(label ca.engines)"
IFS=',' read -r -a ENGINE_LIST <<<"$ENGINES"
for e in "${ENGINE_LIST[@]}"; do
  [ -n "$e" ] || continue
  [[ "$e" =~ ^[a-z0-9-]+$ ]] || die 3 "nome motore non valido in ca.engines: '$e'"
  d="$LIC/$e"
  [ -d "$d" ] && [ ! -L "$d" ] || die 3 "/licenses/$e/ assente per il motore dichiarato"
  { nonempty "$d" 'LICENSE*' || nonempty "$d" 'COPYING*' || nonempty "$d" 'NOTICE*'; } ||
    die 3 "/licenses/$e/ senza file LICENSE*, COPYING* o NOTICE* non vuoto"
  if [ "$e" = scancode ]; then
    nonempty "$d" 'NOTICE*' || die 3 "scancode: manca /licenses/scancode/NOTICE"
    nonempty "$d" '*.ABOUT' 6 || die 3 "scancode: nessun file .ABOUT dei componenti di terzi in /licenses/scancode/"
  fi
done
log "licenze ok (motori: ${ENGINES:-nessuno})"

# --- SBOM ----------------------------------------------------------------------
mkdir -p "$OUT_DIR"
ID="$(docker image inspect -f '{{.Id}}' "$IMAGE")"; ID="${ID#sha256:}"
SAFE="$(printf '%s' "$IMAGE" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-80)"
SBOM="$OUT_DIR/$SAFE-${ID:0:12}.cdx.json"
rm -f "$SBOM"
SYFT_CHECK_FOR_APP_UPDATE=false "$SYFT_BIN" scan "docker:$IMAGE" -q \
  -o "cyclonedx-json@1.7=$SBOM" >&2 || die 4 "syft ha fallito"
[ -s "$SBOM" ] || die 4 "SBOM non prodotto"

python3 -I - "$SBOM" <<'PY' || die 4 "SBOM non valido"
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("bomFormat") == "CycloneDX", "bomFormat"
assert d.get("specVersion") == "1.7", "specVersion %r" % d.get("specVersion")
assert len(d.get("components", [])) > 0, "nessun componente"
PY
log "sbom ok: $SBOM"
echo "$SBOM"
