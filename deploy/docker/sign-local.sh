#!/usr/bin/env bash
# I-02: build, push al registry locale, firma e verifica con una chiave di test.
# ADR-0005 (emendamento dopo V-09), doc/verifiche/scanner-fase-1.md (V-06).
#
# Uso: deploy/docker/sign-local.sh <contesto-build> <nome-immagine> [tag]
# Stampa su stdout solo il riferimento firmato: 127.0.0.1:PORTA/nome@sha256:...
#
# Ambiente:
#   COSIGN              percorso di cosign (default: quello nel PATH)
#   CA_REGISTRY_PORT    porta del registry locale su 127.0.0.1 (default 5055)
#   CA_KEY_DIR          cartella FUORI dal repository per tenere la coppia di
#                       chiavi di test (default: cartella temporanea cancellata
#                       all'uscita). Se contiene gia' cosign.key/cosign.pub li usa.
#   CA_SIGN_ONLY_VERIFY=1  non costruisce ne' firma: verifica soltanto
#                       (richiede CA_IMAGE_REF e CA_KEY_DIR)
#
# La chiave di test NON protegge nulla: password vuota, generata al momento,
# mai nel repository. D-0005 e' aperta: nessun registry diverso da 127.0.0.1.
set -euo pipefail

# Versione e hash fissati (doc/verifiche/scanner-fase-1.md, riga cosign,
# asset cosign-linux-amd64). Altre piattaforme: serve aggiornare queste righe.
COSIGN_VERSION="v3.1.4"
COSIGN_SHA256="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"

PORT="${CA_REGISTRY_PORT:-5055}"
REGISTRY="127.0.0.1:${PORT}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

die() { echo "errore: $*" >&2; exit 2; }
log() { echo "[sign-local] $*" >&2; }

# --- cosign: versione e SHA-256 fissati, nessuna installazione ---------------
COSIGN_BIN="${COSIGN:-$(command -v cosign || true)}"
[ -n "$COSIGN_BIN" ] && [ -x "$COSIGN_BIN" ] ||
  die "cosign $COSIGN_VERSION non trovato. Questo script non installa nulla: scarica l'asset cosign-linux-amd64 della release $COSIGN_VERSION, verifica SHA-256 $COSIGN_SHA256 e indicalo con COSIGN=/percorso/cosign"
actual_sha="$(sha256sum "$COSIGN_BIN" | cut -d' ' -f1)"
[ "$actual_sha" = "$COSIGN_SHA256" ] ||
  die "SHA-256 di $COSIGN_BIN ($actual_sha) diverso da quello fissato ($COSIGN_SHA256)"
"$COSIGN_BIN" version 2>/dev/null | grep -q "GitVersion:[[:space:]]*$COSIGN_VERSION" ||
  die "cosign non riporta la versione $COSIGN_VERSION"

# --- chiavi di test -----------------------------------------------------------
if [ -n "${CA_KEY_DIR:-}" ]; then
  KEY_DIR="$CA_KEY_DIR"
  mkdir -p "$KEY_DIR"
else
  KEY_DIR="$(mktemp -d)"
  trap 'rm -rf "$KEY_DIR"' EXIT
fi
case "$(cd "$KEY_DIR" && pwd)/" in
  "$REPO_ROOT"/*) die "CA_KEY_DIR e' dentro il repository: la chiave privata non va committata" ;;
esac
export COSIGN_PASSWORD=""   # chiave di test senza password: non protegge nulla

verify() {
  "$COSIGN_BIN" verify --key "$KEY_DIR/cosign.pub" \
    --insecure-ignore-tlog=true --allow-http-registry "$1"
}

if [ "${CA_SIGN_ONLY_VERIFY:-0}" = "1" ]; then
  [ -n "${CA_IMAGE_REF:-}" ] || die "CA_IMAGE_REF mancante"
  verify "$CA_IMAGE_REF" >/dev/null
  exit 0
fi

CONTEXT="${1:-}"; NAME="${2:-}"; TAG="${3:-local}"
[ -d "$CONTEXT" ] && [ -n "$NAME" ] || die "uso: $0 <contesto-build> <nome-immagine> [tag]"

if [ ! -f "$KEY_DIR/cosign.key" ]; then
  log "genero una coppia di chiavi di test (non protegge nulla) in $KEY_DIR"
  (cd "$KEY_DIR" && "$COSIGN_BIN" generate-key-pair >/dev/null)
fi

# --- registry locale raggiungibile? ------------------------------------------
curl -fsS --max-time 3 "http://$REGISTRY/v2/" >/dev/null 2>&1 ||
  die "registry locale non raggiungibile su $REGISTRY: docker compose -f deploy/compose/registry.yaml up -d --wait"

# --- build e push ---------------------------------------------------------------
TAGGED="$REGISTRY/$NAME:$TAG"
log "build $TAGGED"
docker build -q -t "$TAGGED" "$CONTEXT" >/dev/null
log "push $TAGGED"
docker push -q "$TAGGED" >/dev/null

# --- digest letto dal registry (non da RepoDigests) ---------------------------
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'
DIGEST="$(curl -fsSI --max-time 10 -H "Accept: $ACCEPT" "http://$REGISTRY/v2/$NAME/manifests/$TAG" |
  tr -d '\r' | awk 'tolower($1)=="docker-content-digest:" {print $2}')"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "digest non leggibile dal registry"
REF="$REGISTRY/$NAME@$DIGEST"

# --- firma e verifica (comandi di ADR-0005, emendamento) -------------------------
log "firma $REF"
"$COSIGN_BIN" sign --yes --key "$KEY_DIR/cosign.key" \
  --tlog-upload=false --use-signing-config=false --allow-http-registry "$REF" >&2
log "verifica $REF"
verify "$REF" >/dev/null
echo "$REF"
