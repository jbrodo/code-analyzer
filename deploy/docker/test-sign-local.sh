#!/usr/bin/env bash
# Prova di I-02: quattro casi di V-06 contro un registry locale temporaneo.
# Costruisce l'immagine base (I-01), la firma con una chiave generata qui, poi
# verifica: firma valida (0), chiave errata (1), immagine non firmata (10),
# registry non raggiungibile (1). A fine prova rimuove container, immagini di
# prova e chiavi. Nessun push fuori da 127.0.0.1.
# Uso: [COSIGN=/percorso/cosign] deploy/docker/test-sign-local.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$HERE/../compose/registry.yaml"
export CA_REGISTRY_PORT="${CA_REGISTRY_PORT:-5055}"
REGISTRY="127.0.0.1:$CA_REGISTRY_PORT"
KEYS="$(mktemp -d)"; export CA_KEY_DIR="$KEYS/good"
fail=0

cleanup() {
  docker compose -f "$COMPOSE" down --volumes --remove-orphans >/dev/null 2>&1
  docker rmi -f "$REGISTRY/ca-plugin-base:local" "$REGISTRY/ca-plugin-unsigned:local" >/dev/null 2>&1
  rm -rf "$KEYS"
}
trap cleanup EXIT

COSIGN_BIN="${COSIGN:-$(command -v cosign || true)}"
check() { # nome atteso effettivo
  if [ "$2" = "$3" ]; then echo "PASS  $1 (exit $3)"; else echo "FAIL  $1: atteso $2, ottenuto $3"; fail=1; fi
}

docker compose -f "$COMPOSE" up -d --wait >/dev/null || { echo "registry non avviato"; exit 2; }

REF="$("$HERE/sign-local.sh" "$HERE/plugin-base" ca-plugin-base)"
check "firma valida (build+push+sign+verify)" 0 $?
[ -n "$REF" ] || { echo "nessun riferimento"; exit 2; }
echo "      ref: $REF"

CA_SIGN_ONLY_VERIFY=1 CA_IMAGE_REF="$REF" "$HERE/sign-local.sh" >/dev/null 2>&1
check "verifica con la chiave giusta" 0 $?

# chiave errata: seconda coppia mai usata per firmare
mkdir -p "$KEYS/bad"
(cd "$KEYS/bad" && COSIGN_PASSWORD="" "$COSIGN_BIN" generate-key-pair >/dev/null 2>&1)
CA_KEY_DIR="$KEYS/bad" CA_SIGN_ONLY_VERIFY=1 CA_IMAGE_REF="$REF" "$HERE/sign-local.sh" >/dev/null 2>&1
check "chiave errata" 1 $?

# immagine non firmata: stessa immagine con altro nome, pushata e mai firmata
docker tag "$REGISTRY/ca-plugin-base:local" "$REGISTRY/ca-plugin-unsigned:local"
docker push -q "$REGISTRY/ca-plugin-unsigned:local" >/dev/null
UDIGEST="$(curl -fsSI -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  "http://$REGISTRY/v2/ca-plugin-unsigned/manifests/local" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:" {print $2}')"
CA_SIGN_ONLY_VERIFY=1 CA_IMAGE_REF="$REGISTRY/ca-plugin-unsigned@$UDIGEST" "$HERE/sign-local.sh" >/dev/null 2>&1
check "immagine non firmata" 10 $?

# registry non raggiungibile: lo fermo davvero
docker compose -f "$COMPOSE" stop >/dev/null 2>&1
CA_SIGN_ONLY_VERIFY=1 CA_IMAGE_REF="$REF" "$HERE/sign-local.sh" >/dev/null 2>&1
check "registry non raggiungibile" 1 $?

# cosign mancante: nessuna installazione, errore chiaro (exit 2)
COSIGN=/nonexistent/cosign PATH=/usr/bin:/bin "$HERE/sign-local.sh" "$HERE/plugin-base" x >/dev/null 2>"$KEYS/err"
check "cosign assente" 2 $?
grep -q 'non installa nulla' "$KEYS/err" && echo "      messaggio chiaro: ok" || { echo "FAIL  messaggio cosign assente"; fail=1; }

exit "$fail"
