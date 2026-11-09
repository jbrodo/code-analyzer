#!/usr/bin/env bash
# Prova di I-05: image-gate.sh passa su plugin-base e fallisce nei casi attesi.
# Costruisce solo in locale (nessun push, nessuna firma, nessuna rete oltre al
# pull della base per digest) e a fine prova rimuove container, immagini e file.
# Uso: SYFT=/percorso/syft deploy/docker/test-image-gate.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; fail=0
SYFT_BIN="${SYFT:-$(command -v syft || true)}"
cleanup() {
  docker images --format '{{.Repository}}:{{.Tag}}' | grep '^ca-gate-test-' | xargs -r docker rmi -f >/dev/null 2>&1
  chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"
}
trap cleanup EXIT
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 (exit $3)"; else echo "FAIL  $1: atteso $2, ottenuto $3"; fail=1; fi; }
gate() { SYFT="${GATE_SYFT:-$SYFT_BIN}" "$HERE/image-gate.sh" "$1" "$TMP/sbom" >/dev/null 2>"$TMP/err"; }

docker build -q -t ca-gate-test-base:t "$HERE/plugin-base" >/dev/null || { echo "build base fallita"; exit 2; }
gate ca-gate-test-base:t; check "plugin-base: licenze e SBOM" 0 $?
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["specVersion"]=="1.7"' "$TMP"/sbom/*.cdx.json
check "SBOM CycloneDX 1.7 su disco" 0 $?

derive() { # nome righe-Dockerfile...
  local n="ca-gate-test-$1:t"; shift
  local body; body="$(printf '%s\n' "$@")"
  printf 'FROM ca-gate-test-base:t\nUSER root\n%s\nUSER 65534:65534\n' "$body" | docker build -q -t "$n" - >/dev/null || echo "build $n fallita"
  echo "$n"
}
img="$(derive nolic 'RUN rm -rf /licenses')";                                        gate "$img"; check "senza /licenses" 3 $?
img="$(derive emptynotice 'RUN : > /licenses/THIRD-PARTY-NOTICES.md')";             gate "$img"; check "notices vuoto" 3 $?
img="$(derive prodlic 'LABEL org.opencontainers.image.licenses="MIT"')";            gate "$img"; check "licenza del prodotto dichiarata" 3 $?
img="$(derive noengine 'LABEL ca.engines="syft"')";                                 gate "$img"; check "motore senza cartella" 3 $?
img="$(derive badname 'LABEL ca.engines="../x"')";                                  gate "$img"; check "nome motore non valido" 3 $?
img="$(derive noabout 'LABEL ca.engines="scancode"' 'RUN mkdir /licenses/scancode && echo n > /licenses/scancode/NOTICE')"
gate "$img"; check "scancode senza .ABOUT" 3 $?
img="$(derive okscan 'LABEL ca.engines="scancode,syft"' \
  'RUN mkdir -p /licenses/scancode/about /licenses/syft && echo n > /licenses/scancode/NOTICE && echo a > /licenses/scancode/about/x.ABOUT && echo l > /licenses/syft/LICENSE')"
gate "$img"; check "scancode e syft completi" 0 $?

# SBOM: syft finti, uno senza file prodotto, uno con specVersion sbagliata
printf '#!/bin/sh\n[ "$1" = version ] && { echo "Version:   1.57.0"; exit 0; }\nexit 0\n' >"$TMP/syft-nofile"
printf '#!/bin/sh\n[ "$1" = version ] && { echo "Version:   1.57.0"; exit 0; }\nf="${*##*=}"\necho '"'"'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{}]}'"'"' >"$f"\n' >"$TMP/syft-oldspec"
chmod +x "$TMP/syft-nofile" "$TMP/syft-oldspec"
GATE_SYFT="$TMP/syft-nofile" gate ca-gate-test-base:t;  check "SBOM non prodotto" 4 $?
GATE_SYFT="$TMP/syft-oldspec" gate ca-gate-test-base:t; check "SBOM con specVersion 1.6" 4 $?
GATE_SYFT=/nonexistent/syft gate ca-gate-test-base:t;   check "syft assente" 2 $?
gate ca-gate-test-inesistente:t;                         check "immagine inesistente" 2 $?

docker ps -a --filter ancestor=ca-gate-test-base:t -q | grep -q . && { echo "FAIL  container residui"; fail=1; }
exit "$fail"
