#!/usr/bin/env bash
# Lancia l'immagine CLI per un comando dell'Action (ADR-0004, ADR-0027). Uso: run-cli.sh scan|gate|notify [argomenti]
#
# Il token di GitHub arriva solo a `notify`, per nome (`-e GITHUB_TOKEN`: il valore non compare
# negli argomenti). `scan` e `gate` non lo ricevono. Solo `scan` monta il socket del daemon.
set -euo pipefail

mode="${1:?comando mancante}"
shift

need() { [ -n "${!1:-}" ] || { echo "errore: variabile $1 mancante" >&2; exit 2; }; }
for v in CA_IMAGE CA_WORKSPACE CA_WORK CA_CACHE CA_OUTPUT; do need "$v"; done

args=(run --rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges
  --read-only --tmpfs /tmp
  -v "$CA_WORKSPACE":/ca/workspace:ro -v "$CA_OUTPUT":/ca/output)

case "$mode" in
  scan)
    need CA_PUBLIC_KEY
    sock=/var/run/docker.sock
    args+=(--group-add "$(stat -c %g "$sock")" -v "$sock":"$sock"
      -v "$CA_WORK":/ca/work -v "$CA_CACHE":/ca/cache
      -v "$CA_PUBLIC_KEY":/ca/keys/cosign.pub:ro -e CA_COSIGN_PUBLIC_KEY=/ca/keys/cosign.pub
      -e CA_HOST_WORKSPACE="$CA_WORKSPACE" -e CA_HOST_WORK="$CA_WORK" -e CA_HOST_CACHE="$CA_CACHE")
    # Feed già presenti in $CA_CACHE: nessuna sincronizzazione.
    if [ "${CA_OFFLINE:-}" = true ]; then set -- --offline "$@"; fi
    ;;
  gate) ;;
  notify)
    need GITHUB_EVENT_PATH
    args+=(-e GITHUB_TOKEN -e GITHUB_REPOSITORY -e GITHUB_API_URL -e GITHUB_EVENT_PATH
      -v "$GITHUB_EVENT_PATH":"$GITHUB_EVENT_PATH":ro)
    # Solo per le prove con un server finto su loopback (vedi `notify`).
    if [ -n "${CA_NOTIFY_ALLOW_LOOPBACK_HTTP:-}" ]; then args+=(-e CA_NOTIFY_ALLOW_LOOPBACK_HTTP); fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      args+=(-e GITHUB_STEP_SUMMARY -v "$GITHUB_STEP_SUMMARY":"$GITHUB_STEP_SUMMARY")
    fi
    ;;
  *) echo "errore: comando non previsto: $mode" >&2; exit 2 ;;
esac

# Registry su loopback (quello di prova): serve la rete dell'host. Vuoto negli altri casi.
if [ -n "${CA_NETWORK:-}" ]; then args+=(--network "$CA_NETWORK"); fi

exec docker "${args[@]}" "$CA_IMAGE" "$mode" "$@"
