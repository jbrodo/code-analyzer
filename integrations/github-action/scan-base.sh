#!/usr/bin/env bash
# Fonte 2 della baseline (ADR-0027): scansione completa del commit base nello stesso job, in una
# copia a parte con la sua configurazione. La copia è un clone locale: la CLI legge il commit da `.git`.
set -euo pipefail

for v in BASE_SHA CA_BASELINE_DIR CA_SCAN_ROOT CA_WORKSPACE; do
  [ -n "${!v:-}" ] || { echo "errore: variabile $v mancante" >&2; exit 2; }
done
[[ "$BASE_SHA" =~ ^[0-9a-f]{40,64}$ ]] || { echo "errore: commit base non valido" >&2; exit 2; }

copy="$CA_SCAN_ROOT/base"
out="$CA_SCAN_ROOT/base-output"
mkdir -p "$out"
chmod 700 "$out"
git clone --quiet --no-checkout --local "$CA_WORKSPACE" "$copy"
git -C "$copy" checkout --quiet --detach "$BASE_SHA"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_WORKSPACE="$copy" CA_OUTPUT="$out" "$here/run-cli.sh" scan --output-dir /ca/output
mkdir -p "$CA_BASELINE_DIR"
cp "$out/code-analyzer.report.json" "$CA_BASELINE_DIR/code-analyzer.report.json"
