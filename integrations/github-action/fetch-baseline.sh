#!/usr/bin/env bash
# Cerca il report del commit base tra gli artefatti dell'esecuzione `push` sul branch principale
# (ADR-0027, "Baseline su GitHub"). Non usa la cache della CI. Scrive il file in $CA_BASELINE_DIR
# e `found=true|false` in $GITHUB_OUTPUT. Non fallisce se non trova nulla: decide il chiamante.
set -euo pipefail

NAME=code-analyzer-baseline
REPORT=code-analyzer.report.json
MAX_BYTES=$((100 * 1024 * 1024))

for v in GH_TOKEN GITHUB_REPOSITORY GITHUB_WORKFLOW_REF BASE_SHA DEFAULT_BRANCH CA_BASELINE_DIR; do
  [ -n "${!v:-}" ] || { echo "errore: variabile $v mancante" >&2; exit 2; }
done
out="${GITHUB_OUTPUT:-/dev/null}"
no() { echo "found=false" >> "$out"; echo "::notice::baseline: $1"; exit 0; }

[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "errore: repository non valido" >&2; exit 2; }
[[ "$BASE_SHA" =~ ^[0-9a-f]{40,64}$ ]] || { echo "errore: commit base non valido" >&2; exit 2; }
[[ "$DEFAULT_BRANCH" =~ ^[A-Za-z0-9_./-]+$ ]] || no "nome del branch principale non valido"

# GITHUB_WORKFLOW_REF = proprietario/repo/.github/workflows/file.yml@ref: serve solo il nome del file.
path="${GITHUB_WORKFLOW_REF%%@*}"
file="${path##*/}"
[[ "$file" =~ ^[A-Za-z0-9_.-]+\.ya?ml$ ]] || no "flusso non riconosciuto"

runs=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/$file/runs" \
  -f event=push -f branch="$DEFAULT_BRANCH" -f head_sha="$BASE_SHA" -f status=success \
  --jq '.workflow_runs[0].id // empty') || no "ricerca dell'esecuzione non riuscita"
[[ "$runs" =~ ^[0-9]+$ ]] || no "nessuna esecuzione riuscita sul commit base"

artifact=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$runs/artifacts" -f name="$NAME" \
  --jq '[.artifacts[] | select(.expired == false)][0] | "\(.id) \(.size_in_bytes)"') \
  || no "elenco degli artefatti non riuscito"
id="${artifact%% *}"; size="${artifact##* }"
[[ "$id" =~ ^[0-9]+$ && "$size" =~ ^[0-9]+$ ]] || no "artefatto assente o scaduto"
[ "$size" -le "$MAX_BYTES" ] || no "artefatto troppo grande"

zip="$(mktemp)"
trap 'rm -f "$zip"' EXIT
gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id/zip" > "$zip" || no "download non riuscito"
mkdir -p "$CA_BASELINE_DIR"
# Si estrae un solo nome, scelto da noi: nessun percorso dello zip arriva sul disco.
unzip -p "$zip" "$REPORT" > "$CA_BASELINE_DIR/$REPORT" 2>/dev/null || no "il report non è nell'artefatto"
echo "found=true" >> "$out"
