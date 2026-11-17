#!/usr/bin/env bash
# G-09: prepara il contesto di build di un plugin che include file di altri pacchetti.
#
# Uso: deploy/docker/stage-context.sh <contesto>
#
# Un plugin che non ha un file `context.sources` si costruisce dalla propria cartella, e questo
# script stampa quella cartella senza toccarla. Con `context.sources`, crea una cartella
# temporanea con una copia del plugin e dei file elencati, e ne stampa il percorso: la rimozione
# spetta a chi chiama (`[ "$ctx" = "$orig" ] || rm -rf "$ctx"`).
#
# Formato di `context.sources`: una riga `<sorgente> <destinazione>`; `#` e righe vuote ignorate.
# La sorgente e' relativa alla radice del repository, la destinazione al contesto. Sono rifiutati
# percorsi assoluti, segmenti `..` e sorgenti inesistenti. `__pycache__` e `*.pyc` non si copiano,
# e `context.sources` stesso non entra nel contesto: la sorgente del codice e' una sola.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CONTEXT="${1:-}"
die() { echo "errore: $*" >&2; exit 2; }
[ -d "$CONTEXT" ] || die "uso: $0 <contesto>"
LIST="$CONTEXT/context.sources"
if [ ! -f "$LIST" ]; then
  echo "$CONTEXT"
  exit 0
fi

safe() { # percorso relativo, senza `..`, senza `/` iniziale
  case "$1" in ""|/*|..|../*|*/..|*/../*) return 1 ;; esac
}

STAGED="$(mktemp -d)"
cp -a "$CONTEXT"/. "$STAGED"/
rm -f "$STAGED/context.sources"
while read -r source dest extra; do
  [ -n "${source:-}" ] || continue
  case "$source" in \#*) continue ;; esac
  [ -z "${extra:-}" ] && [ -n "${dest:-}" ] || { rm -rf "$STAGED"; die "riga non valida in context.sources: $source"; }
  safe "$source" && safe "$dest" || { rm -rf "$STAGED"; die "percorso non ammesso in context.sources: $source $dest"; }
  [ -e "$ROOT/$source" ] || { rm -rf "$STAGED"; die "sorgente inesistente: $source"; }
  [ ! -L "$ROOT/$source" ] || { rm -rf "$STAGED"; die "sorgente collegamento simbolico: $source"; }
  mkdir -p "$(dirname "$STAGED/$dest")"
  cp -a "$ROOT/$source" "$STAGED/$dest"
done < "$LIST"
find "$STAGED" \( -name __pycache__ -type d -prune -o -name '*.pyc' -type f \) -exec rm -rf {} + 2>/dev/null || true
echo "$STAGED"
