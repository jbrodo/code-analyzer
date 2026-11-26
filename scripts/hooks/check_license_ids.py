"""Hook di pre-commit: avvisa se le righe aggiunte a un testo nominano una licenza copyleft.

scancode riconosce gli identificatori anche nella prosa: l'auto-analisi apre un finding di licenza
sul documento, o cambia l'impronta di un'eccezione già approvata, e il gate torna rosso. Nei
documenti la licenza si descrive a parole («licenza copyleft di rete», «licenza del progetto»).

Guarda solo le righe aggiunte nello stage, non i file interi: i documenti che nominano licenze
apposta (README, ADR-0013, note di terze parti) restano modificabili. Se un identificatore serve
davvero, serve anche un'eccezione approvata in `.code-analyzer.yml`: `SKIP=license-ids git commit`.
Solo libreria standard.
"""

import re
import subprocess
import sys

TEXT = ("*.md", "*.rst", "*.txt")
# Le famiglie copyleft che la policy (ADR-0013) vieta o chiede di approvare.
LICENSE_ID = re.compile(
    r"\b(?:A|L)?GPL(?:-[0-9][0-9.]*(?:-only|-or-later|\+)?)?\b|\bSSPL\b|\bEUPL\b"
    r"|\b(?:MPL|EPL|OSL)-[0-9][0-9.]*\b|\bCDDL\b|\bCPAL\b"
)
EXEMPT = re.compile(r"(^|/)(LICENSE[^/]*|COPYING[^/]*|THIRD-PARTY-NOTICES[^/]*|LICENSES-SBOM\.md)$")


def added_lines(diff: str) -> list[tuple[str, int, str]]:
    """(file, riga, testo) delle righe aggiunte in un diff unificato con `-U0`."""
    found: list[tuple[str, int, str]] = []
    path, line = "", 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else ""
        elif raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            line = int(match.group(1)) if match else 0
        elif raw.startswith("+") and path:
            found.append((path, line, raw[1:]))
            line += 1
    return found


def offending(diff: str) -> list[tuple[str, int, str]]:
    return [
        (path, line, match.group())
        for path, line, text in added_lines(diff)
        if not EXEMPT.search(path)
        for match in LICENSE_ID.finditer(text)
    ]


def main() -> int:
    diff = subprocess.run(
        ["git", "diff", "--cached", "-U0", "--no-color", "--diff-filter=AM", "--", *TEXT],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    found = offending(diff)
    for path, line, name in found:
        print(f"{path}:{line}: identificatore di licenza «{name}»: descrivilo a parole")
    if found:
        print("Se serve davvero, chiedi l'eccezione e usa SKIP=license-ids (AGENTS.md).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
