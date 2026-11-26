"""Scansione di un repository del corpus in modalità benchmark (ADR-0023, K-06).

Lo lancia `benchmark.py collect` con il Python della CLI impacchettata. È una radice di
composizione, come il processo figlio degli E2E: la modalità benchmark non è un'opzione della riga
di comando di `code-analyzer`, la attiva solo chi compone il `Context`.

Rispetto a una scansione normale:
- solo i plugin ruff, eslint e ca-graph;
- `{"benchmark": true}` come `/inputs/config.json` di ruff ed eslint;
- limite di uscita al tetto del contratto e tempo più lungo per ruff ed eslint, perché ogni
  funzione dà un risultato (circa 350 byte l'uno: django supererebbe i 32 MiB dei manifest).

Argomenti: <repository> <cartella di uscita>. Richiede il registry locale attivo e
`CA_COSIGN_PUBLIC_KEY`, come la CLI impacchettata.
"""

import dataclasses
import json
import sys
import tempfile
from pathlib import Path

from ca_cli.composition import build_context
from ca_cli.main import main
from ca_core.models.plugin_manifest import MAX_OUTPUT_BYTES

PLUGINS = ("ruff", "eslint", "ca-graph")
BENCHMARK = ("ruff", "eslint")
TIMEOUT = "1800s"


class BenchmarkConfig:
    """Sostituisce `config` delle richieste di ruff ed eslint; il resto è delega."""

    def __init__(self, inner: object, path: str) -> None:
        self._inner, self._path = inner, path

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)

    def _with(self, request):  # type: ignore[no-untyped-def]
        if request.manifest.name in BENCHMARK:
            return request.model_copy(update={"config": self._path})
        return request

    def run(self, request):  # type: ignore[no-untyped-def]
        return self._inner.run(self._with(request))  # type: ignore[attr-defined]

    def run_many(self, requests):  # type: ignore[no-untyped-def]
        return self._inner.run_many([self._with(r) for r in requests])  # type: ignore[attr-defined]


def _widen(manifest):  # type: ignore[no-untyped-def]
    if manifest.name not in BENCHMARK:
        return manifest
    outputs = manifest.outputs.model_copy(update={"max_bytes": MAX_OUTPUT_BYTES})
    resources = manifest.resources.model_copy(update={"timeout": TIMEOUT})
    return manifest.model_copy(update={"outputs": outputs, "resources": resources})


def run(repository: str, out_dir: str) -> int:
    context = build_context()
    manifests = [_widen(m) for m in context.manifests() if m.name in PLUGINS]
    if sorted(m.name for m in manifests) != sorted(PLUGINS):
        print("errore: manca uno dei plugin del benchmark", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="ca-benchmark-") as scratch:
        config = Path(scratch) / "benchmark.json"
        config.write_text(json.dumps({"benchmark": True}))
        composed = dataclasses.replace(
            context,
            manifests=lambda: manifests,
            executor=BenchmarkConfig(context.executor, str(config)),
        )
        argv = ["scan", repository, "--output-dir", out_dir, "--format", "json", "--offline"]
        return main(argv, context=composed)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1], sys.argv[2]))
