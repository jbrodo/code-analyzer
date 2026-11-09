"""Processo figlio degli E2E: `code-analyzer` come lo lancia l'utente, con tre cablature di prova.

Cio' che la riga di comando non offre (e che `packages/` non fornisce ancora, I-04):
1. i manifest dei plugin con il digest vero (il pacchetto ha `registry.invalid` e nessun digest);
2. il registry locale su HTTP (`allow_http_registry`, opzione di chi cabla);
3. la cache dei feed congelata (`Context.feeds_cache`).
Facoltative: `inject_config` (plugin -> file) emula il cablaggio di `inputs.config`, che
`run_plugins` non fa; `network_guard` rifiuta ogni connessione di questo processo fuori dal
loopback (non copre cosign e docker, che sono processi figli).

Argomenti: <spec.json> <argv di code-analyzer...>
"""

import dataclasses
import json
import socket
import sys

from ca_cli.composition import build_context
from ca_cli.main import main
from ca_core.models import PackagedPluginManifest

spec = json.load(open(sys.argv[1]))  # noqa: SIM115 - script di prova, vive quanto il processo
argv = sys.argv[2:]

if spec.get("network_guard"):
    _connect = socket.socket.connect

    def guarded(self: socket.socket, address: object) -> None:
        if self.family == socket.AF_UNIX or (
            isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "::1")
        ):
            return _connect(self, address)  # type: ignore[arg-type]
        raise OSError(f"E2E: connessione di rete non consentita verso {address!r}")

    socket.socket.connect = guarded  # type: ignore[method-assign]


class ConfigInjector:
    """Aggiunge `config` alle richieste dei plugin indicati; il resto e' delega."""

    def __init__(self, inner: object, configs: dict[str, str]) -> None:
        self._inner, self._configs = inner, configs

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)

    def _with(self, request):  # type: ignore[no-untyped-def]
        path = self._configs.get(request.manifest.name)
        return request.model_copy(update={"config": path}) if path else request

    def run(self, request):  # type: ignore[no-untyped-def]
        return self._inner.run(self._with(request))  # type: ignore[attr-defined]

    def run_many(self, requests):  # type: ignore[no-untyped-def]
        return self._inner.run_many([self._with(r) for r in requests])  # type: ignore[attr-defined]


manifests = [
    PackagedPluginManifest.model_validate(json.load(open(path))) for path in spec["manifests"]
]
context = build_context(allow_http_registry=True)
changes: dict[str, object] = {"manifests": lambda: manifests}
if spec.get("feeds_cache"):
    from pathlib import Path

    changes["feeds_cache"] = Path(spec["feeds_cache"])
if spec.get("inject_config"):
    changes["executor"] = ConfigInjector(context.executor, spec["inject_config"])
sys.exit(main(argv, context=dataclasses.replace(context, **changes)))
