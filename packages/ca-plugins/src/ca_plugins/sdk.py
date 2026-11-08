"""Caricamento dei manifest dei plugin (§7.1; ADR-0004, 0005, 0014).

Il manifest è un dato del pacchetto CLI (`ca_plugins/manifests/<nome>.json`), mai del repository
analizzato né di `.code-analyzer.yml`. Il formato è JSON, sottoinsieme di YAML: evita un parser in
più (shortcut: se serve YAML, aggiungere PyYAML con `safe_load` e verifica di licenza).
Il rilascio inserisce il digest in `image` (ADR-0005); qui il manifest impacchettato senza digest
è rifiutato, come uno senza `outputs.max_bytes` (obbligatorio nel modello).
"""

import json
import re
from importlib.resources import files
from typing import Any

from pydantic import ValidationError

from ca_core.models import PackagedPluginManifest, PluginManifest

MAX_MANIFEST_BYTES = 65_536
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")  # stesso vincolo di `PluginManifest.name`


class ManifestError(ValueError):
    """Manifest non leggibile o non conforme al contratto."""


def parse_manifest(data: bytes, *, packaged: bool = True) -> PluginManifest:
    """Valida i byte di un manifest; `packaged` richiede il digest in `image`."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest troppo grande")
    try:
        raw: Any = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise ManifestError("manifest non è JSON valido") from exc
    model = PackagedPluginManifest if packaged else PluginManifest
    try:
        return model.model_validate(raw, strict=False)
    except ValidationError as exc:
        # Non si riporta l'input (dato non fidato): solo posizione e tipo di errore.
        detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['type']}" for e in exc.errors())
        raise ManifestError(f"manifest non conforme: {detail}") from exc


def load_packaged_manifest(name: str) -> PackagedPluginManifest:
    """Legge il manifest impacchettato del plugin `name` dai dati del pacchetto."""
    if not _NAME.fullmatch(name):
        raise ManifestError("nome plugin non valido")
    resource = files("ca_plugins").joinpath("manifests", f"{name}.json")
    if not resource.is_file():
        raise ManifestError(f"manifest assente per il plugin {name!r}")
    with resource.open("rb") as handle:
        data = handle.read(MAX_MANIFEST_BYTES + 1)
    manifest = parse_manifest(data, packaged=True)
    if manifest.name != name:
        raise ManifestError("il nome nel manifest non corrisponde al file")
    assert isinstance(manifest, PackagedPluginManifest)
    return manifest


def list_packaged_plugins() -> list[str]:
    """Nomi dei plugin con manifest nel pacchetto, in ordine."""
    root = files("ca_plugins").joinpath("manifests")
    if not root.is_dir():
        return []
    return sorted(p.name.removesuffix(".json") for p in root.iterdir() if p.name.endswith(".json"))
