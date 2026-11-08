"""Caricamento dei manifest dei plugin (§7.1; ADR-0004, 0005, 0014).

Il manifest è un dato del pacchetto CLI (`ca_plugins/builtin/<nome>/plugin.yaml`, con `_` al posto
di `-` nel nome della cartella), mai del repository analizzato né di `.code-analyzer.yml`.
Il rilascio inserisce il digest in `image` (ADR-0005); qui il manifest impacchettato senza digest
è rifiutato, come uno senza `outputs.max_bytes` (obbligatorio nel modello).
Parser: PyYAML con `safe_load` (nessun oggetto Python arbitrario); gli alias YAML sono rifiutati.
"""

import re
from importlib.resources import files
from typing import Any

import yaml
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
        if any(isinstance(e, yaml.AliasEvent) for e in yaml.parse(data, Loader=yaml.SafeLoader)):
            raise ManifestError("alias YAML non ammessi")
        raw: Any = yaml.safe_load(data)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ManifestError("manifest non è YAML valido") from exc
    if not isinstance(raw, dict):
        raise ManifestError("il manifest deve essere una mappa")
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
    resource = files("ca_plugins").joinpath("builtin", name.replace("-", "_"), "plugin.yaml")
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
    """Nomi dei plugin con `plugin.yaml` nel pacchetto, in ordine."""
    root = files("ca_plugins").joinpath("builtin")
    if not root.is_dir():
        return []
    return sorted(
        p.name.replace("_", "-") for p in root.iterdir() if p.joinpath("plugin.yaml").is_file()
    )
