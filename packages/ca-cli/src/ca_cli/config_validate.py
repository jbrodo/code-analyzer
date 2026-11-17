"""`config validate` (L-02, ADR-0010, 0013, 0014): controllo offline di `.code-analyzer.yml`.

Il file sta nel repository analizzato: input non fidato. Stessi criteri di `ca_plugins/sdk.py`
(`safe_load`, limite di dimensione prima del parsing, alias rifiutati, documento mappa), poi il
modello di `ca_core`. I messaggi riportano posizione e tipo di errore, mai il valore. Nessuna
rete, nessun Docker. Il file non può toccare immagini, firma, isolamento, rete: il modello non ha
chiavi per questi valori (`extra="forbid"`).
"""

import argparse
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ca_cli.composition import Context
from ca_core.models.config import CodeAnalyzerConfig
from ca_core.policy.licenses import SpdxSyntaxError, parse_expression

CONFIG_NAME = ".code-analyzer.yml"
MAX_CONFIG_BYTES = 262_144
_SAFE_KEY = re.compile(r"[A-Za-z0-9_-]{1,64}")
_INERT = ("service", "scoring", "agents")  # validate ma senza effetto in Fase 1 (ADR-0014)


class ConfigFileError(ValueError):
    """File non leggibile o non conforme; il testo non contiene mai valori del file."""


def _where(loc: tuple[int | str, ...]) -> str:
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        else:  # il nome di una chiave sconosciuta è dato non fidato
            out += ("." if out else "") + (part if _SAFE_KEY.fullmatch(part) else "<chiave>")
    return out or "<radice>"


def parse_config(data: bytes) -> CodeAnalyzerConfig:
    """Valida i byte del file; `ConfigFileError` con le sole posizioni e tipi di errore."""
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigFileError("file troppo grande")
    try:
        events = yaml.parse(data, Loader=yaml.SafeLoader)
        if any(isinstance(e, yaml.AliasEvent) for e in events):
            raise ConfigFileError("alias YAML non ammessi")
        raw: Any = yaml.safe_load(data)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        at = f" (riga {mark.line + 1}, colonna {mark.column + 1})" if mark else ""
        raise ConfigFileError(f"YAML non valido{at}") from exc
    except (yaml.YAMLError, RecursionError) as exc:
        raise ConfigFileError("YAML non valido") from exc
    if not isinstance(raw, dict):
        raise ConfigFileError("il documento deve essere una mappa")
    try:
        return CodeAnalyzerConfig.model_validate(raw, strict=False)
    except ValidationError as exc:
        found = exc.errors(include_input=False, include_url=False)
        raise ConfigFileError("; ".join(f"{_where(e['loc'])}: {e['type']}" for e in found)) from exc


def semantic_checks(
    config: CodeAnalyzerConfig, root: Path, today: date
) -> tuple[list[str], list[str]]:
    """Controlli oltre lo schema: (errori, avvisi). Mai valori del file nei messaggi."""
    errors: list[str] = []
    warnings: list[str] = []
    listed: set[str] = set()
    if config.licenses:
        for name in ("forbidden", "require_approval"):
            for i, expression in enumerate(getattr(config.licenses, name)):
                try:
                    parse_expression(expression)
                except SpdxSyntaxError:
                    errors.append(f"licenses.{name}[{i}]: spdx_syntax")
                listed.add(expression)
        for name in ("forbidden", "require_approval"):
            for i, expression in enumerate(getattr(config.licenses, name)):
                if expression.endswith("-only") and f"{expression[:-5]}-or-later" not in listed:
                    warnings.append(f"licenses.{name}[{i}]: solo_variante_only")
    for i, item in enumerate(config.exceptions):
        if item.expires < today:
            warnings.append(f"exceptions[{i}].expires: scaduta, l'eccezione sarà ignorata")
    resolved_root = root.resolve()
    rules = config.plugins.semgrep.rules if config.plugins.semgrep else []
    for i, rule_path in enumerate(rules):
        where = f"plugins.semgrep.rules[{i}]"
        target = (resolved_root / rule_path).resolve()
        if not target.is_relative_to(resolved_root):
            errors.append(f"{where}: fuori_dal_workspace")
        elif not target.exists():
            warnings.append(f"{where}: percorso_assente")
    warnings.extend(
        f"{key}: chiave inerte in Fase 1" for key in _INERT if getattr(config, key) is not None
    )
    if config.gate.mode.value == "new-findings-only":
        warnings.append("gate.mode: vale solo in una scansione PR con baseline valida")
    return errors, warnings


def handle(args: argparse.Namespace, context: Context) -> int:
    target = Path(args.path)
    file = target / CONFIG_NAME if target.is_dir() else target
    if not file.is_file():
        print(f"code-analyzer: {file.name}: file assente", file=sys.stderr)
        return 2
    with file.open("rb") as handle_:
        data = handle_.read(MAX_CONFIG_BYTES + 1)
    try:
        config = parse_config(data)
    except ConfigFileError as exc:
        print(f"code-analyzer: {file.name}: {exc}", file=sys.stderr)
        return 2
    errors, warnings = semantic_checks(config, file.parent, context.clock.now().date())
    for message in warnings:
        print(f"avviso: {file.name}: {message}", file=sys.stderr)
    for message in errors:
        print(f"errore: {file.name}: {message}", file=sys.stderr)
    if errors:
        return 2
    print(f"{file.name}: valido")
    return 0
