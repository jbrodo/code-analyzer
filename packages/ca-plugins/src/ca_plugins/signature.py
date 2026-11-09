"""Verifica della firma delle immagini dei plugin con `cosign` (R-04, ADR-0005, V-06).

Comando, come lista e mai con una shell:
`cosign verify --key <pub> --insecure-ignore-tlog=true [--allow-http-registry] <immagine@digest>`.
Si verifica sempre il digest, mai un tag. Nessuna firma e nessun contatto con il log di
trasparenza pubblico. Ogni esito diverso da 0 (firma assente o errata, registry non raggiungibile,
cosign assente o di versione diversa, timeout) è `ScanAborted`: exit 2, nessun container, e un
solo messaggio che non distingue i casi. Lo stderr di cosign non viene riportato (dato non fidato).

Un riferimento su loopback usa sempre HTTP (registry locale di prova, I-04): il riferimento viene
dal manifest del pacchetto, mai dal repository analizzato. `allow_http_registry` lo decide solo chi
cabla; `allow_unsigned` solo la variabile d'ambiente `CA_INSECURE_ALLOW_UNSIGNED=1` letta dalla
radice di composizione: mai `.code-analyzer.yml`. Nessuna chiave pubblica nel pacchetto (D-0005).
"""

import os
import re
import shutil
import subprocess
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from ca_core.models.plugin_manifest import PackagedPluginManifest
from ca_core.ports import ScanAborted, Signature

COSIGN_VERSION: Final = "v3.1.4"
ENV_ALLOW_UNSIGNED: Final = "CA_INSECURE_ALLOW_UNSIGNED"
_ENV_ALLOWLIST: Final = ("PATH", "HOME", "USER", "DOCKER_CONFIG", "SSL_CERT_FILE", "SSL_CERT_DIR")
_REF: Final = re.compile(r"[a-z0-9][^\s@]*@sha256:[0-9a-f]{64}")
_LOOPBACK: Final = re.compile(r"(?:127\.0\.0\.1|localhost)(?::\d+)?/")
_DEFAULT_TIMEOUT: Final = 60.0


def allow_unsigned_from_env(environ: Mapping[str, str]) -> bool:
    return environ.get(ENV_ALLOW_UNSIGNED) == "1"


class CosignVerifier:
    """Chiamabile `(manifest, riferimento_per_digest) -> Signature` per `OciExecutor(verifier=)`."""

    def __init__(
        self,
        *,
        public_key: str | None,
        cosign: str | None = None,
        allow_http_registry: bool = False,
        allow_unsigned: bool = False,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._key = public_key
        self._cosign = cosign
        self._http = allow_http_registry
        self._unsigned = allow_unsigned
        self._timeout = timeout
        self._lock = threading.Lock()
        self._checked: str | None = None

    @staticmethod
    def _env() -> dict[str, str]:
        return {k: v for k in _ENV_ALLOWLIST if (v := os.environ.get(k)) is not None}

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(  # noqa: S603 - lista di argomenti, nessuna shell
                args,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                env=self._env(),
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ScanAborted(
                f"verifica della firma non eseguibile ({exc.__class__.__name__}): annullata"
            ) from exc

    def _binary(self) -> str:
        with self._lock:
            if self._checked is not None:
                return self._checked
            path = self._cosign or shutil.which("cosign")
            if not path or not os.access(path, os.X_OK):
                raise ScanAborted(
                    f"cosign {COSIGN_VERSION} non trovato: indicarlo con COSIGN=/percorso/cosign "
                    "(nessuna installazione automatica); scansione annullata"
                )
            done = self._run([path, "version"])
            if done.returncode != 0 or not re.search(
                rf"GitVersion:\s*{re.escape(COSIGN_VERSION)}\b",
                done.stdout.decode("utf-8", "replace"),
            ):
                raise ScanAborted(
                    f"cosign non riporta la versione {COSIGN_VERSION}: scansione annullata"
                )
            self._checked = path
            return path

    def __call__(self, manifest: PackagedPluginManifest, ref: str) -> Signature:
        if self._unsigned:
            return Signature.SKIPPED
        if not self._key or not Path(self._key).is_file():
            raise ScanAborted(
                "chiave pubblica di verifica non configurata o non leggibile "
                "(CA_COSIGN_PUBLIC_KEY): scansione annullata"
            )
        if not _REF.fullmatch(ref):
            raise ScanAborted(
                "l'immagine del plugin non è indicata per digest: scansione annullata"
            )
        args = [self._binary(), "verify", "--key", self._key, "--insecure-ignore-tlog=true"]
        if self._http or _LOOPBACK.match(ref):
            args.append("--allow-http-registry")
        if self._run([*args, ref]).returncode != 0:
            raise ScanAborted(
                f"firma dell'immagine del plugin {manifest.name} non verificata: annullata"
            )
        return Signature.VERIFIED


__all__ = ["COSIGN_VERSION", "ENV_ALLOW_UNSIGNED", "CosignVerifier", "allow_unsigned_from_env"]
