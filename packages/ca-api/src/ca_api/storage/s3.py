"""Adattatore S3 della porta `ArtifactStore` (B-07, ADR-0030, D2-07).

Parla il protocollo S3 con un servizio fornito da chi installa: indirizzo, bucket e regione dalla
configurazione del server; **credenziali solo dall'ambiente o da file montati** (catena predefinita
di boto3), mai da un argomento. Supera la stessa batteria di contratto dell'adattatore su file
system. Nessun server di object storage nel prodotto.

Scrittura: il flusso si legge in un file temporaneo con il tetto di `max_bytes` e il digest
calcolato mentre si legge (S3 vuole la lunghezza), poi `PutObject` con `If-None-Match: *`, che
rifiuta la sovrascrittura anche in corsa. Il digest sta nei metadati dell'oggetto: una ripetizione
si riconosce con un `HEAD`, senza scaricare nulla. Chiavi: `prefix` più la chiave validata.
"""

import hashlib
import io
import tempfile
from typing import Any, BinaryIO

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from ca_core.ports import (
    ArtifactConflict,
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactTooLarge,
    StoredArtifact,
    validate_artifact_key,
)

CHUNK = 1024 * 1024
SPOOL_BYTES = 8 * 1024 * 1024
META_SHA = "sha256"
_NOT_FOUND = {"404", "NoSuchKey", "NotFound"}


class StorageUnavailable(RuntimeError):
    """Il servizio S3 non risponde o rifiuta l'accesso; il messaggio non riporta credenziali."""


def make_client(
    *, endpoint_url: str | None, region: str, allow_http: bool = False, timeout: int = 30
) -> Any:
    """Client S3 con credenziali dalla catena predefinita (ambiente o file montati)."""
    import boto3

    if endpoint_url and endpoint_url.startswith("http://") and not allow_http:
        raise ValueError("endpoint S3 non cifrato: serve https")
    config = Config(
        connect_timeout=timeout,
        read_timeout=timeout,
        retries={"max_attempts": 3, "mode": "standard"},
        s3={"addressing_style": "path"},
    )
    return boto3.client("s3", endpoint_url=endpoint_url, region_name=region, config=config)


class _Reader(io.RawIOBase):
    """Il corpo di una risposta S3 come flusso binario, chiudibile con `with`."""

    def __init__(self, body: Any) -> None:
        self._body = body

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._body.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        try:
            self._body.close()
        finally:
            super().close()


class S3ArtifactStore:
    def __init__(self, client: Any, bucket: str, *, prefix: str = "") -> None:
        if not bucket or "/" in bucket:
            raise ValueError("nome del bucket non valido")
        if prefix:
            validate_artifact_key(prefix.strip("/"))
        self._client, self._bucket = client, bucket
        self._prefix = prefix.strip("/") + "/" if prefix else ""

    def _object(self, key: str) -> str:
        return self._prefix + validate_artifact_key(key)

    @staticmethod
    def _missing(exc: ClientError) -> bool:
        return str(exc.response.get("Error", {}).get("Code", "")) in _NOT_FOUND

    def _head_digest(self, name: str) -> str | None:
        try:
            head = self._client.head_object(Bucket=self._bucket, Key=name)
        except ClientError as exc:
            if self._missing(exc):
                return None
            raise StorageUnavailable("richiesta rifiutata") from exc
        except BotoCoreError as exc:
            raise StorageUnavailable("servizio non raggiungibile") from exc
        value = head.get("Metadata", {}).get(META_SHA)
        return value if isinstance(value, str) else ""

    def put(
        self, key: str, stream: BinaryIO, *, max_bytes: int, sha256: str | None = None
    ) -> StoredArtifact:
        name = self._object(key)
        if max_bytes < 1:
            raise ValueError("max_bytes deve essere positivo")
        sha, size = hashlib.sha256(), 0
        with tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES) as spool:
            while chunk := stream.read(min(CHUNK, max_bytes + 1 - size)):
                size += len(chunk)
                if size > max_bytes:
                    raise ArtifactTooLarge(f"oltre {max_bytes} byte")
                sha.update(chunk)
                spool.write(chunk)
            digest = sha.hexdigest()
            if sha256 is not None and sha256 != digest:
                raise ArtifactIntegrityError("sha256 dichiarato diverso da quello dei byte")
            spool.seek(0)
            try:
                self._client.put_object(
                    Bucket=self._bucket,
                    Key=name,
                    Body=spool,
                    ContentLength=size,
                    IfNoneMatch="*",
                    Metadata={META_SHA: digest},
                )
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code", ""))
                if code not in {"PreconditionFailed", "412", "ConditionalRequestConflict"}:
                    raise StorageUnavailable("scrittura rifiutata") from exc
                if self._head_digest(name) != digest:
                    raise ArtifactConflict("la chiave esiste con contenuto diverso") from None
            except BotoCoreError as exc:
                raise StorageUnavailable("servizio non raggiungibile") from exc
        return StoredArtifact(key=key, size=size, sha256=digest)

    def open(self, key: str) -> BinaryIO:
        name = self._object(key)
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=name)
        except ClientError as exc:
            if self._missing(exc):
                raise ArtifactNotFound(key) from exc
            raise StorageUnavailable("lettura rifiutata") from exc
        except BotoCoreError as exc:
            raise StorageUnavailable("servizio non raggiungibile") from exc
        return io.BufferedReader(_Reader(response["Body"]))

    def exists(self, key: str) -> bool:
        return self._head_digest(self._object(key)) is not None

    def delete(self, key: str) -> None:
        name = self._object(key)
        try:
            self._client.delete_object(Bucket=self._bucket, Key=name)
        except ClientError as exc:
            if not self._missing(exc):
                raise StorageUnavailable("cancellazione rifiutata") from exc
        except BotoCoreError as exc:
            raise StorageUnavailable("servizio non raggiungibile") from exc
