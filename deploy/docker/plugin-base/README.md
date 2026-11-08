# Immagine base dei plugin

`Dockerfile` fissa `python:3.12-slim-trixie` per digest dell'indice OCI.

Fonte del digest: header `Docker-Content-Digest` di
`https://registry-1.docker.io/v2/library/python/manifests/3.12-slim-trixie`
(letto il 2026-11-08, con `Accept: application/vnd.oci.image.index.v1+json`).
Riverifica: `docker buildx imagetools inspect python:3.12-slim-trixie` deve
riportare lo stesso `Digest`.

Le immagini dei plugin derivano da questa (`FROM` per digest) e aggiungono
scanner e adattatore. Nessun registry: D-0005 e' aperta, l'immagine resta locale.

Prova locale con il profilo `hardened-container` (ADR-0004):

```
docker build -t ca-plugin-base:local deploy/docker/plugin-base
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid -e HOME=/tmp \
  -v "$PWD":/workspace:ro --user 65534:65534 \
  ca-plugin-base:local python -c 'print("ok")'
```
