# Componenti di terzi nell'immagine code-analyzer-plugin-ruff

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: ruff

- ruff 0.17.5 (Astral), licenza MIT (verificata sul testo in `doc/verifiche/scanner-fase-2.md`,
  V-02).
- Wheel `ruff-0.17.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` da PyPI, SHA-256
  `40ca8afaac309b41a5b2e09e4e7beb1f824826b93c25697c4d74f573324fba4e` (V-01), controllato da pip
  con `--require-hashes` durante la build.
- Testo: `/licenses/ruff/LICENSE` (file `LICENSE` della wheel). Il file riporta anche le licenze
  del codice di terzi da cui ruff deriva le proprie regole, tutte nella stessa famiglia permissiva.

## Dipendenze Python

Nessuna: ruff e' un binario nativo e `requirements.lock` contiene solo la sua wheel.

## Interprete Python

- CPython 3.12, licenza PSF (Python Software Foundation License).
- Testo: `/licenses/python/LICENSE.txt` (copia di `/usr/local/lib/python3.12/LICENSE.txt`).

## Sistema base Debian 13 (trixie)

- Immagine di partenza: `python:3.12-slim-trixie`, fissata per digest nel `Dockerfile`.
- I pacchetti Debian hanno licenze diverse, anche con obblighi di copyleft. Le condizioni di
  ciascun pacchetto sono nel suo file `/usr/share/doc/<pacchetto>/copyright`, presente
  nell'immagine.
- Il sorgente dei pacchetti Debian e' ottenibile dai repository Debian corrispondenti alla versione
  riportata nell'SBOM.

## Adattatore

`/opt/ca-plugin/ruff_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
