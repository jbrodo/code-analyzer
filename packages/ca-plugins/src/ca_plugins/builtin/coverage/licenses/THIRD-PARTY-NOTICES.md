# Componenti di terzi nell'immagine code-analyzer-plugin-coverage

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi

Nessuno. Il plugin legge i report di copertura che la CI ha prodotto (LCOV e Cobertura) con la
sola libreria standard di Python; non include coverage.py, vitest, nyc ne' altri strumenti che
generano quei report.

## Dipendenze Python

Nessuna.

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

`/opt/ca-plugin/coverage_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
