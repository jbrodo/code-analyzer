# Componenti di terzi nell'immagine code-analyzer-plugin-osv-scanner

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: osv-scanner

- osv-scanner v2.7.0 (Google), licenza Apache-2.0 (verificata in `doc/verifiche/scanner-fase-1.md`, V-02).
- Binario linux amd64 dalla release GitHub `google/osv-scanner` v2.7.0, controllato con SHA-256
  `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` durante la build.
- Testo: `/licenses/osv-scanner/LICENSE` (file `LICENSE` del tag v2.7.0). Il repository non ha un `NOTICE`.
- Il binario e' compilato in modo statico con moduli Go di terzi, ciascuno con la propria licenza. I
  nomi e le versioni dei moduli sono nei metadati del binario e quindi nell'SBOM dell'immagine; i
  testi delle loro licenze non sono inclusi in questa immagine e vanno raccolti nella verifica
  legale (voce aperta).

## Dati di vulnerabilita' (non nell'immagine)

Il database OSV (`all.zip` per ecosistema) non fa parte dell'immagine: lo scarica `sync` in
`/feeds` a run time. I record provengono da fonti diverse con licenze proprie, non valutate qui:
attribuzione e condizioni di redistribuzione sono nella verifica legale (voce aperta).

## Interprete Python

- CPython 3.12, licenza PSF (Python Software Foundation License).
- Testo: `/licenses/python/LICENSE.txt` (copia di `/usr/local/lib/python3.12/LICENSE.txt`).

## Sistema base Debian 13 (trixie)

- Immagine di partenza: `python:3.12-slim-trixie`, fissata per digest nel `Dockerfile`.
- I pacchetti Debian hanno licenze diverse, anche copyleft (per esempio GPL e LGPL per libc e
  utility di base). Le condizioni di ciascun pacchetto sono nel suo file
  `/usr/share/doc/<pacchetto>/copyright`, presente nell'immagine.
- Il sorgente dei pacchetti Debian e' ottenibile dai repository Debian corrispondenti alla versione
  riportata nell'SBOM.

## Adattatore

`/opt/ca-plugin/osv_scanner_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
