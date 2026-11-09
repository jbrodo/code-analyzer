# Componenti di terzi nell'immagine code-analyzer-plugin-trivy

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: trivy

- trivy v0.76.2 (Aqua Security), licenza Apache-2.0 (verificata in `doc/verifiche/scanner-fase-1.md`, V-02).
- Binario linux amd64 dal tarball della release GitHub `aquasecurity/trivy` v0.76.2, controllato con
  SHA-256 `bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf` durante la build.
- Testi: `/licenses/trivy/LICENSE` e `/licenses/trivy/NOTICE` (file del tag v0.76.2).
- Il binario e' compilato in modo statico con moduli Go di terzi, ciascuno con la propria licenza. I
  nomi e le versioni dei moduli sono nei metadati del binario e quindi nell'SBOM dell'immagine; i
  testi delle loro licenze non sono inclusi in questa immagine e vanno raccolti nella verifica
  legale (voce aperta).

## Dati di vulnerabilita' e regole (non nell'immagine)

Il database di vulnerabilita' (trivy-db) e il bundle delle regole di configurazione non fanno parte
dell'immagine: li scarica `sync` in `/feeds/trivy` a run time. Hanno licenze proprie (trivy-db e'
una raccolta di fonti diverse); le condizioni sono nella verifica legale (voce aperta).

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

`/opt/ca-plugin/trivy_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
