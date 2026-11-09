# Componenti di terzi nell'immagine code-analyzer-plugin-gitleaks

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: gitleaks

- gitleaks v8.30.1 (Zach Rice e collaboratori), licenza MIT (verificata in
  `doc/verifiche/scanner-fase-1.md`, V-02).
- Binario linux amd64 dalla release GitHub `gitleaks/gitleaks` v8.30.1, controllato con SHA-256
  `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` durante la build.
- Configurazione predefinita `config/gitleaks.toml` dello stesso tag (MIT), SHA-256
  `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`, in
  `/opt/ca-plugin/gitleaks.toml`.
- Testo: `/licenses/gitleaks/LICENSE` (file `LICENSE` del tag v8.30.1).
- Il binario e' compilato in modo statico con moduli Go di terzi, ciascuno con la propria licenza. I
  nomi e le versioni dei moduli sono nei metadati del binario e quindi nell'SBOM dell'immagine; i
  testi delle loro licenze non sono inclusi in questa immagine e vanno raccolti nella verifica
  legale (voce aperta).

## git

- Pacchetto Debian `git` (GPL-2.0-only e altre licenze dei componenti), installato con `apt` dal
  repository Debian 13: la versione non e' fissata dal `Dockerfile` ma e' nell'SBOM. Le condizioni
  sono in `/usr/share/doc/git/copyright`. Il sorgente e' ottenibile dai repository Debian.

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

`/opt/ca-plugin/gitleaks_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
