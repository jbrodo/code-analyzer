# Componenti di terzi nell'immagine code-analyzer-plugin-bandit

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: bandit

- bandit 1.9.4 (PyCQA), licenza Apache-2.0 (verificata in `doc/verifiche/scanner-fase-1.md`, V-02).
- Wheel `bandit-1.9.4-py3-none-any.whl` da PyPI, SHA-256
  `f89ffa663767f5a0585ea075f01020207e966a9c0f2b9ef56a57c7963a3f6f8e` (V-01), controllato da pip
  con `--require-hashes` durante la build, come ogni dipendenza in `requirements.lock`.
- Testo: `/licenses/bandit/LICENSE` (file `LICENSE` della wheel). La wheel non contiene un `NOTICE`.

## Dipendenze Python

- Bloccate e con hash in `requirements.lock`: attrs, jschema-to-python, jsonpickle, markdown-it-py,
  mdurl, pbr, pygments, pyyaml, rich, sarif-om, setuptools, stevedore. Licenze dichiarate dai
  metadati (MIT, BSD, Apache-2.0); i testi presenti nelle wheel sono in `/licenses/deps/`, uno per
  pacchetto. Per i pacchetti che non portano un file di licenza nella wheel (markdown-it-py,
  mdurl) la verifica legale deve procurarsi il testo: voce aperta.

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

`/opt/ca-plugin/bandit_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
