# Componenti di terzi nell'immagine code-analyzer-plugin-checkov

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: checkov

- checkov 3.4.5 (Prisma Cloud), licenza Apache-2.0 (verificata sul testo in
  `doc/verifiche/scanner-fase-2.md`, V-02).
- Wheel `checkov-3.4.5-py3-none-any.whl` da PyPI, SHA-256
  `64210c48a957ecb85dfb38057e00faa150b5e46e76b08e710d29beb687b7ced2` (V-01), controllato da pip
  con `--require-hashes` durante la build, come ogni dipendenza in `requirements.lock`.
- Testo: `/licenses/checkov/LICENSE` (file `LICENSE` della wheel).
- checkov puo' contattare i servizi della piattaforma a pagamento del produttore: l'adattatore lo
  esegue con `--skip-download`, senza rete e senza chiave. Nessuna funzione della piattaforma e'
  usata.

## Dipendenze Python

- 95 pacchetti, tutti bloccati e con hash in `requirements.lock` (generato con `uv pip compile`
  da `requirements.in`). Licenze dichiarate dai metadati: in maggioranza permissive; tre
  dipendenze dichiarano una licenza con reciprocita' limitata ai file modificati (certifi, tqdm,
  orjson) e due non dichiarano una licenza nei metadati (cloudsplaining, networkx). I testi
  presenti nelle wheel sono in `/licenses/deps/`, uno per pacchetto. Per quelli che non portano un
  file di licenza nella wheel la verifica legale deve procurarsi il testo: voce aperta.

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

`/opt/ca-plugin/checkov_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
