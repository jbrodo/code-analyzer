# Componenti di terzi nell'immagine code-analyzer-plugin-semgrep

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: semgrep

- semgrep 1.184.0 (Semgrep, Inc.), motore community, licenza LGPL-2.1 (V-02). I metadati della
  wheel dichiarano `LGPL-2.1-or-later`: differenza da portare alla verifica legale.
- Wheel `semgrep-1.184.0-...-manylinux_2_34_x86_64.whl` da PyPI, SHA-256
  `d847abb8fb6fdde77d9e30a6bc869dbfcb68eff4142dcd77897c52635a7600d9` (V-01), controllato da pip con
  `--require-hashes` durante la build, come ogni dipendenza in `requirements.lock`.
- Testo: `/licenses/semgrep/LICENSE`, file `LICENSE` del tag `v1.184.0` del repository
  `semgrep/semgrep` (la wheel non lo contiene).
- La wheel contiene `semgrep-core`, un binario OCaml compilato con librerie di terzi: i loro testi di
  licenza non sono nell'immagine e vanno raccolti nella verifica legale (voce aperta).
- Aggregazione di un motore LGPL con il resto dell'immagine: da valutare (ADR-0015).

## Regole

- Solo le regole del progetto in `/opt/ca-plugin/rules/` (ADR-0015, P-09), scritte per questo
  prodotto. Nessuna regola del registry Semgrep (Semgrep Rules License v1.0) e' nell'immagine.

## Dipendenze Python

- Bloccate e con hash in `requirements.lock` (circa 40 pacchetti). I testi presenti nelle wheel sono
  in `/licenses/deps/`, uno per pacchetto. Licenze dichiarate dai metadati: per lo piu' MIT, BSD e
  Apache-2.0; `certifi` e' MPL-2.0 (copyleft debole); `glom` dichiara `UNKNOWN`, e boltons, peewee,
  colorama, exceptiongroup, face, markdown-it-py e mdurl non dichiarano una licenza nei metadati.
  La verifica legale deve procurarsi i testi che mancano: voce aperta.

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

`/opt/ca-plugin/semgrep_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
