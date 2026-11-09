# Componenti di terzi nell'immagine code-analyzer-plugin-scancode

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: scancode-toolkit

- scancode-toolkit 32.5.0 (nexB Inc. e altri). Il `NOTICE` della wheel dichiara Apache-2.0 per il
  codice e CC-BY-4.0 per i dati (attribuzione richiesta): `SPDX-License-Identifier: Apache-2.0 AND
  CC-BY-4.0` (V-02).
- Wheel `scancode_toolkit-32.5.0-cp312-none-any.whl` da PyPI, SHA-256
  `f6bc16880d495393c8475a77155ddc38a800c0b7f8f75e81a165a00fadb4ca06` (V-01), controllato da pip con
  `--require-hashes` durante la build, come ogni dipendenza in `requirements.lock`. Il lock fissa
  `pluggy` 1.6.0: scancode 32.5.0 non si avvia con pluggy 1.7 (V-07).
- Testi: `/licenses/scancode/NOTICE`, `/licenses/scancode/apache-2.0.LICENSE` e
  `/licenses/scancode/cc-by-4.0.LICENSE` (file della wheel).
- Componenti di terzi: scancode incorpora software con licenze permissive, di copyleft limitato e
  di copyleft (ad esempio libmagic e libarchive in forma precompilata). Ciascuno e' documentato da
  un file `.ABOUT`: tutti quelli della wheel e delle dipendenze sono in
  `/licenses/scancode/about/`, raccolti durante la build. Il codice sorgente dei componenti
  precompilati e' ottenibile dalla pagina di rilascio di scancode-toolkit. La verifica legale deve
  esaminarli uno per uno: voce aperta.

## Dipendenze Python

- Bloccate e con hash in `requirements.lock` (circa 80 pacchetti, anche con binari precompilati). I
  testi presenti nelle wheel sono in `/licenses/deps/`, uno per pacchetto; le licenze dichiarate dai
  metadati sono varie (MIT, BSD, Apache-2.0, MPL-2.0, LGPL, GPL per componenti binari). I pacchetti
  senza file di licenza nella wheel richiedono che la verifica legale si procuri i testi: voce
  aperta.

## Libreria di sistema

- `libgomp1` (GCC runtime library, GPL-3.0 con GCC Runtime Library Exception), installata con `apt`
  dal repository Debian 13 perche' richiesta da libarchive. La versione non e' fissata dal
  `Dockerfile` ma e' nell'SBOM. Condizioni in `/usr/share/doc/libgomp1/copyright`.

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

`/opt/ca-plugin/scancode_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
