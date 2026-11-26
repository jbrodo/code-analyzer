# Componenti di terzi nell'immagine code-analyzer-plugin-eslint

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: eslint con typescript-eslint

- eslint 10.15.0, @eslint/js 10.0.1, typescript-eslint 8.74.0 e typescript 6.0.3: licenza
  permissiva per ciascuno, verificata sul testo del pacchetto in `doc/verifiche/scanner-fase-2.md`
  (V-02; typescript include anche un avviso con testi di terzi). typescript e' alla 6.0.3 e non
  alla serie 7 perche' typescript-eslint 8.74.0 non la accetta (V-03).
- Versioni e integrita' di questi pacchetti e di tutte le dipendenze sono in `package-lock.json`;
  `npm ci` rifiuta cio' che non coincide.
- Testo di eslint: `/licenses/eslint/LICENSE`. I testi delle dipendenze, uno per pacchetto, sono in
  `/licenses/deps/`. Alcune dipendenze usano licenze permissive meno comuni (per esempio Blue Oak
  Model License): la verifica legale deve procurarsi i testi che il pacchetto non porta.

## Node.js

- Node 24, binario copiato dall'immagine ufficiale `node:24-trixie-slim`, fissata per digest nel
  `Dockerfile`. Licenza: file `LICENSE` del progetto Node, che elenca anche le licenze dei
  componenti inclusi nel binario; il testo non e' nell'immagine finale e va procurato dalla
  verifica legale: voce aperta.

## Interprete Python

- CPython 3.12, licenza PSF (Python Software Foundation License), per l'adattatore.
- Testo: `/licenses/python/LICENSE.txt` (copia di `/usr/local/lib/python3.12/LICENSE.txt`).

## Sistema base Debian 13 (trixie)

- Immagine di partenza: `python:3.12-slim-trixie`, fissata per digest nel `Dockerfile`.
- I pacchetti Debian hanno licenze diverse, anche con obblighi di copyleft. Le condizioni di
  ciascun pacchetto sono nel suo file `/usr/share/doc/<pacchetto>/copyright`, presente
  nell'immagine.
- Il sorgente dei pacchetti Debian e' ottenibile dai repository Debian corrispondenti alla versione
  riportata nell'SBOM.

## Adattatore e configurazione

`/opt/ca-plugin/eslint_adapter.py` e `/opt/ca-plugin/eslint.config.mjs` sono codice e
configurazione di Code Analyzer (nessuna licenza dichiarata, D-0015).
