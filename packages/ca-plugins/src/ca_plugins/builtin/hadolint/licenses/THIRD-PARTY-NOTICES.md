# Componenti di terzi nell'immagine code-analyzer-plugin-hadolint

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: hadolint

- hadolint 2.15.1 (progetto hadolint), binario statico dai rilasci ufficiali, SHA-256
  `c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507` (V-01), controllato dalla
  build. Il binario include librerie Haskell e ShellCheck, con le loro licenze.
- Licenza: copyleft forte, della stessa famiglia e versione di quella del prodotto; D-0013 la mette
  tra quelle da approvare. **Approvata solo per uso interno** (D2-14, 2026-11-17, Riccardo Roveda).
- Testo: `/licenses/hadolint/LICENSE`, scaricato dal tag `v2.15.1` del sorgente con controllo
  dell'SHA-256 `589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2`.
- **Offerta della sorgente.** Il sorgente corrispondente al binario di questa immagine e' il tag
  `v2.15.1` (commit `2eece55955ced00200be9729e9728cb7dacca505`) del repository
  `https://github.com/hadolint/hadolint`. Chi distribuisce questa immagine deve mantenere l'offerta
  e fornire il sorgente a chi lo chiede. Finche' l'immagine e' solo per uso interno l'obbligo non
  scatta, ma l'offerta resta scritta qui perche' non si perda al rilascio (I-07).

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

`/opt/ca-plugin/hadolint_adapter.py` e' codice di Code Analyzer (nessuna licenza dichiarata, D-0015).
