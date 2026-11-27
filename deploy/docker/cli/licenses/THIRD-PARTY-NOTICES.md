# Componenti di terzi nell'immagine code-analyzer-cli

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non e' un parere legale: la verifica legale e' di una persona (D2-14).

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Code Analyzer

- Pacchetti `ca-core`, `ca-plugins`, `ca-graph`, `ca-integrations`, `ca-cli`: codice del progetto, con la licenza del progetto (`/licenses/code-analyzer/LICENSE`).
- Testo: `/licenses/code-analyzer/LICENSE` (copia del file `LICENSE` del repository).

## cosign

- cosign v3.1.4 (Sigstore), licenza Apache-2.0.
- Binario `cosign-linux-amd64` dal rilascio v3.1.4, SHA-256
  `424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa`, controllato da
  `ADD --checksum` durante la build.
- Testo: `/licenses/cosign/LICENSE` (file `LICENSE` del tag v3.1.4). Il binario collega in modo
  statico moduli Go di terzi: le loro licenze sono elencate nell'SBOM. Voce aperta per D2-14.

## Client Docker

- docker/cli 28.5.2, licenza Apache-2.0. Solo il client: nessun daemon nell'immagine.
- Binario `/usr/local/bin/docker` copiato dall'immagine ufficiale `docker:28.5.2-cli`, fissata per
  digest nel `Dockerfile`.
- Testi: `/licenses/docker/LICENSE` e `/licenses/docker/NOTICE` (tag v28.5.2). Come per cosign, i
  moduli Go collegati sono nell'SBOM. Voce aperta per D2-14.

## Dipendenze Python

- Bloccate e con hash da `uv.lock` (`uv export`), installate con `pip --require-hashes`. I testi
  di licenza presenti nelle wheel sono in `/licenses/deps/`, una cartella per pacchetto. Per i
  pacchetti che non portano un file di licenza nella wheel la verifica deve procurarsi il testo:
  voce aperta per D2-14.

## Interprete Python

- CPython 3.14, licenza PSF (Python Software Foundation License).
- Testo: `/licenses/python/LICENSE.txt` (copia di `/usr/local/lib/python3.14/LICENSE.txt`).

## Sistema base Debian 13 (trixie)

- Immagine di partenza: `python:3.14-slim-trixie`, fissata per digest nel `Dockerfile`.
- I pacchetti Debian hanno licenze diverse, anche copyleft (per esempio GPL e LGPL per libc e
  utility di base). Le condizioni di ciascun pacchetto sono nel suo file
  `/usr/share/doc/<pacchetto>/copyright`, presente nell'immagine.
- Il sorgente dei pacchetti Debian e' ottenibile dai repository Debian corrispondenti alla versione
  riportata nell'SBOM.
