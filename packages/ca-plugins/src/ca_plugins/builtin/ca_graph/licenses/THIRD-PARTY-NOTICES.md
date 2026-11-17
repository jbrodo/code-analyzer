# Componenti di terzi nell'immagine code-analyzer-plugin-ca-graph

Questo file elenca i componenti di terzi inclusi nell'immagine e dove trovare i testi delle loro
licenze. Non dichiara la licenza del prodotto Code Analyzer. Non e' un parere legale: la verifica
legale e' di una persona.

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine
(prodotto da `deploy/docker/image-gate.sh`).

## Motore di analisi: tree-sitter

- tree-sitter 0.26.1, tree-sitter-python 0.25.0, tree-sitter-javascript 0.25.0 e
  tree-sitter-typescript 0.23.2 (progetto tree-sitter): licenza permissiva, verificata sul testo
  delle versioni fissate in `doc/verifiche/scanner-fase-2.md` (V-02).
- Wheel da PyPI con gli SHA-256 di V-01, controllati da pip con `--require-hashes` durante la
  build, come ogni dipendenza in `requirements.lock`.
- Testi: `/licenses/tree-sitter/LICENSE` (tree-sitter) e `LICENSE.python`, `LICENSE.javascript`,
  `LICENSE.typescript` (le tre grammatiche), copiati dalle wheel. Le wheel delle grammatiche
  contengono codice C generato: la sua provenienza non e' stata esaminata (V-02).
- Il parser legge file del repository analizzato, che sono input non fidato: per questo l'estrazione
  gira solo in questo container (ADR-0020).

## Dipendenze Python

Nessuna oltre a quelle elencate: `requirements.lock` contiene solo i quattro pacchetti.

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

## Adattatore e estrattore

`/opt/ca-plugin/ca_graph_adapter.py` e `/opt/ca-plugin/ca_graph/` sono codice di Code Analyzer
(nessuna licenza dichiarata, D-0015).
