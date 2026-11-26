# Componenti di terzi nell'immagine code-analyzer-server

Questo file elenca dove trovare i testi delle licenze dei componenti inclusi nell'immagine. Non e' un
parere legale: la verifica legale e' di una persona (D2-14).

L'elenco completo e versionato dei pacchetti e' nell'SBOM CycloneDX associato all'immagine, prodotto
da `deploy/docker/image-gate.sh`.

## Code Analyzer

- Pacchetti `ca-core` e `ca-api`: codice del progetto, con la licenza scelta dal proprietario.
- Testo: `/licenses/code-analyzer/LICENSE` (copia del file `LICENSE` del repository).

## Dipendenze Python

- Installate dal lock del repository, con gli hash. I file di licenza, avviso e copyright di ciascuna
  sono copiati in `/licenses/deps/<pacchetto>/`.
- L'interprete Python: `/licenses/python/LICENSE.txt`.

## Dashboard (SPA)

- Il codice compilato di `web/` e' in `/srv/web/`. Le licenze delle sue dipendenze di esecuzione e di
  quelle che queste richiedono sono in `/licenses/web/<pacchetto>-<versione>/`; l'elenco, con quali
  hanno un testo copiato, e' `/licenses/web/INDEX.tsv`.
- Le dipendenze di sviluppo (compilatore, test, linter) non sono nell'immagine.
