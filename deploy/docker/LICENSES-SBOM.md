# Licenze e SBOM per immagine (I-05)

ADR-0015, §7.3 e §15, `doc/verifiche/scanner-fase-1.md` (V-02, V-03). Ogni
immagine contiene i file di licenza dei componenti di terzi e ha un SBOM
associato. Se manca uno dei due, il controllo fallisce.

**La licenza del prodotto non e' dichiarata (D-0015).** Nessun file o etichetta
la riporta: `org.opencontainers.image.licenses` e' vietata dal controllo. I
file di licenza riguardano solo scanner e dipendenze incluse. Sono un materiale
per la verifica legale, che resta di una persona: non la sostituiscono.

## Strumenti
- `image-gate.sh <immagine> <cartella-sbom>`: controlla le licenze nell'immagine
  (letta con `docker create`/`docker cp`, senza eseguirla), poi produce l'SBOM
  con syft 1.57.0 (`SYFT=/percorso/syft`, versione verificata; `CA_SYFT_SHA256`
  opzionale) e lo valida. Uscite: 0 ok, 2 uso o strumento mancante, 3 licenze,
  4 SBOM.
- `build-image.sh <contesto> <nome:tag> <cartella-sbom>`: `docker build` locale
  piu' `image-gate.sh`. Nessun push, nessuna firma.
- `test-image-gate.sh`: prova dei casi positivi e negativi, pulisce le immagini.

## SBOM
CycloneDX 1.7 JSON (syft `cyclonedx-json@1.7`), un file per immagine:
`<cartella>/<riferimento>-<primi 12 caratteri dell'ID immagine>.cdx.json`. Il
file e' accanto all'immagine, non dentro (non e' possibile includere l'SBOM
dell'immagine nell'immagine stessa). Il legame e' l'ID dell'immagine nel nome e
`metadata.component` del documento. Pubblicarlo o allegarlo al registry (e
firmarlo) spetta a I-04/I-06.

Per ogni rilascio, conservare immagini, digest e SBOM nella cartella persistente
di output di `package-cli.sh` (`<cartella-di-uscita>/sbom/`), non in `/tmp`.
Le versioni dei pacchetti APT non sono fissate dalla build: l'SBOM documenta i
componenti effettivamente inclusi in quel rilascio.

## Licenze nell'immagine
- `/licenses/THIRD-PARTY-NOTICES.md` (non vuoto): componenti di terzi e dove
  stanno i testi. Obbligatorio in ogni immagine.
- Etichetta `ca.engines="scancode,semgrep"`: elenco dei motori inclusi.
  Per ciascuno serve `/licenses/<motore>/` (nome `[a-z0-9-]+`) con almeno un
  file `LICENSE*`, `COPYING*` o `NOTICE*` non vuoto.
- scancode (V-02): in piu' `/licenses/scancode/NOTICE` e almeno un file
  `*.ABOUT` (anche in sottocartelle fino a 5 livelli). Il `NOTICE` dice
  Apache-2.0 per il codice e CC-BY-4.0 per i dati (attribuzione). I componenti
  di terzi hanno licenze anche copyleft, documentate dai `.ABOUT` distribuiti
  nel wheel `scancode_toolkit-32.5.0`: vanno copiati in immagine.

| Motore | Licenza (V-02) | Da copiare in `/licenses/<motore>/` |
| --- | --- | --- |
| syft, osv-scanner, trivy, bandit | Apache-2.0 | `LICENSE`, `NOTICE` se esiste |
| gitleaks | MIT | `LICENSE` |
| scancode | Apache-2.0 + CC-BY-4.0 dati, terzi anche copyleft | `NOTICE`, `*.ABOUT` |
| semgrep (motore) | LGPL-2.1 | `LICENSE` (testo LGPL); le regole del registry non vanno incluse (ADR-0015) |

## Per un plugin (P-01..)
1. `FROM` la base per digest; nella cartella del contesto una `licenses/` con
   `THIRD-PARTY-NOTICES.md` e le cartelle dei motori.
2. `COPY licenses/ /licenses/` (con `chmod -R a=rX` come nella base), eseguito
   prima di `USER`.
3. `LABEL ca.engines="..."` con i motori inclusi.
4. Prendere i testi dalla release fissata, non da memoria; registrare l'esito
   della verifica di licenza nel task.
5. Costruire con `build-image.sh`; l'SBOM esce nella cartella indicata.
