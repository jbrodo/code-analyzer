# Componente GitLab CI di Code Analyzer

`templates/code-analyzer.yml` (ADR-0027, §12.2). Un job `code-analyzer` che esegue, in ordine: controllo del daemon, scansione, SBOM, `export` verso i report nativi e `gate`. Il job fallisce secondo il gate; gli artefatti si conservano comunque (`when: always`).

## Uso

```yaml
include:
  - component: <host>/<gruppo>/<progetto>/code-analyzer@<versione>
    inputs:
      image: <nome:tag o nome@digest>
      public_key: <percorso della chiave cosign, visibile al daemon>
      tags: [docker-socket]
```

| Ingresso | Predefinito | Significato |
| --- | --- | --- |
| `image` | nessuno | Immagine della CLI. Nessun registry predefinito (D2-16). |
| `public_key` | nessuno | Chiave pubblica cosign dei plugin, fuori dal repository analizzato. |
| `job_image` | `docker:28.5.2-cli@sha256:…` | Immagine del job, con il client Docker. Se manca `git`, il job lo installa con `apk`. |
| `stage` | `test` | |
| `fail_on` | vuoto | Livelli bloccanti per `gate`; vuoto usa la configurazione. |
| `sbom` | `true` | Produce anche il report `cyclonedx`. |
| `offline`, `network` | `false`, vuoto | Come nell'Action. |
| `git_depth` | `200` | Storia da scaricare: in una merge request il commit base deve esserci. |
| `tags` | `[]` | Tag del runner con il daemon. |

## Requisiti

- Un runner con un daemon di container raggiungibile dal job, con **la directory di build allo stesso percorso per il job e per il daemon** (per esempio `/var/run/docker.sock` e `/builds` montati alla pari). La CLI lo prova prima di avviare i plugin e, se non coincidono, esce con 2. `DOCKER_HOST` remoto non è supportato (ADR-0004): l'esempio con il solo servizio Docker-in-Docker non basta, perché il daemon vedrebbe un'altra directory.
- Il socket dà al job lo stesso potere di `root` sull'host: solo su runner effimeri o fidati (README dell'immagine CLI).

## Cosa produce

| Report GitLab | Contenuto |
| --- | --- |
| `sast` | finding `sast` |
| `dependency_scanning` | finding `dependency` (serve percorso e versione dal purl) |
| `codequality` | finding `quality` (serve percorso e riga) |
| `cyclonedx` | l'SBOM del prodotto riportato dalla 1.7 alla 1.6, che GitLab accetta (1.4, 1.5 o 1.6); il report `cyclonedx` è del livello Ultimate |

Segreti, licenze, IaC, architettura, test e salute non hanno posto in questi formati: `export` dice quanti sono e restano in `code-analyzer.report.json` e nel SARIF, conservati come artefatti. I finding senza il dato che il formato richiede non si esportano e si contano; non si inventa mai un valore.

## Merge request e baseline

In una merge request il componente analizza il commit base (`CI_MERGE_REQUEST_DIFF_BASE_SHA`) in una copia a parte, con la sua configurazione, e lo usa come baseline per `scan --pr` (ADR-0025). Senza baseline il gate valuta tutti i finding, con un avviso. **Nessun commento sulla merge request**: il token del job non può scriverlo (ADR-0027).

## Limiti

- **Mai eseguito su GitLab.** Non c'è un'istanza (D2-12): il componente è provato solo come struttura e con uno script eseguito con `docker` finto. Non è stato controllato con il linter CI di GitLab.
- La baseline da artefatto del branch principale (consentita da ADR-0027 quando il commit coincide) non c'è: si usa sempre la scansione del base.
- Pipeline di merge request da fork e "merged results pipelines" non provate.
