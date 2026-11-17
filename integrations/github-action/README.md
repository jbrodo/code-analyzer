# GitHub Action di Code Analyzer

Action composita (ADR-0027). Passi, in quest'ordine: controllo dell'evento, baseline (su una PR), `scan`, conservazione del report (push sul branch principale), caricamento del SARIF, `notify` (su una PR), `gate`. L'esito del job è quello di `gate`.

## Uso

```yaml
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  actions: read            # cercare la baseline tra gli artefatti
  security-events: write   # SARIF
  pull-requests: write     # commento
  checks: write            # check run

jobs:
  analyze:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<hash-del-commit>
        with:
          fetch-depth: 2
          persist-credentials: false
      - uses: ./integrations/github-action
        with:
          image: <nome:tag o nome@digest>
          public-key: <percorso sul runner della chiave cosign>
```

| Ingresso | Predefinito | Significato |
| --- | --- | --- |
| `image` | nessuno | Immagine della CLI. Non c'è un registry pubblico predefinito (D2-16). |
| `public-key` | nessuno | Chiave pubblica cosign dei plugin, fuori dal repository analizzato. |
| `fail-on` | vuoto | Livelli bloccanti per `gate`; vuoto usa la configurazione. |
| `sarif`, `comment`, `check-run` | `true` | Interruttori dei tre passi. |
| `base-scan` | `true` | Senza il report del base tra gli artefatti, analizza il base nello stesso job. |
| `network` | vuoto | Rete dei container; `host` col registry di prova su loopback. |

## Cosa fa su una PR

- Il commit analizzato è il commit di merge; il base è il suo primo genitore. Serve `fetch-depth: 2`.
- Baseline, in ordine: artefatto `code-analyzer-baseline` dell'esecuzione `push` riuscita sul branch principale con il commit base; altrimenti scansione del base in un clone separato; altrimenti avviso e gate su tutti i finding. La cache della CI non si usa.
- Un push sul branch principale conserva il report come artefatto `code-analyzer-baseline` (30 giorni): così le PR trovano la baseline.

## Permessi e PR da fork

Quelli dell'esempio sono i minimi. Su una PR da fork il token è di sola lettura: `scan` e `gate` girano, il SARIF non si carica (avviso), `notify` scrive il commento nel riepilogo del job. `pull_request_target` non è supportato: l'Action si ferma con un errore.

Su `pull_request` il file del flusso è quello della PR: chi la apre può togliere il gate modificandolo. Per imporlo servono i meccanismi del provider per eseguire un flusso da un ramo protetto.

## Limiti

- Ingressi `variant` e `server-url` non ci sono: la CLI non ha ancora né le varianti di punteggio né `upload`.
- Non provata con l'immagine reale su un runner: i test usano un `docker` e un `gh` finti (N-05).
- La scansione del base su un clone locale di un checkout superficiale può dare una storia parziale a gitleaks.
