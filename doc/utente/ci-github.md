# GitHub: Action, commento e check run

Decisioni: ADR-0027, ADR-0010. Codice: `integrations/github-action/` e `code-analyzer notify`.

**Stato.** Non esiste un'immagine pubblicata né un'Action su un registry (D2-16): l'Action funziona solo dove si costruisce e si firma l'immagine della CLI da sé, come fa il workflow `e2e-action.yml` del progetto. Il workflow non è ancora stato eseguito su GitHub: gli script sono provati con l'immagine vera e un GitHub finto.

## L'Action

Composita (`integrations/github-action/action.yml`). Passi, in quest'ordine:

1. rifiuta `pull_request_target` (vedi sotto);
2. su una PR, trova il commit base (primo genitore del commit di merge) e la baseline;
3. `scan` (con `--pr` su una PR), **senza** `--fail-on`;
4. su un push al branch principale conserva il report come artefatto `code-analyzer-baseline`;
5. carica il SARIF in Code Scanning, anche se un passo precedente è fallito;
6. su una PR, `notify`;
7. `gate`, per ultimo: l'esito del job è il suo.

```yaml
permissions:
  contents: read
  actions: read            # cercare la baseline tra gli artefatti
  security-events: write   # SARIF
  pull-requests: write     # commento
  checks: write            # check run
steps:
  - uses: actions/checkout@<hash>
    with: { fetch-depth: 2, persist-credentials: false }
  - uses: ./integrations/github-action
    with:
      image: <immagine della CLI>
      public-key: <chiave cosign, fuori dal repository>
      fail-on: critico,alto
```

Ingressi, permessi e comportamento sulle PR da fork: `integrations/github-action/README.md`. Una scelta da conoscere: la soglia si fissa con `fail-on` perché `.code-analyzer.yml` lo può cambiare chi modifica il branch.

**Baseline.** In ordine: l'artefatto `code-analyzer-baseline` dell'esecuzione `push` riuscita sul branch principale con il commit base; altrimenti la scansione del base nello stesso job (`base-scan: true`); altrimenti avviso e gate su tutti i finding. La cache della CI non si usa: una PR potrebbe scriverci una baseline falsa.

## `notify`

```bash
GITHUB_TOKEN=… code-analyzer notify --provider github --report code-analyzer.report.json
```

Scrive **un** commento per PR, riconosciuto da un marcatore e aggiornato a ogni esecuzione, e una check run sul commit di testa. Il commento elenca i finding nuovi, con i conteggi di esistenti e risolti; senza baseline valida lo dice e mostra quelli che bloccano. Un gruppo di correlazione (stesso problema confermato da più strumenti) compare una volta. Il numero di finding è limitato (`--max-findings`, predefinito 20), così come le annotazioni (`--max-annotations`, 50).

- Il token viene solo da `GITHUB_TOKEN`, mai da un'opzione, e non compare in nessuna uscita.
- `notify` non decide: l'esito è di `gate`. La conclusione della check run viene dalla stessa regola.
- I testi del report vengono dal repository analizzato e sono trattati come non fidati: caratteri di controllo e bidirezionali tolti, punteggiatura Markdown neutralizzata, menzioni (`@`), riferimenti (`#n`), indirizzi e hash interrotti da un carattere invisibile, nessun collegamento costruito dai testi.
- `--no-comment`, `--no-check-run` per usarne uno solo.

**Exit.** 0 fatto o saltato con avviso; 2 errore (solo il codice, mai il testo della risposta). Mai 1.

## PR da fork e `pull_request_target`

Su una PR da fork il token è di sola lettura: `scan` e `gate` girano, il SARIF non si carica (avviso) e `notify` scrive il contenuto del commento nel riepilogo del job, con exit 0. Il commento sulle PR da fork richiederebbe due flussi, uno senza privilegi e uno privilegiato: non c'è in Fase 2.

`pull_request_target` **non è supportato**: darebbe a contenuto scelto da chi apre la PR un token con permessi di scrittura. L'Action si ferma con un errore.

## Limiti dichiarati

- Su `pull_request` il flusso è quello della PR: chi la apre può togliere il gate modificandolo. Per imporlo servono i meccanismi di GitHub per eseguire un flusso da un ramo protetto.
- I limiti di dimensione di commenti, check run e annotazioni, i permessi esatti e il fatto che la neutralizzazione di `@` e `#` basti sui servizi di GitHub **non sono verificati alla fonte**: sono quelli noti a memoria. Il caricamento del SARIF richiede Code Scanning attivo sul repository.
- Non ci sono ancora gli ingressi `variant` e `server-url`: la CLI non ha le varianti di punteggio né l'invio al server (vedi `livelli-e-punteggi.md`).
