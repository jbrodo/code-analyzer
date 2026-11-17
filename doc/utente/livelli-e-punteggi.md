# Livelli, punteggi e varianti

Decisioni: ADR-0009 (livelli provvisori), ADR-0021 (punteggi, override), ADR-0022 (raggiungibilità e churn), ADR-0024 (feed EPSS e KEV), ADR-0028 (contesto del servizio), D2-10.

## In breve

`scan` calcola per ogni finding **due punteggi**, A e B, e li scrive nel report (`variant_scores`) con i fattori e l'evidenza di ciascuno. Ma **il livello che decide il gate resta quello provvisorio della Fase 1** finché chi controlla la configurazione di scoring non imposta `levels.source: score`. Fino ad allora i punteggi sono in ombra: non cambiano né il livello né l'esito di `gate`.

I livelli provvisori derivano dalla severità dello scanner e dalle policy, senza raggiungibilità: una vulnerabilità non raggiungibile con CVSS alto blocca comunque. Quando il livello da punteggio diventerà attivo molti finding cambieranno livello, una volta sola (alcuni salgono, altri scendono); sarà annunciato nelle note di rilascio, e chi ha un `block_on` o un'eccezione legata a un livello dovrà rivederli.

## Il punteggio

`impatto = 100 · G · P · E · C`, ciascun fattore in `[0,1]`, arrotondato a due decimali prima di confrontarlo con le soglie (`[70,100]` critico, `[40,70)` alto, `[15,40)` medio, `[0,15)` basso). Tutti i valori sono in un file di configurazione di scoring, non nel codice.

| Fattore | Da dove viene |
| --- | --- |
| G, gravità | CVSS (il più recente per versione) per le dipendenze; severità della regola per codice, IaC, qualità, test; policy per le licenze; fissa per segreti e salute |
| P, probabilità | Dipendenze: in KEV 1,0, altrimenti `max(EPSS, 0,01)`. SAST: 0,8 se il risultato viene da una regola di flusso dei dati (taint) del prodotto, altrimenti 0,4. Qualità, architettura e test: percentile di churn dei file. Fissa per IaC, segreti, licenze, salute |
| E, esposizione | Raggiungibilità del codice dagli entrypoint (1,0 / 0,6 / 0,3 / 0,2) e se il servizio è esposto su internet |
| C, criticità | Tier del servizio: 1 → 1,0, 2 → 0,7, 3 → 0,4, assente → 0,7 |

**Dati mancanti.** Un dato mancante non diventa mai un valore favorevole: senza feed EPSS e KEV P vale 0,1; senza storia git completa il churn è ignoto e P vale 0,3; senza grafo E è `ignota` (0,3). Il report lo dichiara nell'evidenza di ogni fattore (`fallback`, `reason`) e con l'avviso `scoring-with-fallbacks`.

## Override

Alzano il livello a un minimo, mai il punteggio: KEV e raggiungibile → critico; licenza vietata in un prodotto distribuito → critico; EPSS ≥ 0,1 e raggiungibile → alto; SAST con percorso confermato in un servizio dichiarato esposto → alto; smell di architettura in un file tra il 10% più modificato → medio; copertura sotto il 50% su codice raggiungibile e molto modificato → medio. Nessun override scatta su un dato assente.

## Come usarlo

```bash
code-analyzer scan . --variant B --scoring-config /percorso/fuori/dal/repo/scoring.json \
  --service-context /percorso/fuori/dal/repo/service.json
```

- `--variant A|B`: la variante attiva. Precedenza: il flag, poi `scoring.variant` di `.code-analyzer.yml` (in una PR, quello del base), poi il file di scoring.
- `--scoring-config FILE` (o `CA_SCORING_CONFIG`): un file di configurazione completo, in JSON (`ca_core/scoring/default.json` è il predefinito e il modello). Non si fonde col predefinito. **Un file dentro la directory analizzata è rifiutato**, anche tramite un collegamento simbolico: lo scoring non si configura dal repository, che altrimenti potrebbe abbassare i propri punteggi. Il report registra `scoring.config_version` (versione e impronta del contenuto).
- `--service-context FILE`: tier ed esposizione, fuori dal repository (`{"version": 1, "tier": 1, "internet_facing": true}`). Senza file vale il blocco `service` di `.code-analyzer.yml`, dichiarazione non verificata (avviso `service-from-repository`); senza nemmeno quello, valori predefiniti.
- `--offline` impedisce la sincronizzazione di EPSS e KEV (usa la cache, anche vecchia, con `feeds-stale`).

Il report registra anche `service_context` (valore e fonte di tier ed esposizione: `catalog`, `repository` o `default`) ed `enrichment` (origine, ora di scaricamento, SHA-256 e identità di ciascuno snapshot): bastano a ricostruire un punteggio.

## Feed EPSS e KEV

Li scarica la CLI, senza il workspace, e li tiene in cache per utente: EPSS dal file giornaliero di FIRST, KEV dal JSON di CISA, con controlli di forma, dimensione e plausibilità. Dopo un giorno si risincronizza. I punteggi EPSS sono generati da Empirical Security e pubblicati da FIRST (EPSS SIG); **FIRST chiede di citare EPSS nei prodotti che lo usano**. Le origini si cambiano solo con `CA_FEEDS_EPSS_URL` e `CA_FEEDS_KEV_URL` (https, senza credenziali), mai dal repository. Nessuna delle due fonti pubblica firme: uno snapshot plausibile ma alterato non si riconosce, con effetto limitato al P di una CVE.

## Limiti dichiarati

- **«Segreto valido esposto» non si applica.** Provare un segreto contro il servizio che lo ha emesso richiede rete, che i plugin non hanno: ogni segreto ha `evidence.validity` `unverified`.
- **Criticità ed esposizione dichiarate, non verificate**, se non vengono da un server (ADR-0028).
- **La Variante B non è definita** per qualità e architettura (ADR-0023 manca): lì coincide con A e il report lo dichiara (`variante-b-non-definita`). Confrontare A e B su quelle categorie non dice nulla.
- **«Percorso confermato» non è un'analisi tra file:** vale solo per i risultati delle regole di flusso dei dati che il prodotto stesso porta, nel perimetro della regola. Il SARIF di semgrep non contiene `codeFlows`.
- **Raggiungibilità prudente:** un solo import calcolato o un file letto in parte rende `ignota` ogni modulo non raggiunto del suo linguaggio; un repository senza entrypoint riconosciuti (una libreria) ha tutto `ignota`, quindi E = 0,3 ovunque e punteggi più bassi di un'applicazione. Le dipendenze transitive e quelle di sviluppo dichiarate da lockfile non sono ancora distinte.
- **Churn** richiede una storia git che copra 90 giorni: con `fetch-depth: 2` il confronto della PR funziona, il churn no.
- I valori numerici predefiniti sono ipotesi da calibrare sui repository pilota (Gate 2).
