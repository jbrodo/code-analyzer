# ADR-0021: Scoring Variante A, ombra, livelli e override

- Stato: Proposto. Scelta tecnica. I valori numerici predefiniti sono ipotesi da calibrare in X-02 (Gate 2); la struttura non dipende da essi. Passa ad `Accettato` con le prove di K-04, K-05, K-14 e della tabella di regressione di F-05
- Data: 2026-11-17
- Decisione umana richiesta: no. D2-10 (decisa il 2026-11-10) fissa quale livello decide il gate; qui si dice come
- Riferimenti: §6, §6.1, §6.3, §8, §9.1, §16 regola 3; ADR-0009, 0012, 0013, 0014, 0018, 0022, 0025, 0026, 0028; lacune 4, 5, 6 e 7 del piano

## Contesto

§6 definisce `Impatto = 100·G·P·E·C` e le soglie dei livelli, ma lascia aperte cose che il codice deve decidere: G e P di ogni categoria diversa da CVE e SAST (segreti, licenze, IaC, test, salute, qualità); cosa fare quando manca un dato (CVSS v4, feed EPSS e KEV, churn); le soglie, che §6.3 mette in `scoring/levels.py` mentre §16 regola 3 le vuole in configurazione; cosa significa ciascun override; chi può cambiare pesi e soglie; dove stanno le due varianti nel report; con quale precedenza si sceglie la variante. D2-10 ha deciso che fino al Gate 2 il gate resta sui livelli provvisori di ADR-0009 e che A e B si calcolano entrambe in ombra.

Questo ADR definisce la Variante A e il quadro comune. La Variante B per qualità e architettura è di ADR-0023 (D2-11): qui si dice solo cosa fa finché non esiste.

## Decisione

### Formula, arrotondamento, livelli

- `impatto = 100 · G · P · E · C`, con ciascun fattore in `[0,1]`. Un fattore fuori intervallo è un errore di configurazione, mai un valore tagliato in silenzio.
- Il punteggio si **arrotonda a due decimali prima** di confrontarlo con le soglie (metà verso l'alto): il numero che si mostra e il livello che ne segue non possono contraddirsi.
- Intervalli semiaperti: critico `[70,100]`, alto `[40,70)`, medio `[15,40)`, basso `[0,15)`. Un punteggio di 69,99 è alto, 70 è critico. Le soglie stanno in configurazione.
- Il livello da punteggio può essere alzato da un override (sotto), mai abbassato.

### Configurazione di scoring

Pesi, soglie, mappe di severità, valori dei fattori, override e parametri della Variante B stanno in **un file di configurazione di scoring**, mai nel codice di `scoring/` (regola 3).

- Il contratto è `scoring-config` (C-03, `schemas/scoring-config.schema.json`); ha una `version` intera. Il file predefinito sta nel pacchetto `ca-core` e supera lo schema.
- **Chi lo cambia.** Il tenant, sul server (ADR-0018), e chi lancia la CLI senza server con `--scoring-config FILE` o `CA_SCORING_CONFIG`, con un file fuori dal repository analizzato (come la baseline di ADR-0025). **Mai `.code-analyzer.yml`**: è modificabile da chi modifica il branch (ADR-0014), e con esso si abbasserebbero i punteggi del proprio codice. Da `.code-analyzer.yml` si legge solo la scelta della variante (`scoring.variant`).
- Un file di sovrascrittura è **un file completo**, validato per intero: niente fusione parziale con il predefinito, che renderebbe incerto quale valore vale.
- Il report registra `scoring.config_version` (la `version` più l'impronta SHA-256 del file effettivo, `"<version>+<primi 12 caratteri>"`), così due scansioni sono confrontabili solo se la configurazione è la stessa. Una PR usa la stessa configurazione del base per costruzione: non viene dal repository.

### G e P per categoria (Variante A)

Valori predefiniti; ogni cifra è un campo del file di configurazione.

| Categoria | G | P |
| --- | --- | --- |
| `dependency` | Punteggio base CVSS diviso 10: v4 se c'è, altrimenti il v3.1 o il v3.0 più recente, altrimenti il v2. La versione usata è nell'evidenza. Nessun CVSS: **0,75** (coerente con `alto` di ADR-0009, e dichiarato) | In KEV: 1,0. Altrimenti `max(epss, 0,01)`. Senza snapshot EPSS e KEV (scansione offline senza feed): **0,1**, dichiarato nell'evidenza come `feed-assente` |
| `sast` | Mappa della severità della regola: critical 1,0; high o SARIF `error` 0,75; medium o `warning` 0,5; low o `note` 0,25; senza severità 0,5 | 0,8 se il percorso è confermato (sotto), altrimenti 0,4 |
| `iac` | Come `sast` | 0,5 |
| `secret` | 0,75 (ADR-0012: `alto`, validità non verificata) | 0,8: il valore è nel repository; la validità non si conosce e non si afferma |
| `license` | Vietata in prodotto distribuito 1,0; vietata non distribuito 0,75; da approvare 0,6; ignota 0,5; obbligo di attribuzione 0,3 (oggi non rilevabile, ADR-0013) | 1,0: un obbligo di licenza non è una probabilità |
| `quality`, `architecture` (finché non c'è ADR-0023), `test` | Mappa della severità come `sast`. `test` (copertura bassa): severità del plugin (ADR-0026) | Percentile di churn del file (ADR-0022), con minimo **0,1**. Churn ignoto (storia superficiale o assente): **0,3** |
| `health` | 0,5 (`medio` di ADR-0009) | 1,0 |

- **Percorso confermato (SAST).** Non c'è analisi del flusso dei dati nel prodotto. Si dice «confermato» quando il risultato SARIF dello strumento porta almeno un `codeFlows` con più di una posizione (le regole di tipo taint di semgrep lo emettono). Se uno strumento non lo emette il percorso non è confermato: mai dedotto. K-12 verifica che semgrep lo produca davvero con le regole del prodotto.
- **E** secondo ADR-0022 (stati di raggiungibilità, esposizione, valori 1,0, 0,6, 0,3, 0,2) e **C** secondo ADR-0028 (tier 1: 1,0; 2: 0,7; 3: 0,4; assente: 0,7).
- **Il dato mancante non diventa un valore favorevole.** Ogni fallback sopra è dichiarato nell'evidenza del fattore (`fallback`) e il report conta i finding calcolati con un fallback. Il punteggio resta calcolabile, ma una scansione senza feed o senza churn non può passare per una scansione con i dati.

### Override di §6.3

Un override **alza il livello a un minimo**, non cambia il punteggio, e il finding porta `level_source: override` e il nome dell'override nell'evidenza. Le soglie degli override stanno in configurazione.

| Livello minimo | Override | Definizione operativa |
| --- | --- | --- |
| critico | CVE in KEV e raggiungibile | In KEV (snapshot di ADR-0024) **e** stato di raggiungibilità `raggiungibile` (ADR-0022). Con `ignota` non scatta: l'override affermerebbe ciò che il grafo non prova |
| critico | Segreto valido esposto | **Non si applica.** Provarlo richiede rete verso il servizio emittente, vietata ai plugin (ADR-0006, ADR-0012): ogni segreto ha `evidence.validity` `unverified`. Il report non lo nomina come applicato |
| critico | Licenza vietata in prodotto distribuito | Esito della policy di ADR-0013 con `distributed_product: true` (già così oggi) |
| alto | CVE con EPSS ≥ 0,1 raggiungibile | EPSS dello snapshot non inferiore a 0,1 e `raggiungibile` |
| alto | SAST con percorso confermato in servizio esposto | Percorso confermato (sopra) e `internet_facing` vero, con fonte `catalog` o `repository` (non `default`) |
| medio | Architectural smell in un hotspot | Un finding `architecture` il cui file ha churn al percentile ≥ 90 (**hotspot**; parametro in configurazione). Senza churn non scatta |
| medio | Copertura < 50% su codice critico modificato spesso | Un finding `test` su un file raggiungibile con churn al percentile ≥ 90. «Codice critico» è quindi «raggiungibile da un entrypoint», non un giudizio sul dominio. La soglia del 50% è quella del plugin `coverage` (ADR-0026) |

### Dove stanno A e B

- Nel report, per ogni finding, `variant_scores`: i punteggi di A e di B, ciascuno con fattori e loro evidenza e il livello da punteggio (contratto di C-01). In `scan-report`, la sezione `scoring` dice la variante attiva, la versione di configurazione e `shadow`.
- Sul server, in `finding_occurrences` (ADR-0018): colonne `a_*` e `b_*`, accanto al livello provvisorio con la sua origine.
- Le due varianti si calcolano **sempre**, qualunque cosa decida il gate.

### Quale livello decide il gate (D2-10)

- La configurazione di scoring ha `levels.source`: `provisional` (predefinito) o `score`. Con `provisional` il livello del finding e il gate sono quelli di ADR-0009, e A e B stanno solo in `variant_scores`. Con `score` il livello è quello della variante attiva, con gli override.
- Passare a `score` è l'atto del Gate 2 e lo fa chi controlla la configurazione di scoring, non il repository. Cambia i livelli una volta sola, e la documentazione utente lo annuncia (L-05).
- Con `levels.source: provisional` il report resta identico a quello della Fase 1 nei livelli e nell'esito del gate.

### Precedenza della variante

Quale variante diventa «attiva» quando `levels.source` è `score`:

1. `--variant A|B` sulla riga di comando;
2. `scoring.variant` della configurazione effettiva (in una PR, quella del base: ADR-0025);
3. `variant` del file di configurazione di scoring (predefinito `A`).

In ombra la scelta non cambia nulla: entrambe sono calcolate e il report registra quale sarebbe l'attiva.

### Variante B finché ADR-0023 non c'è

Per `quality` e `architecture` la Variante B non ha ancora una definizione (D2-11). Fino ad allora B **coincide con A** su quelle categorie e il report lo dichiara (`evidence.fallback: variante-b-non-definita`): confrontare A e B su di esse non dice nulla, e X-02 non deve contarle come prova.

### Ordinamento

L'elenco si ordina per livello attivo, poi punteggio decrescente, poi categoria e fingerprint: deterministico, indipendente dall'ordine dei plugin.

## Casi attesi (tabella di regressione, F-05)

| Caso | G | P | E | C | Punteggio | Livello |
| --- | --- | --- | --- | --- | --- | --- |
| CVE CVSS 9,8, EPSS 0,5, raggiungibile, esposto, tier 1 | 0,98 | 0,5 | 1,0 | 1,0 | 49,00 | alto |
| Lo stesso in KEV | 0,98 | 1,0 | 1,0 | 1,0 | 98,00 | critico |
| Lo stesso in KEV, raggiungibilità ignota | 0,98 | 1,0 | 0,3 | 1,0 | 29,40 | medio (l'override KEV non scatta: la raggiungibilità è ignota) |
| SAST medium, percorso non confermato, raggiungibile, interno, tier 2 | 0,5 | 0,4 | 0,6 | 0,7 | 8,40 | basso |
| Segreto, esposto, tier 1 | 0,75 | 0,8 | 1,0 | 1,0 | 60,00 | alto |
| Licenza vietata distribuita, interna, tier 3 | 1,0 | 1,0 | 0,6 | 0,4 | 24,00 | medio, alzato a critico dall'override |
| Punteggio 69,99 / 70,00 | | | | | | alto / critico |

## Opzioni scartate

- **Soglie e valori nel codice**, come in §6.3: contraddice la regola 3 e impedisce la calibrazione di X-02.
- **Configurazione di scoring in `.code-analyzer.yml`**: chi modifica il branch abbasserebbe i propri punteggi (ADR-0014).
- **Fusione parziale del file del tenant con il predefinito**: rende ambiguo quale valore vale e quale versione è stata usata.
- **Override che cambia il punteggio**: nasconde il motivo del livello. Il punteggio resta quello calcolato e l'override è un'etichetta separata e visibile.
- **Fallback favorevole al dato mancante** (EPSS 0,01 senza feed): premierebbe le scansioni senza dati.

## Conseguenze

- C-03 scrive lo schema e il file predefinito da questa tabella; K-04, K-05, K-11, K-12, K-13 e K-14 la realizzano; L-02 aggiunge `--variant`, `--scoring-config` e i punteggi in uscita.
- I valori numerici sono ipotesi: X-02 li confronta con i repository pilota e possono cambiare senza modificare codice, solo la configurazione e la sua versione.
- Un repository senza entrypoint riconosciuti ha E = 0,3 ovunque (ADR-0022): i suoi punteggi sono più bassi.
- Il valore 0,1 di P senza feed e i minimi di churn sono scelte di questo ADR, non di §6: vanno guardati in X-02.
- "Percorso confermato" dipende dalla capacità degli strumenti di emettere `codeFlows`; dove non c'è, l'override SAST non scatta mai.
- ADR-0009 resta valido per i livelli provvisori fino al Gate 2; poi la sua tabella resta come origine `tool_severity` per i finding senza punteggio.
