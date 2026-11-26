# ADR-0023: Variante B, smell e debito architetturale

- Stato: Proposto. Scelta tecnica su una decisione già presa (D2-11, 2026-11-10). I valori numerici sono ipotesi da calibrare in X-02 e X-06. Le definizioni sono ricostruite dalle pubblicazioni di §19 senza averle sotto mano: ogni punto segnato **da confrontare** va verificato sul testo prima di `Accettato`. Passa ad `Accettato` con quel confronto, la distribuzione di benchmark di K-06 e le prove di K-07..K-10 e G-13
- Data: 2026-11-26
- Decisione umana richiesta: no per la struttura (D2-11 è decisa). Sì per la conferma delle definizioni segnate **da confrontare**, che spetta a chi conosce le pubblicazioni
- Riferimenti: §6, §6.2, §16 regola 3, §19; ADR-0003, 0014, 0020, 0021, 0022, 0026, 0028; D2-11; X-02 in `doc/verifiche/gate-2.md`

## Contesto

§6.2 definisce la Variante B per le categorie `quality` e `architecture` a partire da cinque pubblicazioni: indice di intensità dei code smell (MTD 2015), severità degli architectural smell per tipo e dimensione (ICSME 2016, ICSAW 2017), change-proneness da churn e violazioni (EASE 2017), criticità come PageRank (ECSA 2019), Architectural Debt Index per modulo (SEAA 2018). Non dice come si costruisce la distribuzione di benchmark su cui si normalizza l'intensità, né cosa fare per le regole senza metrica, per i dati mancanti o per la normalizzazione di PageRank.

D2-11 ha deciso: un corpus fisso di repository pubblici con commit fissati, i tre pilota inclusi, una decina in tutto; la distribuzione come dato versionato nel pacchetto, ricalcolata solo con un'azione esplicita; l'ADI calcolato e servito dall'API, il trend in Fase 4.

Fino a oggi B coincide con A su `quality` e `architecture` (ADR-0021, `variante-b-non-definita`). X-02 lo ha misurato: A e B sono identiche su tutti e cinque i repository, e G2.b non può distinguerle.

Cosa c'è già:

- ruff ed eslint estraggono valore e soglia delle regole con una metrica in `properties.metric` (ADR-0026): `C901`, `PLR0911`, `PLR0912`, `PLR0913`, `PLR0915`; `complexity`, `max-depth`, `max-lines-per-function`, `max-params`. Una regola, una metrica.
- `ca-graph` trova Cyclic, Hub-Like e Unstable Dependency con la dimensione nell'evidenza, e calcola PageRank per modulo (ADR-0020).
- Il churn per file e il suo percentile ci sono (ADR-0022, `ChurnIndex`). La densità di violazioni no (G-11 l'ha lasciata aperta): il grafo non conosce le righe dei file.

## Decisione

### Ambito

- B si applica solo a `quality` e `architecture`. Per le altre categorie B è A, come in §6.2. E è sempre quello di ADR-0022.
- **Due motori separati** (§6.2): `scoring/variant_b/code_smell.py` per G dei finding `quality`, `scoring/variant_b/arch_smell.py` per G dei finding `architecture`. Nessuno dei due legge i risultati dell'altro.
- Ogni valore numerico sta in un blocco `variant_b` della configurazione di scoring (C-03), mai nel codice. Il blocco è facoltativo nello schema, come `dependency_cvss_floor`: un file senza il blocco dà B uguale ad A su quelle categorie, con `evidence.fallback: variante-b-non-configurata`. Il file predefinito del pacchetto lo ha sempre.

### Distribuzione di benchmark (K-06)

- **Corpus** (approvato dall'utente il 2026-11-26). I tre pilota della Fase 1 (`saleor/saleor`, `fastapi/full-stack-fastapi-template`, `excalidraw/excalidraw`) più sette repository pubblici: `pallets/flask`, `encode/httpx`, `scrapy/scrapy`, `django/django` (Python); `expressjs/express` (JavaScript); `vuejs/core`, `vitejs/vite` (TypeScript). Licenze permissive (BSD-3, MIT), tutti attivi a novembre 2026, dimensioni da piccola a molto grande. Ciascuno all'ultimo tag di rilascio stabile al momento della raccolta; i commit stanno nel file di benchmark. Scartati: un repository AGPL (da non mettere in discussione con D-0013), e repository che pesano quasi solo per storia e risorse. I due repository dell'utente di X-01 **non** entrano: sono riservati, e il benchmark esce nel pacchetto.
- **Peso uguale per repository.** La distribuzione è la miscela a pesi uguali delle distribuzioni dei singoli repository: ogni osservazione vale `1 / (osservazioni del suo repository)`. Senza, django da solo descriverebbe il benchmark. Un repository senza osservazioni per una metrica (per esempio nessun JavaScript) non entra in quella metrica. **Da confermare** con le pubblicazioni, che normalizzano su un corpus diverso.
- **Modalità di raccolta.** L'adattatore di ruff e quello di eslint accettano in `/inputs/config.json` la chiave `benchmark: true`. Con essa le soglie delle regole con metrica scendono al minimo, così ogni funzione produce un risultato con il suo valore. Il file lo genera l'host (ADR-0014): il repository analizzato non può chiederlo. Nelle scansioni normali la chiave è assente.
- **Procedura.** Uno script in `scripts/benchmark/` clona il corpus ai commit fissati, esegue i plugin firmati del registry locale in modalità benchmark, scarta i file di test (percorsi di ADR-0022) e scrive la distribuzione. Le stesse scansioni, in modo normale, danno le dimensioni degli architectural smell. Ricalcolo solo con lo script: mai durante una scansione.
- **Dato.** `ca_core/scoring/benchmark.json` con contratto `scoring-benchmark` (`schemas/scoring-benchmark.schema.json`, ADR-0003): `version`, corpus con URL e commit, versione dei motori, e per ogni regola con metrica e per ogni tipo e ambito di architectural smell la funzione di ripartizione empirica su 101 quantili (0, 1, …, 100) più il numero di osservazioni. Nessun dato del codice analizzato oltre ai numeri.
- **Tracciabilità.** Il report registra in `scoring.benchmark_version` la `version` e l'impronta del file (`"<version>+<primi 12 caratteri>"`), come `config_version`. Se la versione del motore che ha prodotto il finding è diversa da quella del benchmark il calcolo procede e l'evidenza lo dice (`benchmark-motore-diverso`): la forma della distribuzione cambia poco tra versioni minori, e rifiutare il calcolo renderebbe B indisponibile a ogni aggiornamento.

### G dei code smell (`quality`)

Indice di intensità di MTD 2015, nella forma che segue. Sia `F` la funzione di ripartizione empirica della metrica nel benchmark (interpolata linearmente tra i quantili), `v` il valore del finding e `t` la soglia della regola, entrambi da `properties.metric`:

```
intensità = (F(v) − F(t)) / (1 − F(t))        tagliata in [0, 1]
G = max(g_floor, intensità)
```

- È «quanto il valore supera la soglia», misurato nello spazio dei quantili del benchmark: 0 appena sopra la soglia, 1 al massimo osservato. Con `F(t) = 1` (soglia oltre ogni valore del benchmark) G vale 1. `g_floor` (predefinito 0,1) impedisce che un finding reale abbia G zero.
- Si usa la soglia del finding, non quella della configurazione: se le soglie delle regole cambiano (ADR-0026) l'indice resta coerente con ciò che la regola ha visto.
- Regola con più metriche: media delle intensità. Oggi nessuna ne ha più di una.
- **Da confrontare.** MTD 2015 classifica l'intensità in livelli discreti con soglie ai quantili del benchmark; questa è una forma continua della stessa idea. Se il testo prescrive i livelli discreti, la configurazione può aggiungere la tabella dei livelli senza cambiare la struttura.
- **Regole senza metrica** (ruff `F` e `B`, le regole di eslint senza metrica): non sono code smell nel senso di MTD 2015. G è quello di A (mappa della severità), con `evidence.fallback: regola-senza-metrica`. Non si inventa un'intensità.
- **Metrica non estratta** (messaggio che non corrisponde, ADR-0026) o **regola assente dal benchmark**: G di A, con `metrica-assente` o `benchmark-assente`.

### G degli architectural smell (`architecture`)

```
G = peso(tipo) · F_dim(tipo, ambito)(dimensione)
```

- `peso(tipo)` in configurazione. Predefiniti, ipotesi: Cyclic Dependency 1,0; Hub-Like Dependency 0,8; Unstable Dependency 0,6.
- `dimensione` è il numero di componenti coinvolti, dall'evidenza di `ca-graph` (ADR-0020): per Cyclic Dependency `size`, i membri del ciclo; per Unstable Dependency `size`, il pacchetto più quelli meno stabili da cui dipende; per Hub-Like `fan_in + fan_out`, i moduli collegati all'hub. Per Hub-Like `size` vale sempre 1 (l'evidenza conta solo l'hub), e userlo darebbe una dimensione costante. `F_dim` è la ripartizione empirica delle dimensioni di quel tipo e ambito (modulo o pacchetto) nel benchmark, con lo stesso `g_floor` di sotto.
- Tipo o ambito assente dal benchmark: G di A, con `benchmark-assente`.
- **Da confrontare.** I pesi per tipo e la definizione di dimensione per Hub-Like e Unstable Dependency vanno confrontati con ICSME 2016 e ICSAW 2017. ADR-0020 dice già che le definizioni degli smell sono trascritte a memoria.

### P: churn e densità di violazioni

Da EASE 2017: le violazioni di regole di codifica, insieme al churn, predicono la change-proneness.

```
P = max(p_floor, w_churn · pct_churn(file) + w_dens · pct_dens(file))     con w_churn + w_dens = 1
```

- `pct_churn` è il percentile di ADR-0022 (`ChurnIndex`).
- `pct_dens` è lo stesso percentile calcolato sulla **densità di violazioni**: finding `quality` del file per mille righe. I finding sono quelli della scansione dopo la normalizzazione e la deduplicazione, prima di eccezioni e baseline (una violazione accettata resta una violazione). La popolazione sono i moduli non di test del grafo; un modulo senza violazioni ha densità 0.
- Per le righe il contratto `graph` passa a 1.1 con `Module.lines` (righe fisiche, facoltativo): lo conta l'estrattore, che ha già il file in memoria. Chiude la parte aperta di G-11.
- Finding su più file (architettura a livello di pacchetto): il massimo tra i membri, come in A.
- Predefiniti, ipotesi: `w_churn` 0,5, `w_dens` 0,5, `p_floor` 0,1. Churn ignoto: si usa `p.churn.unknown` di A come valore del suo termine; densità ignota (file fuori dal grafo o senza `lines`): `variant_b.p.density_unknown`, predefinito 0,3. Entrambi dichiarati nell'evidenza.
- **Da confrontare.** EASE 2017 usa un modello predittivo, non una media pesata; la combinazione lineare è una scelta di questo ADR per restare spiegabile nella UI.

### C: PageRank

- C è la posizione del PageRank del modulo tra i moduli non di test del grafo: la quota di moduli con PageRank **minore o uguale**. Il modulo più critico vale 1, il meno critico `1/n`, poi `max(c_floor, …)` con `c_floor` 0,1.
- Non è il valore `metrics.pagerank` del grafo (grezzo diviso per il massimo): sui grafi reali quella distribuzione è molto asimmetrica, e quasi tutti i moduli avrebbero C vicino a zero e un punteggio di B trascurabile rispetto ad A. Il valore del grafo resta com'è per l'ADI e la UI. È la scelta che ADR-0020 lasciava a questo ADR.
- Finding su più moduli: il massimo. File fuori dal grafo o grafo assente: C di A (tier del servizio, ADR-0028), con `grafo-assente`.
- In B il tier del servizio non entra nei finding `quality` e `architecture`: §6.2 sostituisce C. La UI mostra comunque il tier tra i dati del repository.

### Architectural Debt Index (G-13)

```
ADI(m) = Σ G_B(s)     su ogni architectural smell s che include il modulo m
```

- Calcolato sull'host dopo gli smell, scritto nel grafo dell'artefatto (`code-analyzer.graph.json`) come `metrics.adi` del modulo, con due decimali. Sul server si serve con `GET /v1/repositories/{id}/graph` (B-11), che già restituisce il grafo: nessuna route né colonna nuova. Per i pacchetti, la somma sui moduli.
- Non è un fattore del punteggio e non decide livelli. Nessun trend né grafico nella UI (Fase 4, D2-15).
- **Da confrontare.** SEAA 2018 definisce l'ADI con termini che qui mancano (per esempio la storia dello smell o una normalizzazione per dimensione del componente). Questa è la forma minima che si può calcolare con i dati di oggi.

### Spiegazione e limiti nella UI

- L'evidenza di ogni fattore di B porta i numeri che lo producono: per G valore, soglia, `F(v)`, `F(t)` e versione del benchmark; per P i due percentili e i pesi; per C il PageRank grezzo e la posizione. La UI (U-04) li mostra accanto al punteggio con pesi e soglie (§6.2).
- I testi di UI e documentazione non presentano gli architectural smell come predittori di bug di concorrenza (§6.2).

### Livelli

Stesse soglie e stessi override di ADR-0021. L'override «architectural smell in un hotspot» vale per entrambe le varianti. In ombra (D2-10) nulla cambia per il gate.

## Opzioni scartate

- **Benchmark dai repository analizzati, ricalcolato a ogni scansione**: lo stesso finding cambierebbe punteggio con il resto del codice, e il benchmark dipenderebbe da chi scansiona. D2-11 lo esclude.
- **Soglie fisse per l'intensità invece dei quantili** (per esempio complessità 20 = 1): è la Variante A sotto un altro nome, e §6.2 chiede i quantili.
- **Inventare una metrica per le regole senza metrica** (per esempio dal numero di occorrenze): non c'è base nelle pubblicazioni.
- **C come PageRank diviso per il massimo**: vedi sopra.
- **ADI in una tabella del server**: duplica il grafo che il server già conserva, e senza trend non serve una serie.
- **Includere i repository dell'utente nel corpus**: il benchmark si distribuisce nel pacchetto, e quei repository sono riservati.

## Conseguenze

- **Contratti** (regola 1 di `AGENTS.md`): `graph` 1.1 con `Module.lines` e `ModuleMetrics.adi`; `scoring-config` con il blocco facoltativo `variant_b`; `scan-report` con `scoring.benchmark_version` facoltativo; nuovo `scoring-benchmark`. Tutti aggiunte compatibili, con schemi e test di contratto.
- **Task.** K-06 costruisce corpus, modalità benchmark degli adattatori, script e `benchmark.json`. K-07 e K-08 i due motori di G, K-09 P con la densità (e `lines` nell'estrattore, che chiede di ricostruire l'immagine di `ca-graph`), K-10 C, G-13 l'ADI. `VariantBModel` smette di dichiarare `variante-b-non-definita`.
- **X-02 va ripetuta** con B definita, e solo allora X-04 e X-06 possono confrontare A e B. X-02 ha già mostrato che le soglie dei livelli vanno ritarate per A; per B lo stesso vale a maggior ragione, perché G e C di B stanno spesso sotto quelli di A.
- La modalità benchmark aggiunge una chiave a `/inputs/config.json` dei due plugin: va nel test di contratto degli adattatori e in S-03 (il repository non deve poterla attivare).
- Il benchmark è un dato del prodotto: ogni aggiornamento di ruff o eslint che cambia il calcolo delle metriche chiede di rifarlo, con una nuova `version`.
