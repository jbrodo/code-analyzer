# ADR-0020: `ca-graph`: isolamento, schema del grafo, smell

- Stato: Proposto. Scelta tecnica. Passa ad `Accettato` con le prove di G-02..G-10. Le definizioni degli smell vanno confermate sul testo delle pubblicazioni prima di G-05
- Data: 2026-11-16
- Decisione umana richiesta: no
- Riferimenti: §3, §4.3, §5 passo 4, §6.2, §7.3, §19; ADR-0001, 0004, 0007, 0008, 0012, 0014; V-07 in `doc/verifiche/scanner-fase-2.md`; incoerenza 14 del piano

## Contesto

§7.3 elenca `ca-graph` come "interno", cioè senza container. Ma `ca-graph` analizza con tree-sitter, un parser in C, i file del repository analizzato, che sono input non fidato: eseguirlo nel processo della CLI contraddice il principio di ADR-0004, dove tutto ciò che legge il workspace gira isolato.

§6.2 nomina tre smell (Cyclic, Hub-Like, Unstable Dependency) senza definizioni operative, soglie né granularità. §4.3 dà agli archi una `confidence ∈ {dichiarato, dedotto, osservato}` senza dire quando vale ciascun valore. ADR-0008 non ha un `kind` di fingerprint per uno smell, che non ha una riga.

V-07 ha misurato: meno di 6 secondi e 42 MB per il pilota più grande con le restrizioni dei plugin; 5 file su 5.259 analizzati in parte; senza leggere gli alias di `tsconfig` più della metà degli import interni di un pilota risulta esterna; cartelle Python senza `__init__.py`; pochi import calcolati.

## Opzioni per l'estrazione

1. Nel processo della CLI, come dice §7.3: nessun container in più, ma un difetto del parser o di una grammatica diventa esecuzione di codice sull'host, con i permessi di chi lancia la scansione.
2. **In un container firmato come un plugin**, che emette il grafo come dato; il resto di `ca-graph` lavora sull'host, solo su quel dato.
3. Tutto `ca-graph` nel container, smell compresi: il container dovrebbe conoscere configurazione e soglie, e gli smell non si potrebbero ricalcolare senza rieseguirlo.

## Raccomandazione

Opzione 2. V-07 mostra che il costo è l'avvio di un container.

### Divisione del codice

| Parte | Dove gira | Cosa importa |
| --- | --- | --- |
| `ca_graph.treesitter` (estrattori, risoluzione degli import) | Solo nell'immagine `ca-graph` | Libreria standard, tree-sitter e le tre grammatiche. Non importa `ca_core` né il resto di `ca_graph` |
| `ca_graph.deps`, `ca_graph.smells`, `ca_graph.pagerank` e il resto | Sull'host, nel processo della CLI | `ca_core`. Nessun parser, nessuna rete, nessun processo, nessuna lettura del workspace |

- tree-sitter e le grammatiche sono una dipendenza facoltativa di `ca-graph`, installata nell'immagine di estrazione e nell'ambiente di sviluppo, **non nell'immagine CLI**. Un contratto `import-linter` vieta a `ca_cli`, a `ca_core` e al resto di `ca_graph` di importare `ca_graph.treesitter` (G-01).
- L'immagine sta in `ca_plugins/builtin/ca_graph/` con manifest, licenze e SBOM, ed è firmata e verificata come le altre (ADR-0005). Profilo `hardened-container`, `network: none`, workspace in sola lettura.
- Il manifest dichiara un'uscita nuova, `graph`, accanto a `sarif` e `cyclonedx`. È una modifica di `plugin-manifest` (C-02, con l'emendamento di ADR-0007 in A-16).
- L'estrazione non dipende dall'SBOM: parte insieme agli altri plugin. Il passo `build_graph` di §5 sull'host legge il grafo, calcola metriche e smell e produce i finding (G-10).
- `ca_api` non importa `ca_graph`: il server riceve il grafo come artefatto e non lo ricalcola (ADR-0016, ADR-0018).

Lo stesso container estrae la storia git per il churn, con la git dir ombra di ADR-0012 (emendamento per P-07): nessuna configurazione del repository viene letta. Finestra, misura e trattamento del clone superficiale sono di ADR-0022.

### Grafo emesso dal container

Il formato è il contratto di C-02. Contenuto:

- **Nodi.** Un nodo per file sorgente, identificato dal percorso POSIX relativo alla radice del workspace. Estensioni: `.py`; `.js`, `.mjs`, `.cjs`, `.jsx`; `.ts`, `.mts`, `.cts`, `.tsx`. I file di sole dichiarazioni (`.pyi`, `.d.ts`) si saltano. Ogni nodo porta linguaggio, esito dell'analisi (`completa` o `parziale`) e se è un file di test, riconosciuto con le stesse regole di percorso fisse di P-07.
- **Nodi esterni.** Un nodo per pacchetto esterno importato, con il nome così come compare nell'import (primo segmento per Python; nome del pacchetto, con lo scope, per npm). Servono alla raggiungibilità delle dipendenze (ADR-0022), non agli smell.
- **Archi.** Da file a file o da file a pacchetto esterno, uno per coppia, con il numero di import che lo sostengono, la forma (`statico`, `dinamico`), se è di soli tipi (`import type`, blocco `TYPE_CHECKING`) e la `confidence`.
- **Conteggi.** File analizzati, analizzati in parte, saltati per dimensione, e import non risolti divisi per motivo.

`confidence`:

| Valore | Quando |
| --- | --- |
| `dichiarato` | Import con stringa letterale risolto con le sole regole del linguaggio: relativo, oppure assoluto di Python dalla radice del workspace |
| `dedotto` | Risolto con una regola che interpreta dati del repository o una convenzione: alias di `tsconfig`, nome di un pacchetto del workspace, radice di sorgenti diversa dalla radice del workspace, pacchetto senza `__init__.py` |
| `osservato` | Da dati di esecuzione. Nessun arco in Fase 2: il valore resta nel contratto per la Fase 4 |

Regole di risoluzione, tutte su dati e mai eseguendo qualcosa:

- **Mai inventare.** Un import il cui argomento non è una stringa letterale (`require` o `import()` calcolati, `importlib.import_module`) non produce archi: si conta. Lo stesso per un import che non corrisponde a un file del workspace né ha la forma di un pacchetto esterno.
- **Python.** Import relativi dal percorso del file. Import assoluti cercati dalla radice del workspace e dalle radici di sorgenti riconosciute: le cartelle `src` e quelle che contengono un file di progetto Python. Una cartella è un pacchetto anche senza `__init__.py`. Con più corrispondenze vince la radice più vicina al file che importa.
- **JS e TS.** Specificatori relativi con le estensioni ammesse, `index` di cartella e la convenzione di TypeScript che scrive `.js` per un file `.ts`. Gli altri specificatori si confrontano prima con gli alias `paths` e `baseUrl` del `tsconfig.json` più vicino risalendo le cartelle, poi con i nomi dei `package.json` presenti nel workspace; se nessuno corrisponde, il pacchetto è esterno.
- **`tsconfig.json` e `package.json` sono dati non fidati.** Si leggono con limiti di dimensione e profondità, tollerando commenti e virgole finali. `extends` si segue solo verso file dentro il workspace e per un numero limitato di passi; un `extends` verso un pacchetto si conta e si ignora. Un alias che porta fuori dal workspace non produce archi. `node_modules` non si visita mai.
- **File con errori di sintassi.** L'albero di tree-sitter resta utilizzabile: si leggono gli import trovati, il nodo è `parziale`, il file si conta. Non è un fallimento.
- Cartelle saltate sempre: `.git`, `node_modules`, ambienti virtuali, cartelle di build note. Le esclusioni di `.code-analyzer.yml` (ADR-0014) si applicano sull'host, togliendo nodi e archi prima di ogni calcolo.

Limiti, nel manifest o nella configurazione dell'adattatore: dimensione massima di un file (oltre, saltato e contato), numero massimo di file e di archi, `max_bytes` dell'uscita, tempo e memoria. Superare un limite globale è un fallimento del plugin, non un grafo troncato in silenzio.

Sull'host il grafo è un input non fidato come ogni uscita di plugin: validato contro lo schema, percorsi confinati al workspace con la regola di ADR-0008, archi che citano solo nodi presenti, limiti di numero. Nodi e archi sono ordinati: lo stesso workspace dà lo stesso file, byte per byte.

### Granularità

- **Modulo:** un file sorgente.
- **Pacchetto:** una cartella che contiene almeno un modulo. Una sottocartella è un pacchetto distinto, non una parte del padre, come i package nelle pubblicazioni di riferimento.
- Il grafo dei pacchetti si ricava da quello dei moduli: un arco da A a B se un modulo di A importa un modulo di B, con il numero di archi sottostanti. Gli archi interni a un pacchetto non contano.
- Metriche per nodo ai due livelli: dipendenze entranti (Ca), uscenti (Ce) e instabilità `I = Ce / (Ca + Ce)`, con `I = 0` per un nodo isolato. Solo archi interni al repository.

Predefiniti, entrambi in configurazione: i moduli di test non entrano nel calcolo di metriche e smell; gli archi di soli tipi entrano, e l'evidenza dice quali sono.

### Smell

Le definizioni seguono Arcelli Fontana et al., ICSME 2016, e Arcan, ICSAW 2017 (§19). **Sono trascritte a memoria**: formule e soglie predefinite vanno confrontate con il testo prima di G-05, e ogni differenza corregge questa tabella. Le soglie stanno nella configurazione di scoring (C-03), mai nel codice.

| Smell | Livello | Definizione | Parametri e predefiniti |
| --- | --- | --- | --- |
| Cyclic Dependency | Modulo e pacchetto | Una componente fortemente connessa del grafo con almeno due nodi | Dimensione minima 2; livelli attivi: entrambi |
| Hub-Like Dependency | Modulo | Dipendenze entranti e uscenti entrambe sopra la mediana del sistema, e sbilanciamento `|Ca − Ce|` sotto una frazione del totale `Ca + Ce` | Frazione 0,25 |
| Unstable Dependency | Pacchetto | Il pacchetto dipende da pacchetti meno stabili di sé; grado = dipendenze verso pacchetti con `I` maggiore diviso il totale delle dipendenze uscenti | Segnalato se il grado è almeno 0,3 |

Due guardie contro il rumore non vengono dalle pubblicazioni e sono dichiarate come scostamento: un numero minimo di dipendenze totali perché un modulo possa essere un hub, e un numero minimo di dipendenze uscenti perché un pacchetto possa avere una dipendenza instabile. Predefinito 0 per entrambe, cioè spente: si alzano solo con i dati di X-02, e il valore usato compare nel report.

Ogni smell diventa un `Finding` con `category: architecture`, `tool: ca-graph` e:

| Smell | `rule_id` | Ancora | Evidenza |
| --- | --- | --- | --- |
| Cyclic Dependency | `ca.arch.cyclic-dependency` | Il primo membro del ciclo in ordine lessicografico | Livello, membri (con un tetto e il totale), numero di archi, archi di soli tipi |
| Hub-Like Dependency | `ca.arch.hub-like-dependency` | Il modulo | Ca, Ce, mediane, sbilanciamento |
| Unstable Dependency | `ca.arch.unstable-dependency` | Il pacchetto | `I` del pacchetto, grado, dipendenze meno stabili con il loro `I` |

La posizione del finding è il percorso dell'ancora, senza riga. Il numero di componenti coinvolti, che §6.2 usa per G della Variante B, è nell'evidenza.

Livello provvisorio fino al Gate 2 (D2-10): `basso`, con `level_source: default`. ADR-0009 non ha una riga per `architecture`, e nessuno smell deve bloccare una CI prima che l'ordinamento sia validato. A-16 aggiunge la riga.

§6.2 vieta di presentare gli smell come predittori di bug di concorrenza: i testi dei finding descrivono la struttura trovata e nient'altro.

### Fingerprint

Nuovo `kind` per ADR-0008, senza toccare la formula né i `kind` esistenti:

| `kind` | `rule_id` | `tool_family` | `normalized_location` | `component` |
| --- | --- | --- | --- | --- |
| `architecture` | id dello smell | `ca-graph` | `scope` NUL `path` | vuoto |

`scope` è `module` o `package`; `path` è l'ancora. Nessuna riga e nessun contesto di codice: spostare righe non cambia il fingerprint.

Limite accettato per i cicli: l'ancora è il membro più piccolo, quindi il fingerprint resta uguale quando il ciclo cresce o si riduce, ma cambia se quel membro esce dal ciclo o se ne entra uno che lo precede. Un'eccezione su un ciclo può quindi decadere senza che il ciclo sia sparito. L'alternativa, l'insieme dei membri, cambierebbe a ogni modifica del ciclo.

### Fallimenti

- Estrazione fallita o fuori dai limiti: finding `health` `ca.scanner-not-run` per `ca-graph` e scansione `partial`, come per ogni plugin (ADR-0007). Nessun finding di architettura; i fattori che dipendono dal grafo valgono "ignoto" secondo ADR-0021, 0022 e 0023.
- File analizzati in parte, file saltati, import non risolti: avvisi nel report con i conteggi. La scansione resta `complete`.
- Un linguaggio assente dal repository non è un errore: il grafo può essere vuoto.

## Conseguenze

- §7.3 va corretto in A-17: `ca-graph` non è "interno". L'immagine è l'ottava da costruire, firmare e valutare per le licenze (I-02, D2-14).
- L'immagine CLI non contiene un parser in C né le grammatiche.
- `plugin-manifest` guadagna l'uscita `graph`; `finding` e il fingerprint guadagnano la categoria e il `kind` `architecture`. Sono aggiunte compatibili; gli schemi e i test di contratto si aggiornano con C-01, C-02 e C-10 (`AGENTS.md` regola 1).
- La risoluzione degli import è volutamente incompleta: riesportazioni, `exports` di `package.json`, percorsi aggiunti a `sys.path` a tempo di esecuzione non si seguono. Il grafo dichiara quanti import ha lasciato fuori, e F-01 fissa i casi coperti.
- La grammatica TypeScript è ferma dal 2024 (V-01): la sintassi nuova produce file `parziali`, non errori. Il conteggio nel report è il segnale per aggiornarla o sostituirla.
- Gli smell si possono ricalcolare da un grafo conservato, per esempio dopo aver cambiato le soglie, senza rieseguire l'estrazione.
- G-09 resta com'è nel piano; la sua alternativa "esecuzione sull'host" decade.

## Realizzazione (G-02, G-03)

Scritta il 2026-11-17, a codice provato. L'estrazione sta in `ca_graph/treesitter/` (`files`, `python`, `javascript`, `extract`) e importa solo la libreria standard e tree-sitter; `lint-imports` impone che non importi `ca_core` né il resto di `ca_graph`.

- **Uscita.** `extract_graph(workspace)` restituisce un dizionario nel formato di C-02, che i test validano contro lo schema e contro il modello `Graph`. Stessi file in ordine diverso danno gli stessi byte (`to_json`). Entrypoint, churn, metriche e pacchetti restano vuoti: gli entrypoint e il churn sono di G-12 e G-11, metriche e pacchetti li calcola l'host.
- **Python.** `import`, `from … import` (assoluti e relativi), `importlib.import_module` e `__import__` con stringa letterale (arco `dinamico`); argomento non letterale contato. Gli import in un blocco `if TYPE_CHECKING:` sono `type_only`, il ramo `else` no. Radici da cui si risolvono gli import assoluti: la radice del workspace, `src` e le cartelle con `pyproject.toml`, `setup.py` o `setup.cfg`; prima quelle che contengono il file, poi le altre. Una cartella senza `__init__.py` è un pacchetto con `confidence` `dedotto`; `from pkg import sub` punta al sotto-modulo se esiste. La libreria standard non è un nodo.
- **JS, TS e TSX.** `import`, `export … from`, `import x = require()`, `require()` e `import()` con stringa letterale o template senza sostituzioni; `import type` ed `export type` sono `type_only`. Alias da `tsconfig.json` e `jsconfig.json` (`baseUrl`, `paths` con il prefisso più lungo, `extends` verso file nel workspace fino a 8 passi, con cicli e uscite dal workspace contati in `config_extends`), nomi dei `package.json` del workspace (`main`, `module`, `exports`, `src/index`), la convenzione `./a.js` → `./a.ts`. Un alias che corrisponde ma non ha file è `missing`, mai un pacchetto esterno. `tsconfig` e `package.json` sono letti con un parser tollerante (commenti e virgole finali), con tetto di 256 KiB, mai eseguiti.
- **Input ostile (S-02).** Visite iterative con tetto di profondità (un albero troppo profondo rende il file `parziale`); collegamenti simbolici, FIFO e dispositivi mai seguiti né letti; file oltre 2 MiB contati; oltre 200.000 file l'estrazione fallisce; i nomi con caratteri di controllo si saltano e si contano nel campo nuovo `stats.files_skipped_name` (`graph` passa a 1.1): senza questo un solo nome di file renderebbe invalido l'intero grafo. Provato che nulla del workspace viene eseguito (`setup.py`, `conftest.py`, `eslint.config.js`).
- **Non fatto.** Nessuna misura sui pilota in questa sessione: i numeri di V-07 (meno di 6 s e 42 MB sul più grande) restano quelli di una visita semplice, e il tempo con la risoluzione degli import non è misurato (X-05). tree-sitter non ha un timeout di parsing impostato: lo fa il container (G-09). Non risolti: `import { type X }` (conta come import di valore), `imports` di `package.json` (`#alias`), `rootDirs` e `moduleSuffixes` di `tsconfig`, condizioni di `exports` oltre `import`, `default` e `require`, riesportazioni e `__all__` in Python, modifiche a `sys.path` a tempo di esecuzione. Ognuno ricade in un arco mancante contato, non in uno inventato.
