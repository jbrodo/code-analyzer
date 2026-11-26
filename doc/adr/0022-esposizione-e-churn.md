# ADR-0022: Esposizione e churn

- Stato: Accettato il 2026-11-18. Le prove sono nel codice: la raggiungibilità sul grafo (G-12) e il churn dalla storia git nell'immagine di `ca-graph` (G-11), con l'E2E del pacchetto verde. Restano dichiarati i limiti dei task, tra cui la densità di violazioni, che non è di questo ADR
- Data: 2026-11-16
- Decisione umana richiesta: no. Un valore si scosta da una proposta del piano: vedi "Esposizione assente"
- Riferimenti: §6.1, §6.2; ADR-0012, 0020, 0025, 0028; V-07 in `doc/verifiche/scanner-fase-2.md`; incoerenza 7 del piano

## Contesto

§6.1 definisce E a partire da "raggiungibile da un entrypoint", senza dire cos'è un entrypoint, a che granularità si misura la raggiungibilità né come si collega una dipendenza al codice che la usa. Per smell e qualità P è "il percentile di churn del file negli ultimi 90 giorni", ma le CI clonano spesso un solo commit, e con quella storia il churn non esiste.

Entrambi i dati vengono dal container di estrazione di ADR-0020, che legge i file e la storia git senza eseguire nulla del repository. I calcoli avvengono sull'host, sul grafo.

## Decisione

### Entrypoint

Li rileva il container e li elenca nel grafo (C-02), ciascuno con il tipo e la `confidence` di ADR-0020: `dichiarato` se viene dai metadati del pacchetto, `dedotto` se viene da una convenzione.

| Linguaggio | Dichiarati | Dedotti |
| --- | --- | --- |
| Python | Script, script grafici ed entry point di `pyproject.toml`; `[options.entry_points]` di `setup.cfg` | File `__main__.py`; moduli con il blocco `if __name__ == "__main__"`; `manage.py`, `wsgi.py`, `asgi.py`; moduli che costruiscono un'applicazione di un framework web noto |
| JS e TS | `main`, `module`, `bin` ed `exports` di `package.json`, quando puntano a un file | Il modulo caricato da un `index.html` nella radice di un pacchetto; `src/main.*` e `src/index.*`; moduli che costruiscono un server di un framework noto |

Regole:

- I file di metadati si leggono come dati, con i limiti di ADR-0020. `setup.py` è codice e non si legge. Il campo `scripts` di `package.json` contiene comandi di shell e non si interpreta.
- Un entrypoint dichiarato che punta a un file assente dal repository, per esempio un prodotto della build, si cerca sotto `src/` con lo stesso nome e le estensioni dei sorgenti. Se non si trova si conta, e non produce un entrypoint.
- L'elenco dei framework riconosciuti è un dato dell'immagine di estrazione, versionato con essa.
- Un file di test non è un entrypoint.

### Raggiungibilità dei moduli

A livello di modulo, cioè di file. Si parte dagli entrypoint e si seguono gli archi interni del grafo. Gli archi di soli tipi non si seguono: non esistono a tempo di esecuzione.

| Stato | Quando |
| --- | --- |
| `raggiungibile` | Raggiunto da almeno un entrypoint |
| `solo-test` | È un file di test, oppure è raggiunto solo da file di test |
| `non-raggiungibile` | Non raggiunto, **e** il grafo del suo linguaggio è completo: nessun import non risolto contato |
| `ignota` | In ogni altro caso: grafo assente o fallito, nessun entrypoint trovato per quel linguaggio, import non risolti, file analizzato in parte |

La regola è prudente di proposito. Basta un import calcolato nel repository perché un modulo non raggiunto resti `ignota`: quell'import potrebbe essere la strada che manca. V-07 ne ha trovati da 0 a 7 per pilota, quindi `non-raggiungibile` sarà raro, ed è corretto così: è l'unico stato che abbassa E affermando qualcosa che il grafo non può sempre provare.

### Uso di una dipendenza

Per un finding su un pacchetto (categoria `dependency`, e le licenze dei componenti):

- **Diretta.** Il pacchetto è usato se un modulo lo importa: è l'arco verso un nodo esterno del grafo. Lo stato è il migliore tra quelli dei moduli che lo importano.
- **Nome di import.** Per npm il nome del pacchetto è il nome usato nell'import. Per Python no: il nome della distribuzione può differire da quello del modulo. Si confrontano i nomi normalizzati, più una tabella di corrispondenze note inclusa nel nucleo come dato versionato. Senza corrispondenza lo stato è `ignota`, mai "non usata".
- **Transitiva.** Se l'SBOM porta le relazioni tra componenti, eredita lo stato migliore tra i componenti che la richiedono. Senza relazioni: `ignota`.
- **Di sviluppo o di test.** Quando lockfile o SBOM la dichiarano tale, oppure quando la importano solo moduli `solo-test`. Che cosa syft riporta per ciascun gestore di pacchetti lo verifica G-12.

### Valori di E

I valori stanno nella configurazione di scoring (C-03). Predefiniti da §6.1:

| Condizione | E |
| --- | --- |
| `raggiungibile`, servizio esposto su internet | 1,0 |
| `raggiungibile`, servizio interno | 0,6 |
| `raggiungibile`, esposizione assente | 0,6 |
| `ignota` | 0,3 |
| `solo-test`, dipendenza di sviluppo o di test, `non-raggiungibile` | 0,2 |

- L'esposizione viene dal contesto del servizio (ADR-0028).
- **Esposizione assente.** La sezione 3 del piano proponeva 0,3 per un repository non registrato. Qui vale 0,6, come un servizio interno: con 0,3 non registrare un repository darebbe punteggi più bassi che registrarlo come interno. È lo stesso criterio del tier assente, che vale come il tier di mezzo. Il report dichiara la fonte `default` (ADR-0028).
- `non-raggiungibile` non è in §6.1. Vale come il codice di test: non fa parte di ciò che gira.
- **Finding senza modulo né pacchetto** (IaC, segreti, licenze su file non sorgente): la raggiungibilità non si applica. Valgono come `raggiungibile`, salvo i file sotto i percorsi di test, che valgono 0,2.
- Più moduli nello stesso finding, come in un ciclo: vale lo stato migliore tra i membri.
- L'evidenza di E registra stato, entrypoint che raggiunge il modulo (uno, il più vicino), esposizione e fonte.

### Churn

- **Misura.** Per ogni file, il numero di commit che lo toccano nei 90 giorni che precedono **la data del commit analizzato**, non la data della scansione: la stessa scansione rifatta dopo un mese dà lo stesso valore. Esclusi i commit di merge. Le rinomine non si seguono: conta il percorso attuale.
- **Finestra.** 90 giorni, in configurazione.
- **Estrazione.** Nel container di ADR-0020, con la git dir ombra di ADR-0012: la configurazione git del repository non viene mai letta. Un solo comando di lettura della storia, con tetti su numero di commit e durata. Il container emette nel grafo il conteggio per file, la finestra, i commit letti e lo stato della storia.
- **Percentile.** Sull'host: per un file, la quota di file sorgente del repository con un churn strettamente minore. I percorsi esclusi (ADR-0014) e i file di test non entrano nella popolazione. Un file mai toccato nella finestra ha percentile 0; il minimo di P, se c'è, lo fissa ADR-0021.
- **Più moduli nello stesso finding:** il massimo dei percentili.

Stato della storia:

| Stato | Quando | Churn |
| --- | --- | --- |
| `completa` | Clone non superficiale, oppure superficiale ma con tutti i commit di confine più vecchi dell'inizio della finestra | Calcolato |
| `superficiale` | Clone superficiale la cui storia non copre la finestra | Ignoto per tutti i file. Avviso `churn-history-shallow` |
| `assente` | Cartella non git, o lettura fallita | Ignoto. Avviso `churn-history-missing` |

**Mai un valore inventato.** Con storia `superficiale` un conteggio esisterebbe, ma direbbe "poco modificato" di ogni file. Il churn resta ignoto, P usa la costante dichiarata da ADR-0021 per questo caso, e i punteggi di quella scansione sono marcati come calcolati senza churn. La scansione resta `complete`: è copertura ridotta dichiarata, come per gitleaks sul clone superficiale (ADR-0012).

La documentazione dell'Action indica la profondità di clone che serve (ADR-0027): con `fetch-depth: 2` il confronto della PR funziona, il churn no.

La densità di violazioni, che §6.2 combina con il churn per P della Variante B, è di ADR-0023.

## Conseguenze

- Il grafo di C-02 porta entrypoint, conteggio di churn per nodo e stato della storia. L'estrazione resta un solo container con una sola uscita.
- E dipende da quanto bene si riconoscono gli entrypoint. Un repository senza entrypoint riconosciuti, per esempio una libreria, ha tutto `ignota` e quindi E = 0,3 ovunque: l'ordinamento al suo interno non cambia, ma i suoi punteggi sono più bassi di quelli di un'applicazione. Va scritto nella documentazione (L-05) e guardato in X-02.
- La tabella dei nomi di import di Python è incompleta per natura. Ogni dipendenza senza corrispondenza resta `ignota`, e il report le conta.
- Chi vuole il churn nelle PR deve clonare almeno 90 giorni di storia. Sui repository grandi costa tempo di clone: X-05 lo misura.
- Il valore di E per l'esposizione assente è una scelta di questo ADR diversa dalla proposta del piano: l'utente può cambiarla nella configurazione di scoring senza toccare il codice.
- Gli stati e i valori entrano nella tabella di regressione dello scoring (F-05).

## Realizzazione del churn (G-11, 2026-11-17)

- `ca_graph/treesitter/history.py` (solo libreria standard, nell'immagine di estrazione): git dir ombra come in ADR-0012, un solo `git log --no-merges --no-renames -z --name-only` con tetti su commit (200 mila), byte (256 MiB) e durata (120 s; il processo si termina con il suo gruppo), finestra che finisce alla data del commit analizzato.
- Un clone superficiale è `completa` se tutti i commit di confine sono più vecchi dell'inizio della finestra (come scrive la tabella sopra); altrimenti `superficiale`. Un tetto superato, un fallimento di git o un `.git` non replicabile danno `assente`: mai un conteggio troncato.
- `ca-graph` non può più dirsi privo di processi: **`history.py` è l'unico modulo di `ca_graph` che importa `subprocess`**, e gira solo nel container. Il contratto di `lint-imports` lo ammette con `ignore_imports` per quel solo import, così nessun altro modulo del pacchetto può avviare un processo. L'immagine contiene ora git (pacchetto Debian non fissato per versione) e il limite di `pids` sale a 32.
- Il percentile sull'host è `ca_core.scoring.churn.ChurnIndex`.
