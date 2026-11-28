# Fase 3 — Agenti LLM e motore decisionale

Piano derivato da `doc/PROJECT.md` §10, §11, §13 e §14, scritto il 2026-11-27 dopo la chiusura della Fase 2 (con limiti dichiarati, a Gate 2 non superato).

Obiettivo: un motore decisionale locale suggerisce il triage dei finding, e agenti locali propongono correzioni verificate, come PR in bozza che un umano unisce.

**Stato al 2026-11-27** (`doc/verifiche/fase-3.md`): V3-01 fatto per quanto leggibile senza eseguire nulla; V3-02 fatto, **il corpus di 10 non bastava**; con 30 repository Python basta per numero e JavaScript/TypeScript no (D3-08); V3-03 superato (Laya funziona senza rete); di V3-04 fatta la parte CPU. Restano V3-04 su GPU, V3-05 e il punto di arresto V3-06. **Che Laya sappia fare il triage non è ancora misurato.** L'onda 1 è iniziata (sezione 6). Il 2026-11-27, senza addestramento, né Laya né `gemma3:4b` hanno distinto casi inventati ovvi (V-F3.11–V-F3.13): le prove sul motore sono ferme finché non ci sono etichette affidabili.

**Il piano è dettagliato solo fino alla prima verifica di fattibilità (onde 0–2).** Che un modello locale possa raggiungere il Gate 3, o produrre correzioni utili su questo hardware, non è provato. Le onde successive si dettagliano dopo V3-06.

## 0. Stato di partenza

Verificato il 2026-11-27 nel repository e sulla macchina di riferimento:

- `ca-decision`, `ca-agents`, `golden-set/` e `schemas/phases/` non esistono. Il blocco `agents` di `.code-analyzer.yml` è validato e non ha effetto.
- Il server non ha il codice sorgente (ADR-0016): le decisioni che leggono il codice possono girare solo dove gira la CLI.
- GPU: una RTX 3080 Ti con 12 GB, di cui 1,7 GB liberi al momento della verifica (circa 9,3 GB occupati da un altro processo `llama-server` dell'utente). RAM circa 60 GB, disco libero circa 99 GB.
- Ollama è installato, con due modelli: `laya` (844 MB; architettura ModernBERT, 421 M di parametri, contesto configurato 512, capacità `decision`) e `gemma3:4b`. Non è verificato da quale checkpoint venga quel `laya`, né la sua licenza. Nessuno dei due è stato eseguito.
- Nel codice non c'è una redazione dei segreti pensata per un prompt (§11.4). Esistono i controlli sull'output di gitleaks.

### 0.1 Laya: cosa dice la sua documentazione

Prima lettura, precedente all'ondata 0. Dove V3-01 dice di più o di diverso (formato dei dati, verifica degli hash, `vegaml`, licenze dei modelli di base) vale `doc/verifiche/fase-3.md`.

Letta il 2026-11-27 (README, scheda del modello, commit e release), **solo in parte** (circa gli ultimi 20.000 caratteri del README non sono stati letti) e **senza eseguire nulla**. I numeri sono dichiarati dagli autori.

| Tema | Dichiarato | Cosa comporta |
| --- | --- | --- |
| Funzione | Risposte tipate (sì/no, scelta, punteggio) con probabilità, in un passaggio, senza generare testo | Adatto all'interfaccia di §10.1; l'API è diversa dai nomi di §10 |
| Codice e analisi statica | **Non citati.** Nessuna misura su codice o finding; italiano non nominato | La premessa principale del piano è senza prove |
| Zero-shot sul benchmark degli autori | 0,36 di accuratezza contro 0,46 della classe di maggioranza; 0,77 dopo fine-tuning sullo stesso benchmark | Conferma §10.3: senza addestramento non serve |
| Dati per il fine-tuning | Esempio con circa 30.000 domande su due GPU T4; formato non descritto nelle pagine lette (ricavato dal codice in V3-01). Citate anche calibrazione e testa logistica sulle proprie etichette, senza gradiente | Non è noto se poche centinaia di etichette bastino |
| Contesto | 512 token (inglese), 1.024 (typed-decisions e multilingue) | ±20 righe di codice possono non starci |
| Esecuzione | CPU, CUDA e altri; pesi scaricati al primo uso; uso offline indicando cartelle locali; telemetria **non dichiarata** | Offline da provare con la rete disattivata |
| Licenze | Codice e pesi con licenza permissiva; licenze dei modelli di base non dichiarate nelle pagine lette. Il pacchetto di apprendimento continuo `vegaml-learn` è **solo non commerciale** | `vegaml-learn` è escluso: il prodotto è usabile dalle aziende (ADR-0032) |
| Manutenzione | Rilasci quasi quotidiani nell'ultima settimana (0.5.x) | Versione e pesi vanno fissati per hash |
| `jevos` (§10.1) | Non compare nelle pagine lette | `JevosEngine` resta fuori finché non si trova la sua fonte |

## 1. Vincoli

1. **Niente modelli esterni: il codice analizzato non esce dalla macchina** (decisione dell'utente del 2026-11-27, ADR-0033). Vale per il prodotto, non per gli strumenti con cui lo si sviluppa. `JevEngine` e i provider a zero retention escono.
2. Il processo che esegue un modello **non ha rete**. I pesi si scaricano in un passo separato, fissati per digest, come i feed (ADR-0006). Un'impostazione dell'applicazione non basta come garanzia.
3. L'indirizzo, il nome e i parametri di un modello **non si leggono da `.code-analyzer.yml`**, che è modificabile da chi modifica il branch (ADR-0014).
4. Il codice e i messaggi degli strumenti sono **input non fidato** anche per un modello locale: un suggerimento non cambia stato, livello o gate da solo.
5. I finding di segreti e i valori rilevati **non entrano in nessun prompt** (§11.4). La redazione vale anche in locale: prompt e risposte vengono registrati.
6. Il rilevamento resta deterministico: nessun finding nasce da un modello (§1).
7. Il repository è pubblico: nel golden set entrano solo repository pubblici. Etichette e frammenti di repository privati restano fuori.
8. Nei test e in CI solo fake deterministici, senza modelli veri (§14).

## 2. Gate 3

§13 dice solo "precisione del triage ≥ 80% sul golden set". Così com'è, il gate si può superare senza valore: se l'85% dei finding è vero, rispondere sempre «vero» dà l'85%. **Deciso il 2026-11-27 (D3-02, ADR-0034, che precisa anche le voci «non so» e le dimensioni del test):**

| Condizione | Misura, su un insieme di test mai usato per addestrare o calibrare |
| --- | --- |
| **G3.a** Precisione | Sulle decisioni che il motore non rimanda all'umano, precisione ≥ 0,80 **sia** per «vero» **sia** per «falso positivo» |
| **G3.b** Copertura | Il motore decide almeno il 50% dei finding del test |
| **G3.c** Meglio del banale | Accuratezza bilanciata più alta di quella delle basi di confronto: classe di maggioranza e regola deterministica per `rule_id` |
| **G3.d** Solo in locale | Valutazione eseguita con la rete disattivata |

Il test è separato dall'addestramento **per repository**, non per finding. Si pubblicano matrice di confusione, intervalli di confidenza e numero di esempi per classe. Le soglie si scrivono prima di vedere i risultati; dopo, non si cambiano sullo stesso test.

Quante etichette servono: con 200 esempi di test e un valore osservato di 0,86, l'estremo basso dell'intervallo di Wilson al 95% è circa 0,805; con 100 esempi e 0,80 è 0,71. La precisione per classe si calcola su un sottoinsieme, quindi ha un intervallo più largo: servono almeno 60 esempi della classe meno frequente nel test.

| Insieme | Etichette proposte | Nota |
| --- | --- | --- |
| Pilota | 30 | Misura il tempo per etichetta e la quota di falsi positivi |
| Calibrazione | 100 | Soglie per `question_id` |
| Test | 200 | Chiuso fino alla valutazione |
| Addestramento | 300 per cominciare | Quante ne servano è **ignoto**: si decide dalla curva di apprendimento |

Circa 630 etichette. A 1–3 minuti ciascuna (**ipotesi**, la misura il pilota) sono 10–30 ore di lavoro umano.

## 3. Decisioni dell'utente

| ID | Decisione | Raccomandazione | Blocca |
| --- | --- | --- | --- |
| **D3-01** | Chi annota il golden set, con quanto tempo | **Decisa il 2026-11-27: annota l'utente, da solo.** Si riannotano 30 voci dopo una settimana e il limite si dichiara. Il tempo disponibile si valuta dopo il pilota, che misura quello per etichetta. Un modello o un agente di coding non annota, e le sue proposte non si mostrano a chi annota | — |
| **D3-02** | Definizione del Gate 3 | **Decisa il 2026-11-27:** la sezione 2, con le definizioni di ADR-0034 | — |
| **D3-03** | Quali finding si valutano | Solo SAST in un primo momento (D3-07); la proposta iniziale era SAST, poi IaC. Esclusi i segreti (vincolo 5) e le dipendenze, dove «vero positivo» significa raggiungibilità, un problema diverso. V3-02 dice se SAST e IaC pubblici bastano | G3-02 |
| **D3-04** | Dove gira il motore | **Decisa il 2026-11-27 (ADR-0036):** Solo CLI, spento per default, su richiesta esplicita. Sui runner di una CI ospitata il codice è sulla macchina del fornitore e non c'è GPU: lì resta spento finché non decidi diversamente | — |
| **D3-05** | Cosa può fare un suggerimento | **Decisa il 2026-11-27 (ADR-0036):** In tutta la Fase 3 solo suggerire: nessuna azione `auto` di §10.3, nessun effetto su gate, livello o stato. `auto` si rivaluta dopo il gate, con un ADR | — |
| **D3-06** | Quando costruire gli agenti (fasi 0–5) | Solo dopo V3-05 sui modelli generativi e dopo la prima misura del triage | Onda 4 |

## 4. ADR

| ADR | Oggetto | Quando |
| --- | --- | --- |
| 0033 | Niente modelli esterni | Scritto insieme a questo piano |
| 0034 | Golden set, protocollo di annotazione e Gate 3 | Accettato il 2026-11-27 |
| 0035 | Esecuzione isolata dei modelli, pesi fissati per digest, licenze di pesi e modelli di base | Dopo V3-01, V3-03 e V3-04 |
| 0036 | `ca-decision`: interfaccia, instradamento (accettato il 2026-11-27; l'evidenza reale si fissa con DE-02) | Prima di DE-01; il motore vero si sceglie in V3-06 |
| 0037 | `ca-agents`: contratti di fase, sandbox di build e test, guardrail | Prima dell'onda 4 |

I numeri sono provvisori.

## 5. Ondate e task

Agenti: `architect`, `backend`, `test`, `security`, `devops`. All'inizio di ogni ondata si unisce `main` (`AGENTS.md`, regola 11).

### Onda 0 — Fattibilità (nessuna dipendenza dalle decisioni, salvo dove indicato)

| ID | Task | Accettazione |
| --- | --- | --- |
| V3-01 | Fissare versione di Laya, checkpoint e hash; leggere il resto della documentazione e le licenze sul testo, **modelli di base compresi**; chiarire cos'è il `laya` di Ollama | Tabella in `doc/verifiche/fase-3.md` con fonte e data; ogni voce non verificata dichiarata |
| V3-02 | Contare, sui repository pubblici del corpus, i finding SAST e IaC per regola e per repository | Si sa se si arriva a circa 630 finding distinti senza che poche regole dominino. Se no, si cambia corpus o D3-03 **prima** di annotare |
| V3-03 | Eseguire Laya con la **rete disattivata** in un container: caricamento, una decisione per tipo, tentativi di connessione, telemetria, `trust_remote_code` | Funziona senza rete, oppure è un blocco registrato |
| V3-04 | Misurare tempo, RAM e VRAM su CPU e GPU; dimensione di pacchetto, dipendenze e pesi | Numeri su 100 finding. La prova su GPU richiede memoria libera: la libera l'utente |
| V3-05 | Prova ridotta dei modelli generativi locali: 10 finding con correzione nota, su repository pubblici | Per ogni modello: patch che si applica, test verdi, finding chiuso, nessun finding nuovo, tempo. La soglia per procedere si scrive prima della prova |
| V3-06 | **Punto di arresto:** relazione e proposta | L'utente sceglie: procedere con Laya, cambiare motore (anche un modello generativo locale dietro la stessa interfaccia), o ridurre la fase |

Scaricare pesi nuovi (V3-01, V3-05) usa disco e rete: nessun codice esce, ma i download si elencano prima di farli.

### Onda 1 — Golden set (richiede D3-01, D3-02, D3-03 e V3-02)

| ID | Task | Dipende da | Accettazione |
| --- | --- | --- | --- |
| G3-01 | ADR-0034: definizioni di «vero» e «falso positivo», terza risposta «non so», regole per i casi dubbi, gate | D3-02 | Approvato prima della prima etichetta |
| G3-02 | Formato in `golden-set/`: riferimenti (repository pubblico, commit, fingerprint, etichetta), **senza copie di codice**; il frammento si ricostruisce in locale. Schema e test di contratto | D3-03 | Lo stesso riferimento produce la stessa evidenza; l'auto-analisi non riceve finding nuovi dal golden set |
| G3-03 | Interfaccia di annotazione, a partire da `scripts/gate2/review_ui`: codice, regola, tre risposte, tastiera, ripresa; nessun suggerimento di modelli | G3-02 | Provata sul pilota |
| G3-04 | Pilota di 30 etichette | G3-01, G3-03, D3-01 | Tempo per etichetta, quota per classe e casi dubbi misurati; sezione 2 ricalcolata |
| G3-05 | Divisione per repository e chiusura del test | G3-04 | Hash del test registrato prima di ogni addestramento |
| G3-06 | Annotazione di calibrazione, test e addestramento | G3-05 | Conteggi per classe; accordo o riannotazione misurati |

Il Gate 2 ha mostrato che ordinare a mano senza uno strumento non è sostenibile e che una copia di un ordine proposto non si distingue dai file: l'interfaccia viene prima del volume, e registra chi ha dato ogni etichetta.

### Onda 2 — `ca-decision` (richiede V3-06)

| ID | Task | Dipende da | Accettazione |
| --- | --- | --- | --- |
| DE-01 | Pacchetto `ca-decision` con motore finto; `Decision` e porta in `ca-core`; basi di confronto di G3.c in `golden-set/eval/`; contratti in `lint-imports` (**fatto**) | ADR-0036 | Test senza modelli |
| DE-02 | Selezione dell'evidenza entro il limite di token, con redazione e esclusione dei segreti (**fatto**; limite in caratteri, da verificare in token con DE-04; regola 4 dell'emendamento ad ADR-0036 temporanea) | DE-01, D3-04 | Test con segreti piantati: non compaiono in evidenza, log o errori; il troncamento è dichiarato |
| DE-03 | Instradamento per confidenza, soglie in configurazione, `route` senza `auto` (D3-05) (**fatto con DE-01**; l'elenco delle soglie è vuoto finché non si calibrano) | DE-01 | Nessuna soglia nel codice |
| DE-04 | Motore locale scelto in V3-06, in container senza rete, pesi per digest; ricerca dei segreti anche sui file del commit, senza storia (ADR-0036); evidenza solo dal file al commit | DE-02, ADR-0035 | Prova di integrazione con pesi fissati, fuori dalla CI ordinaria; con gitleaks vero, rinomina semplice e riuso del vecchio nome bloccati, poi si toglie la regola 4 |
| DE-05 | Script in `golden-set/eval/`: accuratezza, precisione per classe, calibrazione, copertura, intervalli (**fatte le misure**; il comando che le applica a un motore richiede DE-02) | DE-01, G3-02 | Riproduce gli stessi numeri a parità di pesi e dati |
| DE-06 | Rassegna di sicurezza di evidenza, esecuzione e pesi | DE-04 | Nessun rilievo alto aperto |

DE-01 e DE-05 non dipendono dal motore scelto e possono iniziare con il motore finto.

### Onda 3 — Addestramento e Gate 3 (richiede le onde 1 e 2)

| ID | Task | Accettazione |
| --- | --- | --- |
| E3-01 | Misure di base sul solo insieme di calibrazione: zero-shot, basi di confronto, calibrazione senza gradiente | Registrate prima di addestrare |
| E3-02 | Fine-tuning in locale, con curva di apprendimento | Pesi con hash, dati e comando registrati; se la curva dice che le etichette non bastano, si torna a G3-06 |
| E3-03 | Soglie calibrate per `question_id` | Curva di affidabilità allegata |
| E3-04 | **Gate 3**, una sola volta sul test chiuso | G3.a–G3.d. Se non passa, il test usato non si riusa come test: ne serve uno nuovo |
| E3-05 | Esiti del triage nel report come suggerimento (nuovo campo, schema, SARIF), poi in API, tabella `decisions` e UI | Distinto in UI dal dato deterministico (ADR-0029), con modello e versione; assente per default |

E3-05 si fa solo se il gate passa.

### Onda 4 — Agenti, fasi 0–5 (da dettagliare; richiede D3-06)

Ordine proposto, una fetta verticale per volta:

1. Contratti in `schemas/phases/` e interfaccia del provider locale (`llm.py`), con provider finto.
2. Controlli deterministici: redazione, perimetro dei file, budget, log in `agent_runs`.
3. Sandbox di build e test per la fase 4: esegue codice non fidato, quindi senza rete e senza credenziali. Le dipendenze del progetto vanno preparate in un passo separato: è un problema da progettare, non un dettaglio.
4. Una sola correzione dall'inizio alla fine: aggiornamento di una dipendenza npm o Python, dalla fase 2 alla fase 5, con riscansione.
5. Correzioni sul codice, solo se V3-05 le ha mostrate praticabili.
6. PR in bozza; integrazione con Renovate e Dependabot (§12.3), che legge API di GitHub e va decisa a parte rispetto al vincolo 1.

La fase 5 richiede un modello diverso dalla fase 4 (§11.2): su 12 GB i due girano uno dopo l'altro.

## 6. Esiti dell'onda 0 e prossimi passi

- **V3-01:** versioni, commit e hash fissati; licenze dichiarate permissive per pacchetti, pesi e modelli di base. Il codice non commerciale non è tra le dipendenze.
- **V3-02:** 737 finding SAST fuori dai test sui 10 repository, di cui 310 di una sola regola (B101); django e scrapy ne fanno l'83%; IaC solo 39. **Non bastano** per le circa 630 etichette. Serve D3-07 prima di annotare.
- **V3-03:** Laya 0.5.5 con i pesi `typed-decisions` funziona in un contenitore senza rete, anche senza `vegaml`.
- **V3-04, solo CPU:** 0,87 s per finding con 4 thread e 0,52 s con 8, circa 2,8 GB di memoria, nessun troncamento dell'evidenza sul campione. Il numero di thread va fissato.

**D3-07, come avere abbastanza finding vari — decisa il 2026-11-27 dall'utente:** corpus del golden set di circa 30 repository pubblici, soprattutto applicazioni e con più JavaScript e TypeScript, separato da `scripts/benchmark/corpus.json` (che serve alla Variante B e non cambia); tetto per repository e regola, proposto in ADR-0034 (20); B101 escluso; **IaC fuori dal primo ambito** (D3-03 si riduce a SAST). Se 30 repository bastino si sa solo scansionandoli. L'elenco è in `doc/verifiche/fase-3.md` (V-F3.5).

L'elenco dei repository è stato approvato e scansionato il 2026-11-27 (V-F3.6): su Python i punti di codice distinti sono 973 (772 con al più 20 per repository e regola), su JavaScript e TypeScript 79, da 4 regole.

| ID | Decisione nuova | Raccomandazione | Blocca |
| --- | --- | --- | --- |
| **D3-08** | Cosa fare con JavaScript e TypeScript | **Decisa il 2026-11-27: golden set e Gate 3 solo per Python**, con il limite dichiarato; nel resto del prodotto non cambia nulla. Scartate: aggiungere prima regole SAST per JavaScript (con la verifica di licenza di ADR-0015 se di terzi), e un golden set misto | — |

**Linguaggi.** Il corpus copre solo Python e JavaScript/TypeScript, l'ambito dell'MVP (§1); gli altri sono di Fase 4 (§13). Un risultato del Gate 3 vale solo per i linguaggi presenti nel test: ogni linguaggio aggiunto richiede nuove etichette e una nuova misura.

**Onda 1, stato al 2026-11-27:** formato, contratti, campionamento e interfaccia di annotazione sono pronti e il campione pilota di 30 voci è estratto (V-F3.7). ADR-0034 è accettato. Il primo pilota è annotato (V-F3.8): con la quota osservata il test del gate non si comporrebbe, e i tempi sono molto sotto l'ipotesi. G3-04 resta aperto. Dopo il secondo pilota una revisione ha trovato difetti nella pagina e criteri incompleti (V-F3.14): corretti, si annota un terzo pilota, poi riannotato per la stabilità. Prima della calibrazione va corretto il campionamento. L'interfaccia è provata solo con dati finti: la prova sul pilota, che G3-03 richiede, è la sua annotazione.

## 7. Rischi

| Rischio | Segnale | Risposta |
| --- | --- | --- |
| Laya non funziona sul codice, anche dopo l'addestramento | E3-01, E3-02 | Basi di confronto e un modello generativo locale dietro la stessa interfaccia; il gate può restare non superato |
| Etichette insufficienti o annotatore non disponibile | G3-04 | Ridurre l'ambito a SAST; non abbassare la soglia dopo aver visto i risultati |
| Pochi falsi positivi nel corpus | V3-02, G3-04 | Campionamento stratificato per regola, dichiarato; la distribuzione del test resta indicata |
| L'evidenza non sta in 512–1.024 token | DE-02 | Checkpoint con contesto più lungo, o evidenza ridotta e dichiarata |
| Modelli generativi locali troppo deboli per correggere | V3-05 | Agenti limitati agli aggiornamenti di dipendenze |
| Un pacchetto cambia licenza o interfaccia | V3-01 | Versione e pesi fissati; aggiornamenti con nuova verifica |

## 8. Fuori ambito

Fase 7 con telemetria e fase 6 oltre al gate CI già esistente; VEX e pgvector finché nessun task li richiede; `JevEngine` e provider esterni (ADR-0033); `JevosEngine` finché non si trova la sua fonte; laya-mlx (solo Apple Silicon).

## 9. Riporti aperti dalla Fase 2

Non fanno parte della Fase 3 e non la bloccano, salvo dove detto: D2-14, D2-16, I-04, I-07, N-09, E-05; N-07 e N-08 (D2-12); I-06 (D2-06); **l'ordinamento non validato** (una correzione del punteggio delle dipendenze va provata su campioni nuovi, ADR-0031); il confronto con le pubblicazioni. La nuova valutazione di D-0015 dopo il cambio di licenza (ADR-0032) resta condizione per distribuire immagini, e va estesa ai pesi dei modelli.
