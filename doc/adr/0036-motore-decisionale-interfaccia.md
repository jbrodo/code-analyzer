# ADR-0036: Motore decisionale, interfaccia e instradamento

- Stato: Accettato il 2026-11-27 dall'utente
- Data: 2026-11-27
- Decisione umana richiesta: sì (D3-04, D3-05 e il confronto di G3.c), presa il 2026-11-27
- Riferimenti: §2, §3, §10; ADR-0001, 0003, 0016, 0033, 0034; `doc/plan/fase-3.md`

## Contesto

§10 descrive un'interfaccia `DecisionEngine`, sei domande e un instradamento con tre esiti. Il piano chiede di fissarla prima di DE-01, che si costruisce con un motore finto: nessuna scelta qui dipende dal motore vero, che si decide in V3-06. Che un motore locale sappia fare il triage non è misurato.

## Decisione

### Dove stanno le cose

| Cosa | Dove |
| --- | --- |
| Modello `Decision` ed evidenza, con contratto in `schemas/` | `ca_core.models.decision` (ADR-0003) |
| Porta `DecisionEngine` | `ca_core.ports` |
| Motore finto, instradamento, poi selezione dell'evidenza e adattatori | pacchetto `ca-decision`, che importa solo `ca-core` |
| Basi di confronto e misure del gate | `golden-set/eval/` (§3, §14) |

§10.1 mette l'interfaccia in `ca-decision`; ADR-0001 mette le porte in `ca-core`. **Vale ADR-0001.** Un contratto nuovo di `import-linter` vieta a `ca_decision` rete, processi e gli altri pacchetti. Chi esegue il modello vero, in un processo senza rete, è materia di ADR-0035 e può richiedere di cambiare quel contratto.

### Prima fetta

Una sola domanda, `is_true_positive`, di tipo `boolean`, sui finding SAST di Python (ADR-0034). La firma di §10.1 resta, con `kind` e `options`, ma le altre cinque domande, `choice` e `score` si realizzano quando avranno etichette e un uso.

### `Decision`

I campi di §10.1, con questi vincoli, controllati dal modello:
- per `boolean` le chiavi di `probabilities` sono esattamente `true` e `false`; valori tra 0 e 1, somma 1 entro 0,001;
- `confidence` è tra 0 e 1. È il valore **dichiarato dal motore**, non una probabilità calibrata: la calibrazione si misura (E3-03);
- `model_version` identifica i pesi per digest; il motore finto si dichiara tale in `model`.

«true» vuol dire «vero» nel senso di ADR-0034. Il motore non ha una risposta «non so»: rinunciare è compito dell'instradamento.

### Errori ed evidenza

- Se non può rispondere, il motore solleva un errore tipizzato: non restituisce una decisione di ripiego.
- **Niente troncamenti silenziosi.** Un'evidenza oltre il limite del motore è un errore. Chi la seleziona (DE-02) la riduce prima e dichiara di averlo fatto.
- Errori e log non riportano l'evidenza.

### Instradamento (D3-05)

`route` ha due soli esiti: **`suggerimento`** se `confidence` raggiunge la soglia della domanda, altrimenti **`umano`**.
- `auto` non esiste: nessun suggerimento cambia stato, livello, punteggio o gate. Non è un esito spento da configurazione: il codice non lo ha.
- `llm_agent` di §10.3 si aggiunge quando esisteranno gli agenti.
- Le soglie stanno in un file di configurazione del prodotto, per `question_id` e versione del modello (§14, regola 3 di `AGENTS.md`). **Non** si leggono da `.code-analyzer.yml`. Senza una soglia calibrata per quel modello l'esito è sempre `umano`.

### Dove gira (D3-04)

Solo nella CLI, spento per default, su richiesta esplicita da riga di comando. Il server non ha il codice (ADR-0016). Finché il gate non passa, le decisioni non entrano nel report né in API, database o interfaccia (E3-05): le usa solo la valutazione. La tabella `decisions` di §5 resta per allora.

### Misure del Gate 3: precisazione di ADR-0034

- «Decise» sono le voci del test instradate a `suggerimento`; la copertura è la loro quota tra quelle con risposta «vero» o «falso positivo».
- **G3.c si calcola sulle voci decise dal motore, per il motore e per le basi di confronto**, così il paragone è sugli stessi esempi. Si riportano anche i valori delle basi su tutto il test. L'alternativa, costringere il motore a rispondere su tutto, misura un uso che il prodotto non fa.
- Le basi di confronto si costruiscono con le sole etichette di addestramento. Per una `rule_id` mai vista, la regola per `rule_id` risponde con la classe di maggioranza.
- Se tra le voci decise manca una delle due classi, il gate non è superato.
- Intervalli di Wilson al 95% per precisione e copertura.

## Conseguenze

- DE-01 si può scrivere e provare senza modelli, pesi o etichette.
- `ca-cli` potrà importare `ca-decision` solo al cablaggio (DE-04), con un emendamento ad ADR-0001.
- Un confronto sulle sole voci decise non dice quanto il motore valga su quelle che rimanda: per questo la copertura minima resta una condizione a sé.

## Emendamento del 2026-11-27: evidenza (DE-02)

### Approvato dall'utente prima di scrivere il codice

1. Se il file del finding ha un finding di segreti, il motore non riceve codice di quel file: decide l'umano.
2. Se la ricerca dei segreti non è riuscita in quella scansione, il motore non riceve **nessun** codice.
3. Anche nei file senza segnalazioni si oscura ciò che somiglia a una credenziale.

Nessun controllo riconosce ogni segreto.

### Aggiunto scrivendo il codice: temporaneo

4. Se un finding di segreti indica un percorso che **nel commit non c'è**, il motore non riceve nessun codice. gitleaks legge la storia git: dopo una rinomina senza modifiche il contenuto compare solo col nome vecchio (provato il 2026-11-27 con `git log` su un repository di prova, con le opzioni di gitleaks ma senza eseguirlo), quindi il file che oggi lo contiene risulta pulito. Il costo è alto per i repository con segreti in file cancellati; quanto sia frequente **non è misurato** (`doc/verifiche/fase-3.md`, V-F3.10).

**La regola 4 non basta:** se dopo la rinomina nasce un file nuovo col nome vecchio, il percorso segnalato esiste, la regola non scatta e il file rinominato sembra pulito.

### Deciso dall'utente il 2026-11-27: cercare i segreti anche nei file del commit

- In DE-04, oltre alla ricerca sulla storia, si cercano i segreti nei **file esatti del commit, senza storia** (la modalità sui soli file che il plugin ha già). I loro finding bloccano il file in cui il contenuto sta adesso.
- Se questa ricerca non riesce, **nessun** codice va al motore. Con un `.gitleaksignore` nella radice la modalità sui soli file fallisce, quindi quel repository non ha evidenza.
- La regola 4 resta finché la ricerca non c'è. **Si toglie solo** dopo prove con gitleaks vero che coprano la rinomina semplice e il riuso del vecchio nome.
- Non misurati: tempo e memoria della seconda ricerca. Restano i limiti di riconoscimento di gitleaks, compresi i file che la sua configurazione predefinita salta.

### Come è fatta

- Solo finding SAST, escluse le regole che segnalano segreti. Contano i finding di segreti di qualunque stato, e le posizioni raccolte dalla deduplicazione.
- L'oscuramento lavora sul file intero e sul messaggio del tool; ogni riga toccata porta il segno, e il numero di righe non cambia.
- L'evidenza è: regola, messaggio, percorso e fino a 20 righe prima e dopo. Oltre il limite si restringe la finestra e si dichiara `reduced`; se non entrano nemmeno le righe del finding, non si dà nulla. Il limite è in **caratteri** (3200): quanti token siano per il motore vero si verifica in DE-04, e il motore rifiuta ciò che non gli sta.
- Espressioni, soglie e limiti stanno in `ca_decision/evidence.json` (contratto `evidence-settings`), mai in `.code-analyzer.yml`.

### Cosa DE-04 deve garantire

- La ricerca dei segreti sui file del commit descritta sopra, prima di ogni evidenza.
- Il testo passato è quello del **file al commit del report**. Con `.git`, la ricerca dei segreti non vede le modifiche non registrate.
- Un file diverso dal commit non produce evidenza.

### Limiti

- Un segreto in una forma non prevista passa. Restano fuori anche i contenuti introdotti solo nella risoluzione di un merge, che la lettura della storia con le opzioni di gitleaks non mostra (dal comportamento di git, non provato qui), e le regole che la configurazione predefinita di gitleaks salta per percorso o parola.
- In un clone senza storia completa gitleaks vede meno: l'avviso del report resta valido.
