# ADR-0036: Motore decisionale, interfaccia e instradamento

- Stato: Proposto
- Data: 2026-11-27
- Decisione umana richiesta: sì (D3-04, D3-05 e il confronto di G3.c)
- Riferimenti: §2, §3, §10; ADR-0001, 0003, 0016, 0033, 0034; `doc/plan/fase-3.md`

## Contesto

§10 descrive un'interfaccia `DecisionEngine`, sei domande e un instradamento con tre esiti. Il piano chiede di fissarla prima di DE-01, che si costruisce con un motore finto: nessuna scelta qui dipende dal motore vero, che si decide in V3-06. Che un motore locale sappia fare il triage non è misurato.

## Decisione proposta

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
