# ADR-0033: Niente modelli esterni

- Stato: Accettato il 2026-11-27 dall'utente
- Data: 2026-11-27
- Decisione umana richiesta: sì (§18, fornitori di modelli ammessi), presa il 2026-11-27
- Riferimenti: §2, §10, §11.4, §15, §18; ADR-0006, 0014, 0016; `doc/plan/fase-3.md`

## Contesto

§2 prevede modelli generativi «a zero retention o self-hosted» e un motore decisionale con un'alternativa gestita via API (`JevEngine`). La Fase 3 passa ai modelli frammenti del codice analizzato, percorsi e messaggi dei finding. L'utente ha deciso: «non uso modelli esterni, il codice non deve uscire dalla mia macchina», e ha chiarito che vale per il solo prodotto.

## Decisione

1. Il prodotto usa **solo modelli eseguiti sulla macchina che esegue l'analisi**. Codice, frammenti, percorsi, messaggi dei finding e prompt che li contengono non si inviano ad API di modelli di terzi, nemmeno con conservazione dichiarata nulla.
2. `JevEngine` e i provider a zero retention escono dall'ambito.
3. La regola non riguarda gli strumenti con cui il prodotto si sviluppa.
4. Come garantirla (processo senza rete, pesi scaricati a parte e fissati per digest, indirizzo del modello non letto dal repository) si decide con l'ADR sull'esecuzione dei modelli. Fino ad allora nel prodotto non c'è codice che chiami un modello.

## Conseguenze

- La qualità del triage e delle correzioni è limitata da ciò che gira sull'hardware di chi analizza. Non è verificata.
- Chi esegue la CLI in una CI ospitata ha il codice sulla macchina del fornitore della CI: questa decisione non lo cambia. Se lì il motore possa girare è D3-04 del piano.
- Il valore `llm_provider` di `.code-analyzer.yml` resta senza effetto. Quando ne avrà, non potrà scegliere un provider esterno; il contratto si aggiorna allora, con i suoi test.
- Riaprire la scelta richiede un nuovo ADR.
