# ADR-0006: Database delle vulnerabilità in Fase 1

- Stato: Proposto
- Data: 2026-11-08
- Decisione umana richiesta: sì (flusso dei dati verso l'esterno)
- Riferimenti: §7.1, §7.2, §13, §15, §16 regola 7

## Contesto

Lacuna non elencata. osv-scanner e trivy sono in Fase 1 e hanno bisogno di un database di vulnerabilità. §7.2 ammette solo `none` o `feeds-only` verso "mirror interni", ma i mirror sono previsti in Fase 2. Così com'è, in Fase 1 questi due plugin non possono funzionare.

## Opzioni

1. **Rete verso gli endpoint pubblici durante la scansione.** Semplice, ma il plugin ha insieme sorgenti e rete, l'allowlist richiede un proxy di uscita e l'elenco dei pacchetti esce dal perimetro.
2. **Database incorporato nell'immagine.** Coperto dalla firma e senza rete, ma richiede ricostruzioni giornaliere e confligge con il digest fissato nella CLI.
3. **Sincronizzazione separata:** un passo con rete ma senza sorgenti scarica lo snapshot, poi la scansione lo monta in sola lettura e gira senza rete.
4. **Anticipare i mirror di Fase 2.** Aggiunge infrastruttura non necessaria a una CLI.

## Raccomandazione

Opzione 3, con l'invariante: **un container può avere il codice o la rete, mai entrambi**.

- Il manifest ha un blocco opzionale `feeds` con il comando di sincronizzazione e il percorso di montaggio (`/feeds`). `network` resta `none` per la scansione.
- La sincronizzazione usa la stessa immagine firmata del plugin, senza workspace né dati derivati dal repository.
- Snapshot in una cache per utente, riutilizzabile come cache CI. `scan` sincronizza se manca o è più vecchio di una soglia configurabile; `--offline` lo impedisce.
- Sincronizzazione fallita: si usa lo snapshot precedente con un avviso. Se non esiste alcuno snapshot, il plugin fallisce e la scansione è parziale.
- Il report registra origine e data dello snapshot per ogni plugin.
- Test: nessuna rete (§16); si usa uno snapshot congelato preparato da un job CI separato.
- In Fase 2 i mirror cambiano solo l'origine della sincronizzazione.

Le opzioni offline di osv-scanner e trivy vanno verificate sulle versioni fissate prima di chiudere il task.

## Conseguenze

- Durante la scansione non esce alcun dato sul codice o sulle dipendenze; la sincronizzazione scarica soltanto.
- Lo schema manifest cambia rispetto a §7.1, e `feeds-only` non viene usato in Fase 1.
- Uno snapshot avvelenato produrrebbe falsi negativi; i database non hanno sempre una firma propria. Rischio accettato per la Fase 1, da rivedere con i mirror.
