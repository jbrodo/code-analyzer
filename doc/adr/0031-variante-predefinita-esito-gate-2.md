# ADR-0031: Variante di scoring predefinita, esito del Gate 2

- Stato: Accettato il 2026-11-27 dall'utente
- Data: 2026-11-27
- Decisione umana richiesta: sì (§18, G2.c), presa il 2026-11-27
- Riferimenti: §6, §13, §18; ADR-0009, 0021, 0023; D2-03, D2-10, D2-11; protocollo, regola di scelta, X-04, X-06 e X-08 in `doc/verifiche/gate-2.md`

## Contesto

Il Gate 2 doveva validare l'ordinamento delle Varianti A e B su quello di chi usa lo strumento e scegliere la variante predefinita. Il 2026-11-26, prima di qualunque ordinamento, l'utente ha approvato la regola di scelta: è candidata solo una variante che supera la soglia (tau-b ≥ 0,5 e 6 dei primi 10 in comune) su tutti i repository; se nessuna lo è, il gate resta sui livelli provvisori, A resta predefinita in via provvisoria e G2.b si dichiara non superata.

Sui tre repository dell'utente (campioni di 30, ordinati alla cieca) il tau-b di A va da −0,584 a −0,310 e quello di B da −0,574 a −0,250; nei primi 10 in comune ne hanno al massimo 1. Nessuna delle due supera la soglia su alcun repository. I livelli provvisori hanno tau-b 0,385, 0,548 e 0,694, e non superano la soglia sul primo.

## Decisione

1. **Nessuna variante è scelta come validata.** A resta predefinita in via provvisoria (il campo `variant` della configurazione di scoring).
2. **Livelli e gate restano provvisori** (`levels.source: provisional`, ADR-0009). A e B si calcolano entrambe e restano in ombra. Interfaccia e documenti non le presentano come un ordinamento validato, e nemmeno i livelli provvisori.
3. **In Fase 2 formule, pesi e soglie non si cambiano sulla base di questi tre ordinamenti.** Una correzione che parta da qui si può sviluppare su di essi, ma si prova su campioni nuovi (seme o repository diversi), ordinati prima di vederne i punteggi, con la regola di scelta scritta prima.

## Da dove viene il risultato

Analisi fatta dopo il risultato, esplorativa (dettagli in X-04). In tutti e tre i campioni il proprietario ha messo in prima posizione tutti e soli i finding sulle dipendenze, che A e B mettono in fondo: per una dipendenza fuori da KEV, P è la probabilità EPSS (mediana 0,01), mentre per `quality` in A è il percentile di churn del file (minimo 0,1). Il prodotto G·P·E·C confronta tra categorie grandezze diverse. Il comportamento è quello di §6 e di ADR-0021. Togliendo le dipendenze A e B restano sotto la soglia (tau-b al massimo 0,417): il confronto tra categorie non è l'unico problema.

Domande da affrontare in un eventuale lavoro successivo, **non decise qui**: come rendere confrontabile P tra categorie; se l'ordine debba partire dalla categoria o dal livello e usare il punteggio solo al loro interno; quali segnali ordinino le dipendenze tra loro, che questi campioni non distinguono.

## Opzioni scartate

- **Scegliere B** per il tau-b medio più alto di 0,032: nessuna è candidata, e lo scarto è sotto lo 0,05 della regola.
- **Correggere P per le dipendenze e ricalcolare sugli stessi campioni:** sarebbe una taratura sulla valutazione, e il risultato non proverebbe niente.
- **Presentare i livelli provvisori come validati** perché ordinano meglio: non superano la soglia su un repository, e in un altro la loro sovrapposizione sui primi 10 va da 1 a 10 secondo come si risolvono i pari merito.

## Conseguenze

- Il Gate 2 non è superato (X-08). Se e come chiudere la Fase 2 con G2.b non superata si decide in X-09.
- Gli override e il limite dal CVSS per le dipendenze (ADR-0021) hanno effetto solo con `levels.source: score`, che resta spento.
- La semplificazione di `runner.py` richiesta nel caso di scelta di B (X-07) non serve.
- ADR-0023 resta `Proposto` per le sue ragioni (confronto con le pubblicazioni).
- La validazione ha un solo valutatore, autore del prodotto: anche un esito positivo futuro andrebbe rivalidato con altri utenti.
