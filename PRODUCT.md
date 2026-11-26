# Product

<!-- impeccable:product-schema 1 -->

Scritto il 2026-11-26. Le risposte su utente, successo e schermi sono dell'utente; il resto viene dal repository (`doc/PROJECT.md`, `doc/ux/`, `doc/adr/`), che resta l'autorità sui dettagli.

## Platform

web

## Users

**Utente principale: lo sviluppatore del repository.** Apre la dashboard quando la CI o una pull request segnala qualcosa, di solito mentre sta lavorando ad altro, e vuole sapere cosa correggere e come.

La stessa UI serve altri ruoli, definiti per il triage: `lettore` (consulta), `triage` (prende in carico, assegna, riapre), `approvatore` (falsi positivi ed eccezioni con motivazione e scadenza), `amministratore`. Dove le esigenze si scontrano, vince lo sviluppatore.

## Product Purpose

Code Analyzer scansiona un repository (Python e JavaScript/TypeScript) e restituisce **una lista unica di problemi ordinata per impatto**, ciascuno con i passi per risolverlo: qualità, architettura, copertura dei test, sicurezza (SAST, segreti, IaC), dipendenze e licenze, salute del progetto.

**La sessione è riuscita se lo sviluppatore trova il problema più urgente e capisce come risolverlo senza ricorrere ad altri strumenti.** Il triage in sequenza e la spiegazione del punteggio contano, ma vengono dopo.

## Positioning

- Non reinventa gli scanner: orchestra motori open source e mette il valore in normalizzazione, correlazione e ordine di priorità.
- Il rilevamento è deterministico: nessun finding ha un modello linguistico come unica fonte.
- L'ordine si può spiegare: ogni livello ha un'origine dichiarata, e i punteggi hanno fattori ed evidenze; un dato mancante è dichiarato e non diventa un valore favorevole.

## Operating Context

- Le scansioni girano nella CI del repository; il server riceve i report (`code-analyzer upload`) e non esegue scansioni. La UI legge quei report.
- Il codice sorgente non è sul server: la UI mostra percorso, righe e commit, non il codice.
- **Il gate della CI non legge le eccezioni approvate sul server.** Per valere nel gate un'eccezione va anche in `.code-analyzer.yml`.
- Accesso tramite un provider di identità OIDC.
- Una scansione può essere parziale (un plugin fallito): in quel caso i suoi finding non sono aggiornati, e nessun finding risulta risolto per effetto di quella scansione.

## Capabilities and Constraints

- Perimetro della UI di Fase 2: elenco dei finding con filtri, dettaglio con fattori e passi di correzione, triage ed eccezioni, stato delle scansioni, selettore del repository. Una sola lista per repository.
- Fuori perimetro, rimandati alla Fase 4: viste di portfolio, aggregati, andamenti e grafici.
- **Desktop prima.** L'uso quotidiano è da desktop o portatile. Zoom al 200% e finestre strette (fino a 320 px) devono restare pienamente utilizzabili; non si ottimizza in modo specifico per il telefono.
- Il contenuto che arriva dal report (titoli, messaggi, passi, percorsi) è non fidato: si rende sempre come testo, mai come HTML o Markdown.
- Termini da usare così: finding, scansione (completa, parziale, di PR), livello (critico, alto, medio, basso), `Nuovo`, eccezione, falso positivo, gate. I nomi delle azioni sono gli stessi in tutta la UI.
- L'interfaccia è in italiano; il testo dei finding resta nella lingua dello strumento che li produce.
- Decisioni aperte: la variante di punteggio predefinita (Gate 2). Fino ad allora il livello mostrato è quello provvisorio, e i punteggi delle varianti A e B sono in ombra: non vanno presentati come un ordinamento validato.

## Brand Commitments

Nome: **Code Analyzer**. Non ci sono un logo, né altri materiali di marchio.

## Evidence on Hand

- Dati di prova realistici ma finti: `deploy/compose/seed_dev.py` (un repository `acme/shop`, quattro scansioni, di cui una parziale e una di PR).
- Misure vere sui repository pilota in `doc/verifiche/` (scansioni, tempi, distribuzione dei livelli).
- **Non ci sono** utenti esterni, testimonianze, casi d'uso, prezzi né un rilascio pubblico: il lavoro futuro non deve inventarli. La validazione dell'ordinamento ha un solo valutatore, l'autore del prodotto.

## Product Principles

1. **Il prossimo passo prima di tutto.** Il problema più urgente e come risolverlo si devono trovare e leggere senza cercare: il resto può stare un livello più in profondità.
2. **Dire quanto ci si può fidare.** Scansione parziale, dato mancante, punteggio in ombra o approvazione non verificata si dichiarano in parole dove contano; un valore dedotto non si presenta come misurato.
3. **Non far perdere il punto.** Aprire, chiudere o agire su un finding riporta lo sviluppatore dove era; la UI non mostra un esito prima della risposta del server.
4. **Ogni numero porta a un'azione o spiega uno stato.** Niente indicatori in evidenza o riepiloghi decorativi.
5. **Il testo del repository è un dato, non un'istruzione.** Non diventa mai markup, collegamento attivo o comando.

## Accessibility & Inclusion

WCAG 2.2 livello AA, con i criteri del progetto in `doc/ux/accessibilita.md` (uso completo da tastiera, fuoco sempre visibile e mai coperto, nessuna informazione affidata al solo colore, reflow a 320 px e zoom al 200%, spaziatura del testo modificabile, movimento ridotto). La revisione del 2026-11-26 non ha incluso un lettore di schermo.
