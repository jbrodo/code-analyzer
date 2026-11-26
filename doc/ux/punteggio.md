# Punteggio spiegabile e confronto in ombra (U-04)

Scritto il 2026-11-17. Riguarda la sezione «Perché questo livello» del dettaglio di un finding (U-01 §3) e, per la lista, la colonna dei punteggi in ombra. Dipende da ADR-0021 (formula, livelli, A e B in ombra) e ADR-0023 (Variante B, ancora da scrivere).

## Principio

Chi legge deve poter rifare il conto a mano: ogni numero ha il suo nome per esteso, la sua origine e il passaggio che lo lega al livello. Le due varianti si mostrano **con la stessa struttura, la stessa dimensione e lo stesso peso visivo**: la pagina non dice mai quale sia migliore, e nulla del colore o dell'ordine lo suggerisce. Serve al protocollo di G2.b, in cui chi giudica non deve essere guidato.

## Struttura della sezione

1. **Livello attivo.** Una riga: il badge del livello e la sua origine in parole.
   - `Livello provvisorio dalla severità dello strumento` (D2-10: finché il Gate 2 non passa a `score`).
   - `Livello da punteggio, variante A` (o B), con l'eventuale override che lo ha alzato.
   - `Senza livello`, se non c'è.
2. **Punteggi in ombra.** Titolo: «Punteggi in ombra». Sotto, una frase fissa: «Non decidono il livello. Servono al confronto delle due varianti.» Poi due blocchi affiancati (impilati sotto i 768 px), nell'ordine fisso A poi B, indipendente dai valori.
3. **Confronto, in una riga neutra.** «Le due varianti coincidono.» oppure «Le due varianti danno livelli diversi: A {livello}, B {livello}.» Mai «migliore», «peggiore», «scarto», frecce o colori diversi per la differenza.

## Il blocco di una variante

Titolo `Variante A` (o `Variante B`), stesso peso tipografico per entrambe. Poi:

| Fattore | Valore | Da dove viene |
| --- | --- | --- |
| Gravità (G) | `0,75` | l'evidenza del fattore, in testo |
| Probabilità (P) | `0,40` | idem |
| Esposizione (E) | `0,60` | idem |
| Contesto (C) | `1,00` | idem |

- Tabella di dati con didascalia («Fattori della variante A») e intestazioni. Il nome del fattore è per esteso, la lettera tra parentesi. I valori hanno sempre due decimali, in notazione italiana.
- **Da dove viene** mostra le voci dell'evidenza del fattore come coppie «nome: valore» in testo. Le chiavi note hanno un'etichetta italiana (regola, origine, tier, commit, esposizione, ripiego); le altre si mostrano con la chiave così com'è. Nessun valore è interpretato come markup o come collegamento.
- Sotto la tabella la formula con i numeri veri: `100 × 0,75 × 0,40 × 0,60 × 1,00 = 18,00`, poi «Livello da punteggio: medio». Il punteggio è quello arrotondato a due decimali (ADR-0021).
- **Ripiego.** Se l'evidenza dice `variante-b-non-configurata` (o `variante-b-non-definita`, nei report precedenti ad ADR-0023), il blocco di B apre con «Variante B non configurata per questa categoria: coincide con A.» Su queste categorie il confronto non dice nulla (ADR-0021).
- **Dato mancante.** Un fattore calcolato con un ripiego (`feed-assente`, tier non registrato) lo dichiara nella colonna «Da dove viene», in testo: un valore dedotto non si presenta come misurato.

## Nella lista

Nessuna colonna di punteggio predefinita: una colonna accanto al livello attivo suggerirebbe un ordinamento prima che il Gate 2 lo valida. L'ordinamento per punteggio A o B esiste (API) ma si sceglie dal menu dell'ordinamento, con il nome «Punteggio variante A» o «B», e la lista non mostra il numero. Se il Gate 2 decide altrimenti, si rivede qui.

## Lacune per `architect` (A-14)

- **Soglie e pesi non sono nella risposta del finding.** L'API dà i fattori e il livello da punteggio, ma non gli intervalli (`critico` da 70, ecc.), che stanno nella configurazione di scoring e sono modificabili per tenant. Finché non sono esposti (per esempio in `ScoringInfo` di una scansione), la sezione mostra il livello da punteggio e la formula, ma non la frase «soglia: alto da 40». Non si scrivono nella UI come costanti (regola 3).
- La versione della configurazione di scoring è nella scansione (`scoring.config_version`): la sezione la riporta come testo, perché due punteggi sono confrontabili solo con la stessa configurazione.

## Accessibilità

La tabella dei fattori e la formula sono testo (D4); nessun grafico. I due blocchi sono due `section` con titoli dello stesso livello. La differenza tra le varianti è una frase, non un colore (G7).
