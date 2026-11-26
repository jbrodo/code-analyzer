# Design token e componenti di base (U-02)

Scritto il 2026-11-13. I token sono in `doc/ux/tokens.json`, nel formato del Design Tokens Community Group, leggibile da `frontend` senza trascrizione: W-01 ne genera le proprietà CSS. I contrasti si verificano con `python doc/ux/check_tokens.py`, che gira anche nei test.

## Direzione

Uno strumento di lavoro, non una vetrina: molte righe leggibili insieme, nessun elemento decorativo, colore usato solo dove porta significato (livello, stato, fuoco, azione principale). Tutto il resto è una scala di grigi freddi.

- **Tipografia:** carattere di sistema; nessun font da scaricare. Monospazio per ciò che si copia o si confronta carattere per carattere: percorsi, regole, fingerprint, versioni, commit.
- **Densità:** testo di base a 14 px (`size-md`), righe della tabella da 36 px. Sotto i 13 px (`size-sm`) si scende solo per le etichette secondarie (`size-xs`, 12 px), mai per il contenuto.
- **Temi:** chiaro e scuro, scelti da `prefers-color-scheme`. Ogni colore ha i due valori; nessun componente usa un colore fuori dai token.
- **Movimento:** solo l'apertura del pannello e dei dialoghi, 120 ms, disattivata con `prefers-reduced-motion`.

## Token

| Gruppo | Uso |
| --- | --- |
| `color.*.bg`, `bg-subtle`, `bg-row-selected` | Sfondo della pagina; intestazioni di tabella e barra superiore; riga con il fuoco o selezionata |
| `color.*.text`, `text-muted` | Contenuto; etichette secondarie. Entrambi a contrasto 4,5:1 su tutti e tre gli sfondi |
| `color.*.border`, `border-control` | Separatori; bordo dei campi e dei controlli (3:1 sugli sfondi) |
| `color.*.accent`, `accent-text` | Collegamenti e azione principale di una vista. Una sola azione principale per vista |
| `color.*.focus` | Indicatore del fuoco: 2 px, staccato di 2 px dal controllo |
| `color.*.danger` | Testo degli errori e azione distruttiva |
| `color.*.level-{livello}-bg` e `-text` | Badge dei quattro livelli. Coppie verificate a 4,5:1 |
| `color.*.status-*` | Esito riuscito; avvisi e fascia di scansione parziale |
| `font.*`, `space.*`, `radius.*`, `border.*`, `motion.*` | Scale di tipografia, spaziatura (passo di 4 px), raggi, bordi, durata |
| `size.*` | Altezza di righe e controlli, bersaglio minimo di 24 px, larghezza del pannello (480 px), soglia sotto la quale il pannello sostituisce la lista (768 px) |

I livelli usano quattro tinte distinte anche in scala di grigi per luminosità del testo, ma il colore non è mai l'unico segnale: il badge contiene la parola.

## Componenti di base

### Integrazione shadcn/ui

Scelta confermata il 2026-11-16: registry ufficiale `@shadcn`, base Radix,
stile Nova (`radix-nova`), nella SPA React/TypeScript/Vite esistente.
`web/components.json` configura la CLI; non e un catalogo `registry.json`
per pubblicare componenti del prodotto.

Tailwind CSS 4 usa il plugin Vite. In `web/src/styles/base.css` le variabili
semantiche shadcn sono alias dei token generati da `web/scripts/tokens.mjs`:
nessuna seconda palette, font scaricato o tema `.dark`. Il tema continua a
seguire `prefers-color-scheme`; anche le varianti `dark:` usano questa preferenza.
Tipografia, spaziatura e raggi riusano le scale del prodotto.

L'inizializzazione non aggiunge viste o componenti dimostrativi. Per aggiungere
un componente, dalla directory `web/`, consultare prima
`rtk bypass bunx --bun shadcn@latest docs <componente>` e gli URL restituiti,
poi usare `search`, `view` e `add` sul registry ufficiale. Leggere il codice
aggiunto e mantenere i requisiti seguenti; lo stile upstream non li sostituisce.

Ogni componente elenca struttura, stati e i criteri di `doc/ux/accessibilita.md` che deve soddisfare.

### Badge di livello

- Testo: `Critico`, `Alto`, `Medio`, `Basso`. Sfondo e testo dai token del livello. Larghezza fissa sul testo più lungo, così la colonna resta allineata.
- Un finding senza livello mostra `Senza livello` con i colori di `basso`.
- Nessuna icona, nessuna variante solo colore. Criteri: G7, L6.

### Badge di stato e di novità

- Stato: testo semplice con `text-muted` per `aperto`; `in corso`, `accettato`, `falso positivo`, `risolto` con lo stesso stile e la parola. Per `accettato` una seconda riga piccola dice l'origine e la scadenza.
- `Nuovo`: testo in `accent`, peso medio. Criteri: G7, L7.

### Tabella densa

- `table` con intestazione fissa durante lo scorrimento, righe alte almeno `size.row-height`, separatore `border` tra le righe, nessuna riga alternata.
- Colonne con larghezza stabile; `Problema` prende lo spazio restante e la tabella ha una larghezza minima, così non si schiaccia. Titolo e percorso vanno fino a due righe prima di tagliare (tre per il titolo quando la regione è stretta, 30rem o meno): la riga cresce quando serve, perché trovare e leggere il problema viene prima della densità (`PRODUCT.md`). Il percorso si tronca al centro, mai alla fine. Nella regione stretta livello e `Problema` riempiono la prima vista. (Modifica del 2026-11-27, da U-05.)
- Stati della riga: normale; con il puntatore sopra (`bg-subtle`); con il fuoco (indicatore di fuoco sull'intera riga); aperta nel pannello (`bg-row-selected` e una barra di 2 px in `accent` sul bordo iniziale, che non dipende dal solo colore di sfondo).
- Intestazione ordinabile: pulsante con il nome della colonna e il verso.
- In fondo: pulsante "Carica altri" e conteggio "50 di 312".
- Caricamento: righe segnaposto della stessa altezza. Vuoto ed errore: testo al posto del corpo della tabella, con l'azione di rimedio.
- Regione scorrevole in orizzontale sotto la larghezza minima, raggiungibile da tastiera; con il fuoco sulla regione, frecce, `j`, `k`, `Home` portano alla prima riga, `End` all'ultima, `/` alla ricerca. Criteri: L1..L5, L8, L9, L12, L13, G8.
- Sotto i 48rem di larghezza o i 32rem di altezza (zoom 200% compreso) la barra superiore non è fissa: scorre via.
- Nelle azioni del pannello c'è un solo pulsante in `accent`, `Prendi in carico`.

### Filtri

- Una riga sopra la tabella: ricerca, poi un controllo per filtro (livello, categoria, stato, strumento) con scelta multipla, poi l'interruttore "Solo nuovi".
- Sotto, i filtri attivi come pulsanti "Rimuovi filtro …", "Azzera filtri" e il numero di finding risultante.
- Ogni cambio aggiorna l'indirizzo della pagina. Criteri: L10, L11.

### Pannello di dettaglio

- Regione a destra larga `size.panel-width`, separata da `border`; sotto `size.breakpoint-narrow` occupa la pagina, con "Torna alla lista".
- Intestazione fissa con livello, titolo e pulsante di chiusura; corpo scorrevole con le sezioni di U-01; azioni fisse in fondo.
- Sezione: intestazione `size-lg` semibold, contenuto a `line-height-text`. I valori tecnici in monospazio, con un pulsante "Copia" dove ha senso (percorso, fingerprint).
- Coppie etichetta e valore come elenco di definizioni. Criteri: D1..D7.

### Dialogo

- Modale centrato, larghezza massima 32 rem, sfondo della pagina oscurato.
- Titolo, testo, campi, e in fondo due pulsanti: l'azione a destra con il verbo dell'azione ("Accetta con eccezione"), "Annulla" a sinistra. Mai "OK".
- L'azione distruttiva o irreversibile usa `danger`; le altre `accent`. Criteri: T1..T8.

### Campi e pulsanti

- Altezza `size.control-height`, bordo `border-control`, etichetta sopra il campo, messaggio di errore sotto in `danger` con il testo che dice cosa correggere.
- Pulsante principale pieno in `accent`; secondario con bordo; terziario solo testo. Disattivato: contrasto ridotto ma con il motivo disponibile (D6).
- Bersaglio minimo `size.target-min`. Criteri: G5, G10, T3, T5.

### Fascia di avviso

- Testo su `status-warn-bg`, larghezza piena sopra la tabella, con un collegamento. Usata solo per la scansione parziale e per l'errore di caricamento. Non si chiude: sparisce quando la causa sparisce. Criterio: L14.

### Regione di stato

- Elemento non visibile con `role="status"`, unico per pagina, in cui i componenti scrivono gli annunci: numero di risultati, righe caricate, esito di un'azione, copia avvenuta. Criteri: L9, L10, T7.

## Cosa non c'è

Grafici, indicatori numerici in evidenza, schede riassuntive, icone di categoria, avatar, notifiche a comparsa che spariscono da sole. Se una vista della Fase 2 sembra averne bisogno, sta uscendo dal perimetro di D2-15.
