# Gate 2 — Verifica

Condizioni e task in `doc/plan/fase-2.md` sezione 2. Questo file raccoglie protocollo, misure ed esito. Il materiale di valutazione (finding, campioni, ordinamenti) resta fuori dal repository: qui entrano solo conteggi e misure.

## Protocollo (X-01)

Registrato il 2026-11-13 su indicazione dell'utente (D2-03, decisa il 2026-11-10).

### Scostamento rispetto a §13

§13 chiede un ordinamento "validato dai team". Non ci sono team da coinvolgere: il validatore è uno solo, l'utente (Riccardo Roveda), sui propri repository. Ne segue che:

- la variante predefinita che esce dal gate è provvisoria e va rivalidata con utenti reali;
- l'accordo misurato è quello di una persona, che è anche l'autore del prodotto e conosce le due varianti. L'ordinamento alla cieca riduce questo effetto ma non lo elimina;
- il Gate 2 si chiude dichiarando questo scostamento in X-08.

Il metodo di Martini et al. (ECSA 2018) citato da §13 non è ancora trascritto in un ADR: lo fanno A-06 e A-08, e l'utente conferma che la trascrizione è fedele. Fino ad allora questo protocollo vale come proposta operativa e non come applicazione verificata di quel metodo.

### Repository

| Repository | Commit | Data del commit | File versionati | Python | JS/TS |
| --- | --- | --- | --- | --- | --- |
| `orario-scuola` | `8b9cee9cc54d456f987f2aaf080d031e6fc62c20` | 2026-11-09 | 1.103 | 170 | 241 |
| `birds-cataloger` | `cb9227f2813b0843a5c0d4d2829c4da7a2d6ae53` | 2025-11-22 | 165 | 36 | 25 |

Entrambi sono dell'utente e si trattano come riservati. D2-03 ne ammette 2 o 3: il terzo è facoltativo e ancora da indicare. Se si aggiunge, entra in questa tabella con il commit fissato prima di X-02.

Le scansioni si eseguono su un clone pulito del commit indicato, sulla macchina di riferimento, con le immagini del registry locale (D2-16). I 3 pilota pubblici della Fase 1 servono a G2.a e G2.d, non a G2.b.

### Campione

- 30 finding per repository. Se i finding ammissibili sono meno di 30 si prendono tutti e si registra il numero.
- Ammissibili: un finding per fingerprint, stato aperto. Sono esclusi quelli coperti da un'eccezione e i finding di tipo `health`.
- Stratificato per categoria e livello provvisorio (ADR-0009): quote proporzionali, con almeno un finding per ogni strato non vuoto.
- Estrazione con seme registrato in X-03.

### Valutazione

- L'utente riceve il campione in ordine casuale, senza punteggio, fattori, livello, severità dello strumento né variante. Vede regola, messaggio, categoria, file e riga, e può aprire il codice.
- Ordina i finding dal più urgente da correggere al meno urgente. Sono ammessi i pari merito.
- L'ordinamento si consegna prima di vedere qualunque punteggio e non si modifica dopo.

### Metrica e soglia

Per ogni repository e per ciascuna variante, A e B:

- tau-b di Kendall tra l'ordinamento dell'utente e quello per punteggio decrescente della variante. Il tau-b tiene conto dei pari merito su entrambi i lati;
- sovrapposizione sui primi 10: quanti dei primi 10 dell'utente sono nei primi 10 della variante. I pari merito al confine si risolvono con l'ordine del fingerprint, su entrambi i lati.

Soglia per repository: la variante migliore ha tau-b ≥ 0,5 e almeno 6 dei primi 10 in comune. G2.b è superata se la soglia è raggiunta su tutti i repository della tabella; con campioni sotto i 30 finding la sovrapposizione si valuta sul terzo superiore del campione, arrotondato per eccesso, con la stessa proporzione (60%).

Si registra anche il risultato dei livelli provvisori, come termine di confronto: una variante che non li supera non giustifica il cambio di livelli.

### Riservatezza

In questo file: numero di finding per categoria e livello, dimensione dei campioni, seme, valori di tau-b e di sovrapposizione, durate. Non entrano percorsi, messaggi, regole per singolo finding né frammenti di codice dei due repository.

## X-02 — Scansione in ombra dei repository del gate (2026-11-18)

Scansioni complete con `--offline` e gli snapshot dei feed già in cache (EPSS e KEV del 2026-11-17), con la CLI impacchettata da `package-cli.sh` al commit `311783f` (immagini firmate sul registry locale), sulla macchina di sviluppo (venti core), una esecuzione per caso. I pilota sono clonati con 80 commit di storia come in V-06; i due repository dell'utente sono cloni puliti dei commit della tabella sopra. `levels.source: provisional` (D2-10): il livello del gate è quello provvisorio di ADR-0009, A e B sono in ombra. Strumento: `scripts/gate2/gate2.py stats`. Qui entrano solo conteggi (i due repository dell'utente sono riservati).

### G2.a: entrambe le varianti su ogni finding

**Superata: 100% su tutti e cinque i repository.** Ogni finding ha i fattori e il punteggio di A e di B, con la versione della configurazione di scoring `1+21df828a85b1`.

### Distribuzione dei livelli

| Repository | Stato | Finding | Provvisorio (critico / alto / medio / basso) | A (critico / alto / medio / basso) | B (id.) | Durata (s) |
| --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | `partial` ¹ | 161 | 1 / 27 / 46 / 87 | 0 / 1 / 24 / 136 | uguale ad A | 19 |
| `excalidraw` | `complete` | 3.350 | 8 / 176 / 1.287 / 1.879 | 0 / 8 / 481 / 2.861 | uguale ad A | 150 |
| `saleor` | `partial` ² | 3.816 | 1 / 53 / 3.414 / 348 | 0 / 1 / 28 / 3.787 | uguale ad A | 235 |
| `orario-scuola` | `complete` | 1.169 | 3 / 52 / 476 / 638 | 1 / 3 / 87 / 1.078 | uguale ad A | 92 |
| `birds-cataloger` | `complete` | 481 | 13 / 207 / 201 / 60 | 0 / 16 / 163 / 302 | uguale ad A | 29 |

¹ `partial` per l'avviso `workspace-symlinks` (quattro collegamenti simbolici con contenuto non analizzato), non per un plugin fallito.
² `partial` perché eslint usciva con 3: `saleor` ha un `package.json` ma nessun file JavaScript e eslint, che non trova nulla da analizzare, esce con 2. **Difetto trovato da questa misura e corretto**: l'adattatore ora riconosce l'unico messaggio di eslint per «niente da analizzare» e dà un risultato vuoto (`eslint_adapter.py`, con test). Le immagini del pacchetto di questa misura sono precedenti alla correzione, quindi la scansione di `saleor` resta `partial` qui; i finding degli altri plugin non cambiano.

### Quanti finding cambiano livello

| Repository | Da provvisorio ad A | Da provvisorio a B | Da A a B |
| --- | --- | --- | --- |
| `full-stack-fastapi-template` | 74 (46,0%) | 74 | 0 |
| `excalidraw` | 1.163 (34,7%) | 1.163 | 0 |
| `saleor` | 3.467 (90,9%) | 3.467 | 0 |
| `orario-scuola` | 479 (41,0%) | 479 | 0 |
| `birds-cataloger` | 392 (81,5%) | 392 | 0 |

Dove cambiano: quasi sempre verso il basso (`medio → basso` è il grosso: 46 su 74, 964 su 1.163, 3.413 su 3.467, 417 su 479, 174 su 392; poi `alto → medio` e `alto → basso`). Controcorrente: `basso → medio` (15 su `excalidraw`, 7 su `orario-scuola`, 1 su `birds-cataloger`) e un solo `alto → critico`, su `orario-scuola`.

### Cosa dicono i numeri

1. **A e B sono identiche ovunque, e non per caso.** La Variante B non è ancora definita per `quality` e `architecture` (ADR-0023, K-06..K-10) e per le altre categorie è per costruzione uguale ad A: il report lo dichiara con `variante-b-non-definita`. Finché B non esiste, G2.b non può distinguere le due varianti: può solo confrontare A con i livelli provvisori.
2. **Con i valori predefiniti, il livello da punteggio quasi non produce livelli alti.** I punteggi massimi sono 15,8, 25,2, 21,0, 37,0 e 29,1 su cinque repository, il 99° percentile tra 6 e 21, la mediana tra 0,3 e 4,2, con soglie a 15, 40 e 70. Se `levels.source` passasse a `score` così com'è, il gate non bloccherebbe quasi nulla (non c'è un `critico` da punteggio in quattro repository su cinque; il solo caso è uno su `orario-scuola`). È la taratura che ADR-0021 dichiara da fare in X-02: **le soglie, i valori di G e P e i limiti minimi dal CVSS vanno rivisti prima di passare a `score`**, non dopo.
3. **I livelli provvisori e quelli da punteggio hanno significati diversi.** Un CVSS alto irraggiungibile è `alto` per ADR-0009 e `basso` per A (ADR-0009 lo notava: un CVSS alto irraggiungibile blocca). Il confronto che il Gate 2 deve fare è quale dei due ordina meglio per l'utente, non quale concorda con l'altro.
4. **Il tempo di una scansione completa**, in secondi sopra, resta sotto i 10 minuti su tutti e cinque (il massimo è `saleor`, 235 s). Non è G2.d, che misura la modalità PR (X-05).

### Limiti

- Una sola esecuzione per caso; snapshot dei feed del 2026-11-17, non aggiornati (`--offline`): gli EPSS e i KEV di oggi possono dare altri punteggi.
- Nessun repository di team: gli unici repository riservati sono i due dell'utente; il terzo, facoltativo, non c'è.
- `saleor` `partial` per il difetto di eslint (corretto nel codice, immagini non ricostruite).

## X-02 ripetuta con la Variante B (2026-11-26)

Stessi cinque repository agli stessi commit, `--offline` con le stesse cache dei feed del 2026-11-17, CLI impacchettata da `package-cli.sh` al commit `0988089` di `main` (ADR-0023 implementata, immagine di `ca-graph` con le righe dei file, immagini firmate sul registry locale). Configurazione di scoring `2+cf90f99e443e`, benchmark `1+35e3b0d58d49`. La misura del 2026-11-18, sopra, resta com'è. La data dei commit è la stessa; l'età dei feed è maggiore e il report lo dice (`feeds-stale`).

**G2.a: superata**, entrambe le varianti sul 100% dei finding di tutti i repository. Nessun plugin fallito: la correzione di eslint vale anche su `saleor`, che resta `partial` solo per i collegamenti simbolici, come `full-stack-fastapi-template`. Nessun finding ricade su A in blocco, nessun avviso di versione del motore diversa da quella del benchmark, righe presenti su tutti i moduli del grafo.

### Distribuzione dei livelli e punteggi

| Repository | Finding | A (critico / alto / medio / basso) | B (id.) | Da A a B | Punteggi A (mediana / 99% / massimo) | B (id.) | Durata (s) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | 161 | 0 / 1 / 24 / 136 | 0 / 1 / 46 / 114 | 22 (13,7%) | 3,2 / 15,8 / 15,8 | 6,1 / 27,3 / 28,5 | 20 |
| `excalidraw` | 3.350 | 0 / 8 / 481 / 2.861 | 0 / 61 / 889 / 2.400 | 622 (18,6%) | 3,4 / 21,0 / 25,2 | 7,3 / 42,8 / 55,6 | 151 |
| `saleor` | 3.815 | 0 / 1 / 27 / 3.787 | 0 / 1 / 43 / 3.771 | 16 (0,4%) | 2,1 / 6,3 / 15,8 | 2,1 / 10,5 / 38,9 | 238 |
| `orario-scuola` | 1.169 | 1 / 3 / 87 / 1.078 | 1 / 4 / 187 / 977 | 167 (14,3%) | 4,2 / 20,8 / 37,0 | 4,0 / 33,0 / 46,6 | 91 |
| `birds-cataloger` | 481 | 0 / 16 / 163 / 302 | 0 / 16 / 176 / 289 | 25 (5,2%) | 0,3 / 19,2 / 29,1 | 0,3 / 25,3 / 29,1 | 30 |

A è invariata: sui due repository dell'utente, dove il confronto è possibile finding per finding, i fingerprint sono gli stessi del 2026-11-18 e nessun punteggio di A è cambiato. I livelli provvisori sono quelli della tabella del 2026-11-18, con un finding in meno su `saleor` (3.815 invece di 3.816).

### Da dove vengono le differenze

Su 7.493 finding `quality` e 300 `architecture` dei cinque repository:

| Ripiego di B | Finding | Motivo |
| --- | --- | --- |
| `g:regola-senza-metrica` | 1.701 `quality` (23%) | previsto: G di A. Il restante 77% usa l'intensità |
| `p:churn-ignoto` | 3.526 `quality` (più 14 senza churn né densità) e 200 `architecture` | quasi tutti su `saleor` e `full-stack-fastapi-template`: 80 commit non coprono i 90 giorni, la storia è `superficiale` e il churn è ignoto, come in A. Pochi altri (4 e 10) sono file fuori dal grafo |
| `c:fuori-dal-grafo` | 3.722 `quality` | 3.708 sono moduli di test (senza PageRank); 14 sono file `.ts` fuori dal grafo |

Mediana dei fattori: sui `quality` P di B è più alto di quello di A su tutti i repository; C di B è più basso di C di A dove il grafo distingue (0,27 contro 0,70 su `orario-scuola`, 0,56 su `birds-cataloger`). Sugli `architecture` C di B è più alto (0,76–0,89); dove il churn è ignoto P di B ha mediana 0,15 contro 0,30 di A, perché la densità di violazioni è 0 per almeno metà dei membri.

### Cosa dicono i numeri

1. **B ora è distinguibile da A, ma poco sui campioni.** Sul campione di X-03 di `orario-scuola` (30 finding, 18 `quality` e 1 `architecture`) A e B danno punteggi diversi a 19, il tau-b tra i due ordinamenti è 0,71 e i primi 10 in comune sono 6. Su `birds-cataloger` (6 `quality` e 1 `architecture`) i punteggi diversi sono 6, il tau-b è 0,97 e i primi 10 sono gli stessi: **lì G2.b non potrà dire quale variante è migliore**. Il campione è stratificato sulle categorie, e A e B differiscono solo su due.
2. **Le soglie restano da ritarare.** B alza i punteggi alti (99° percentile fino a 42,8 contro 21,0), ma con soglie a 15, 40 e 70 non ci sono `critico` oltre all'unico di `orario-scuola`, e gli `alto` restano pochi.
3. **File di test: C alto, effetto piccolo sul punteggio.** Un modulo di test non ha PageRank, quindi in B prende il C di A (0,7 senza tier), spesso più alto del C dei file di produzione. Sul punteggio però pesa E (0,2 su tutti i finding nei test): sui quattro repository con finding `quality` nei test, un finding su un test supera in media tra l'11% e il 28% di quelli di produzione, nessuno arriva a `medio`, e tra i primi 50 `quality` per punteggio di B ce n'è al più uno (su `saleor`, dove i test sono l'84% dei finding). Con C = 0,5 o C = 0,1 per i test la quota superata scenderebbe tra il 5% e il 19%, o tra lo 0% e il 2%: con 0,1 l'essere un test conterebbe due volte, in E e in C.
4. **Tempi** invariati rispetto al 2026-11-18, entro pochi secondi, sotto i 10 minuti su tutti (massimo `saleor`, 238 s).

### Limiti

- Come il 2026-11-18: una sola esecuzione per caso, stessi snapshot dei feed, nessun repository di team.
- Su due pilota il churn è ignoto: lì P di B è guidato solo dalla densità.

## X-03 — Materiale di valutazione (2026-11-18)

Campioni generati con `scripts/gate2/gate2.py sample`, **seme 20261118**, 30 finding per repository, stratificati per categoria e livello provvisorio (quote proporzionali, almeno uno per strato non vuoto), dai finding con fingerprint distinto, di stato aperto, senza eccezione e senza `health`.

| Repository | Finding ammissibili | Campione | Strati non vuoti |
| --- | --- | --- | --- |
| `orario-scuola` | 1.169 | 30 | 13 |
| `birds-cataloger` | 481 | 30 | 12 |

Il materiale è **fuori dal repository**, in `~/gate2-material/` (cartella con permessi riservati): per ciascun repository `valutazione-<repo>.md` (i 30 finding in ordine casuale, con categoria, regola, posizione e messaggio, **senza** livelli, severità, punteggi né variante), `ordinamento-<repo>.csv` (da compilare con il rango, 1 il più urgente, pari merito ammessi), `chiave-<repo>.json` (corrispondenza con i fingerprint, da non aprire prima di consegnare) e il report su cui calcolare. Il calcolo dopo la consegna: `scripts/gate2/gate2.py score --report ~/gate2-material/report-<repo>.json --key ~/gate2-material/chiave-<repo>.json --ranking ~/gate2-material/ordinamento-<repo>.csv`, che stampa tau-b e sovrapposizione sui primi 10 per A, B e per i livelli provvisori e se la soglia (tau-b ≥ 0,5 e 6 su 10) è raggiunta.

**Quando farla.** Ordinare 60 finding costa tempo, e finché la Variante B non esiste (K-06..K-10) il confronto A contro B è vuoto: A e B danno lo stesso ordinamento. L'ordinamento dell'utente si può comunque consegnare ora e misura A contro i livelli provvisori; non andrà rifatto quando B esisterà, perché il campione è fissato dal seme. Il riesame con una configurazione di scoring ritarata (punto 2 sopra) cambia i punteggi ma non il campione.

**Aggiornamento del 2026-11-26 (Variante B definita).** Il campione non cambia: i 30 finding di ciascun repository ci sono tutti nelle scansioni nuove. Per il calcolo si usa il report nuovo, `~/gate2-material/report-<repo>-b.json`, con le stesse chiavi e gli stessi ordinamenti; il report del 2026-11-18 resta per riferimento. Al 2026-11-26 gli ordinamenti non sono ancora compilati. Una modifica di formule o pesi fatta **dopo** la consegna sarebbe una taratura sulla valutazione stessa: va decisa prima, oppure dichiarata in X-06.
