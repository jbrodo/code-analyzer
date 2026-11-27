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

| Repository | File versionati | Python | JS/TS |
| --- | --- | --- | --- |
| `repo-1` | 1.103 | 170 | 241 |
| `repo-2` | 165 | 36 | 25 |
| `repo-3` | 155 | 0 | 35 |

Sono dell'utente e si trattano come riservati: qui hanno **nomi generici**, e nomi veri e commit scansionati stanno solo nel materiale del proprietario, fuori dal repository (`~/gate2-material/commit.json`, impronta SHA-256 `06a76c6598898ed0c55012677a706be2d4c7caf51bf2c6c581ce116154085954`). Dove sotto un nome di file locale contiene `repo-N`, il file vero ha il nome del repository. D2-03 ne ammette 2 o 3. **`repo-3` è il terzo, scelto dall'utente il 2026-11-27** e fissato con il suo commit prima della sua scansione e prima di qualunque risultato di G2.b. È entrato dopo X-02 del 2026-11-18: la sua scansione è descritta più sotto. Era stato proposto anche un altro repository dell'utente, non inserito perché i suoi finding stavano quasi tutti nella copia di uno strumento di terze parti.

Le scansioni si eseguono su un clone pulito del commit indicato, sulla macchina di riferimento, con le immagini del registry locale (D2-16). I 3 pilota pubblici della Fase 1 servono a G2.a e G2.d, non a G2.b.

### Dashboard di valutazione (2026-11-27)

`python3 scripts/gate2/review.py` apre in locale una pagina per ordinare i campioni senza scrivere numeri: un finding alla volta con il codice al commit scansionato e quattro gruppi di urgenza (subito, presto, quando capita, mai o non è un problema). **Dentro un gruppo tutto parte alla pari**; si spostano in fasce solo i finding che vengono prima o dopo gli altri, e spostarne uno non ordina gli altri fra loro. La posizione dipende solo da gruppo e fascia. Legge solo `valutazione-<repo>.md`, il proprio avanzamento e il codice con `git show`: mai report, chiavi o altri ordinamenti, e un ordinamento già scritto nel CSV non viene ricaricato (alla consegna ne resta una copia). Si consegna solo il riepilogo mostrato, che è il CSV scritto; dopo non si modifica, e `consegna-<repo>.json` registra ora e impronta.

Cambia il modo di raccogliere il giudizio, non ciò che si misura; in X-06 vanno ricordati i **gruppi**, assenti nel protocollo del 2026-11-13, e il loro effetto: i pari merito sono ammessi e il tau-b ne tiene conto, ma se una fascia attraversa la decima posizione, quali suoi finding entrino nei primi 10 dipende dall'ordine dei fingerprint (regola già scritta sotto «Soglia»). La pagina non lo segnala, per non orientare il giudizio verso la misura.

**Revisione e correzioni (2026-11-27).** La revisione con la skill `impeccable critique` (due valutatori separati, solo dati finti) ha dato 19/40 sulla prima versione: poteva consegnare un ordine diverso da quello a schermo dopo un salvataggio fallito o con due schede, registrare voti non voluti (tasto tenuto premuto, Invio ripetuto) e creare posizioni mai espresse (aprire il riordino numerava un gruppo nell'ordine del campione). Corretti insieme ai due problemi di livello inferiore (riordino faticoso, codice tagliato senza dirlo), prima di qualunque consegna. L'avanzamento di `repo-1` raccolto con quella versione è stato messo da parte **senza leggerlo** (`progresso-repo-1.prima-correzioni-2026-11-27.json`) e si riparte da zero; per gli altri due repository non ce n'era.

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

## Regola di scelta e altre decisioni (2026-11-26, prima dell'ordinamento)

Approvate dall'utente il 2026-11-26. A quella data l'utente non ha compilato alcun ordinamento e nessun risultato di G2.b è stato calcolato.

**Regola per G2.c**, applicata ai risultati di X-04:

1. è candidata solo una variante che supera la soglia del protocollo su **tutti** i repository della tabella;
2. se le candidate sono due, vince quella con il tau-b medio più alto;
3. se la differenza tra i due tau-b medi è inferiore a 0,05, **vince A**: si spiega più facilmente, e con A il progetto supera il proprio gate (X-07);
4. se nessuna è candidata, il gate resta sui livelli provvisori, A resta predefinita in via provvisoria e **G2.b si dichiara non superata**.

Se vince B, prima di attivarla si semplifica la funzione di `runner.py` che oggi fa fallire il gate del progetto (X-07), invece di aggiungere un'eccezione.

**Terzo repository:** consigliato perché sul campione di `repo-2` A e B hanno gli stessi primi 10. Indicato il 2026-11-27: `repo-3` (tabella dei repository).

**Livelli da punteggio: non si attivano per ora** (`levels.source: provisional`). È una modifica di D2-10, che prevedeva di attivarli dopo la scelta della variante: con le soglie attuali quasi nessun finding arriva ad `alto` (X-02, X-07), e un ordinamento dice quale variante ordina meglio, non dove mettere le soglie. L'esito del gate (X-08) la dichiara.

**Ordinamenti consegnati il 2026-11-27 per i primi due repository: non utilizzabili, in attesa di chiarimento.** I file ufficiali, completi (30 righe ciascuno, ultima modifica alle 00:13), coincidono con quelli di Claude (più sotto, «Ordinamento di Claude») in tutte le 60 posizioni: non sono un ordinamento indipendente. Impronte SHA-256 al momento del controllo: `repo-1` `47af864078448936fe38ba140491d017610dc99f0a485bd7f8dc40679bf23d00`, `repo-2` `606e8070f86036eee0696733381d02444e68f22b7dd6b5c0ee69b3b49826d540`. Su di essi **non è stato calcolato nulla**. Che fare è deciso nel paragrafo seguente.

**Chiarimento e nuova consegna (2026-11-27).** Alla domanda se avesse letto l'ordine di Claude o solo copiato i file, il proprietario ha risposto di averli copiati. Ha poi ordinato i tre campioni da capo con la dashboard, che non carica i CSV esistenti; le copie sostituite restano accanto ai file ufficiali (`ordinamento-<repo>.prima-<ora>.csv`) e non entrano nel calcolo. I nuovi file hanno 30 righe compilate su 30, con 14, 9 e 10 posizioni distinte (`repo-1`, `repo-2`, `repo-3`); nei primi due coincidono con l'ordine di Claude 3 e 2 posizioni su 30. **Sono questi gli ordinamenti di X-04.** Che l'ordine di Claude non abbia influito sul nuovo giudizio è una dichiarazione del proprietario, non verificabile: X-06 la riporta tra i limiti. Impronte SHA-256, uguali a quelle dei registri di consegna e registrate **prima di calcolare qualunque risultato**:

- `repo-1`, consegnato il 2026-11-27T07:46:02+00:00: `afe366beaae61ac05ef5eed932a6489103859fa93dddec503932e1586baafc0c`
- `repo-2`, consegnato il 2026-11-27T07:51:01+00:00: `fe8683aa2936941cd59ac904091fe57cd296156fe50fb190dae3045a4948a75b`
- `repo-3`, consegnato il 2026-11-27T07:56:26+00:00: `6ea61a3c6cf77bbec1c6576ae74f229f0b81f12fd231a0e8cc9dcac509bce5f7`

**Ordinamento di Claude, fuori dal protocollo.** Su richiesta dell'utente, Claude ha ordinato i due campioni in file separati, fuori dal repository (`ordinamento-<repo>-claude.csv`), senza aprire report né chiavi. **Non è l'ordinamento di X-04 e non entra in G2.b:** chi l'ha fatto ha scritto le formule di B e ha visto i confronti aggregati tra A e B. Quando è stato scritto questo paragrafo i file ufficiali erano vuoti; su quelli di Claude non è stato calcolato nulla. **Per `repo-3` Claude non fa alcun ordinamento.**

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
| `repo-1` | `complete` | 1.169 | 3 / 52 / 476 / 638 | 1 / 3 / 87 / 1.078 | uguale ad A | 92 |
| `repo-2` | `complete` | 481 | 13 / 207 / 201 / 60 | 0 / 16 / 163 / 302 | uguale ad A | 29 |

¹ `partial` per l'avviso `workspace-symlinks` (quattro collegamenti simbolici con contenuto non analizzato), non per un plugin fallito.
² `partial` perché eslint usciva con 3: `saleor` ha un `package.json` ma nessun file JavaScript e eslint, che non trova nulla da analizzare, esce con 2. **Difetto trovato da questa misura e corretto**: l'adattatore ora riconosce l'unico messaggio di eslint per «niente da analizzare» e dà un risultato vuoto (`eslint_adapter.py`, con test). Le immagini del pacchetto di questa misura sono precedenti alla correzione, quindi la scansione di `saleor` resta `partial` qui; i finding degli altri plugin non cambiano.

### Quanti finding cambiano livello

| Repository | Da provvisorio ad A | Da provvisorio a B | Da A a B |
| --- | --- | --- | --- |
| `full-stack-fastapi-template` | 74 (46,0%) | 74 | 0 |
| `excalidraw` | 1.163 (34,7%) | 1.163 | 0 |
| `saleor` | 3.467 (90,9%) | 3.467 | 0 |
| `repo-1` | 479 (41,0%) | 479 | 0 |
| `repo-2` | 392 (81,5%) | 392 | 0 |

Dove cambiano: quasi sempre verso il basso (`medio → basso` è il grosso: 46 su 74, 964 su 1.163, 3.413 su 3.467, 417 su 479, 174 su 392; poi `alto → medio` e `alto → basso`). Controcorrente: `basso → medio` (15 su `excalidraw`, 7 su `repo-1`, 1 su `repo-2`) e un solo `alto → critico`, su `repo-1`.

### Cosa dicono i numeri

1. **A e B sono identiche ovunque, e non per caso.** La Variante B non è ancora definita per `quality` e `architecture` (ADR-0023, K-06..K-10) e per le altre categorie è per costruzione uguale ad A: il report lo dichiara con `variante-b-non-definita`. Finché B non esiste, G2.b non può distinguere le due varianti: può solo confrontare A con i livelli provvisori.
2. **Con i valori predefiniti, il livello da punteggio quasi non produce livelli alti.** I punteggi massimi sono 15,8, 25,2, 21,0, 37,0 e 29,1 su cinque repository, il 99° percentile tra 6 e 21, la mediana tra 0,3 e 4,2, con soglie a 15, 40 e 70. Se `levels.source` passasse a `score` così com'è, il gate non bloccherebbe quasi nulla (non c'è un `critico` da punteggio in quattro repository su cinque; il solo caso è uno su `repo-1`). È la taratura che ADR-0021 dichiara da fare in X-02: **le soglie, i valori di G e P e i limiti minimi dal CVSS vanno rivisti prima di passare a `score`**, non dopo.
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
| `repo-1` | 1.169 | 1 / 3 / 87 / 1.078 | 1 / 4 / 187 / 977 | 167 (14,3%) | 4,2 / 20,8 / 37,0 | 4,0 / 33,0 / 46,6 | 91 |
| `repo-2` | 481 | 0 / 16 / 163 / 302 | 0 / 16 / 176 / 289 | 25 (5,2%) | 0,3 / 19,2 / 29,1 | 0,3 / 25,3 / 29,1 | 30 |

A è invariata: sui due repository dell'utente, dove il confronto è possibile finding per finding, i fingerprint sono gli stessi del 2026-11-18 e nessun punteggio di A è cambiato. I livelli provvisori sono quelli della tabella del 2026-11-18, con un finding in meno su `saleor` (3.815 invece di 3.816).

### Da dove vengono le differenze

Su 7.493 finding `quality` e 300 `architecture` dei cinque repository:

| Ripiego di B | Finding | Motivo |
| --- | --- | --- |
| `g:regola-senza-metrica` | 1.701 `quality` (23%) | previsto: G di A. Il restante 77% usa l'intensità |
| `p:churn-ignoto` | 3.526 `quality` (più 14 senza churn né densità) e 200 `architecture` | quasi tutti su `saleor` e `full-stack-fastapi-template`: 80 commit non coprono i 90 giorni, la storia è `superficiale` e il churn è ignoto, come in A. Pochi altri (4 e 10) sono file fuori dal grafo |
| `c:fuori-dal-grafo` | 3.722 `quality` | 3.708 sono moduli di test (senza PageRank); 14 sono file `.ts` fuori dal grafo |

Mediana dei fattori: sui `quality` P di B è più alto di quello di A su tutti i repository; C di B è più basso di C di A dove il grafo distingue (0,27 contro 0,70 su `repo-1`, 0,56 su `repo-2`). Sugli `architecture` C di B è più alto (0,76–0,89); dove il churn è ignoto P di B ha mediana 0,15 contro 0,30 di A, perché la densità di violazioni è 0 per almeno metà dei membri.

### Cosa dicono i numeri

1. **B ora è distinguibile da A, ma poco sui campioni.** Sul campione di X-03 di `repo-1` (30 finding, 18 `quality` e 1 `architecture`) A e B danno punteggi diversi a 19, il tau-b tra i due ordinamenti è 0,71 e i primi 10 in comune sono 6. Su `repo-2` (6 `quality` e 1 `architecture`) i punteggi diversi sono 6, il tau-b è 0,97 e i primi 10 sono gli stessi: **lì G2.b non potrà dire quale variante è migliore**. Il campione è stratificato sulle categorie, e A e B differiscono solo su due.
2. **Le soglie restano da ritarare.** B alza i punteggi alti (99° percentile fino a 42,8 contro 21,0), ma con soglie a 15, 40 e 70 non ci sono `critico` oltre all'unico di `repo-1`, e gli `alto` restano pochi.
3. **File di test: C alto, effetto piccolo sul punteggio.** Un modulo di test non ha PageRank, quindi in B prende il C di A (0,7 senza tier), spesso più alto del C dei file di produzione. Sul punteggio però pesa E (0,2 su tutti i finding nei test): sui quattro repository con finding `quality` nei test, un finding su un test supera in media tra l'11% e il 28% di quelli di produzione, nessuno arriva a `medio`, e tra i primi 50 `quality` per punteggio di B ce n'è al più uno (su `saleor`, dove i test sono l'84% dei finding). Con C = 0,5 o C = 0,1 per i test la quota superata scenderebbe tra il 5% e il 19%, o tra lo 0% e il 2%: con 0,1 l'essere un test conterebbe due volte, in E e in C. **Deciso dall'utente il 2026-11-26, prima di ordinare i campioni: resta com'è** (ADR-0023).
4. **Tempi** invariati rispetto al 2026-11-18, entro pochi secondi, sotto i 10 minuti su tutti (massimo `saleor`, 238 s).

### Limiti

- Come il 2026-11-18: una sola esecuzione per caso, stessi snapshot dei feed, nessun repository di team.
- Su due pilota il churn è ignoto: lì P di B è guidato solo dalla densità.

## X-03 — Materiale di valutazione (2026-11-18)

Campioni generati con `scripts/gate2/gate2.py sample`, **seme 20261118**, 30 finding per repository, stratificati per categoria e livello provvisorio (quote proporzionali, almeno uno per strato non vuoto), dai finding con fingerprint distinto, di stato aperto, senza eccezione e senza `health`.

| Repository | Finding ammissibili | Campione | Strati non vuoti |
| --- | --- | --- | --- |
| `repo-1` | 1.169 | 30 | 13 |
| `repo-2` | 481 | 30 | 12 |

Il materiale è **fuori dal repository**, in `~/gate2-material/` (cartella con permessi riservati): per ciascun repository `valutazione-<repo>.md` (i 30 finding in ordine casuale, con categoria, regola, posizione e messaggio, **senza** livelli, severità, punteggi né variante), `ordinamento-<repo>.csv` (da compilare con il rango, 1 il più urgente, pari merito ammessi), `chiave-<repo>.json` (corrispondenza con i fingerprint, da non aprire prima di consegnare) e il report su cui calcolare. Il calcolo dopo la consegna: `scripts/gate2/gate2.py score --report ~/gate2-material/report-<repo>.json --key ~/gate2-material/chiave-<repo>.json --ranking ~/gate2-material/ordinamento-<repo>.csv`, che stampa tau-b e sovrapposizione sui primi 10 per A, B e per i livelli provvisori e se la soglia (tau-b ≥ 0,5 e 6 su 10) è raggiunta.

**Quando farla.** Ordinare 60 finding costa tempo, e finché la Variante B non esiste (K-06..K-10) il confronto A contro B è vuoto: A e B danno lo stesso ordinamento. L'ordinamento dell'utente si può comunque consegnare ora e misura A contro i livelli provvisori; non andrà rifatto quando B esisterà, perché il campione è fissato dal seme. Il riesame con una configurazione di scoring ritarata (punto 2 sopra) cambia i punteggi ma non il campione.

**Aggiornamento del 2026-11-26 (Variante B definita).** Il campione non cambia: i 30 finding di ciascun repository ci sono tutti nelle scansioni nuove. Per il calcolo si usa il report nuovo, `~/gate2-material/report-<repo>-b.json`, con le stesse chiavi e gli stessi ordinamenti; il report del 2026-11-18 resta per riferimento. Al 2026-11-26 gli ordinamenti non sono ancora compilati. Una modifica di formule o pesi fatta **dopo** la consegna sarebbe una taratura sulla valutazione stessa: va decisa prima, oppure dichiarata in X-06.

## X-05 — Scansione in modalità PR (2026-11-26)

**G2.d: superata.** Le tre scansioni in modalità PR durano al massimo 264 s, meno della metà dei 600 s richiesti.

### Regola di misura

Quella di `gate-1.md`: macchina di riferimento (i9-10900K, 20 thread, 60 GiB; Linux 7.0.0-44-generic, Docker 27.3.1), `--offline` con i feed già in cache (sincronizzazione esclusa), `duration_seconds` del report, costruzione e firma delle immagini escluse. CLI impacchettata da `package-cli.sh` con il codice del prodotto di `main` (`032a8d2`: dopo, in `packages/`, nulla è cambiato), tredici plugin con immagini firmate sul registry locale. Feed: database di osv-scanner e trivy sincronizzati il 2026-11-17; EPSS (SHA-256 `24e6330d304d…`) e KEV (`a76360009e4a…`) del 2026-11-26. Scoring `2+cf90f99e443e`, benchmark `1+35e3b0d58d49`.

**Scostamento:** senza la policy di licenze di `.code-analyzer.yml` (avviso `license-policy-absent`), che la regola di `gate-1.md` prevede. Non cambia quali plugin girano.

### PR di riferimento

Criterio fissato **prima** della misura: a partire dal commit pilota della Fase 1, l'ultimo commit della linea principale (primo genitore) che modifica almeno un file di codice Python o JS/TS non di test; la base è il suo primo genitore. Cloni con 80 commit di storia.

| Pilota | Base | Testa | Commit saltati dal pilota | File (codice non di test) | Righe aggiunte / tolte |
| --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | `f27b4721507824e57ebd0286ff1a84d82e83bf59` | `0007f609ec8467c913283f44660f5e50257a6d7a` | 15 | 5 (3) | 34 / 26 |
| `excalidraw` | `dd2f8fc32b92cbf56f4abee6a0cf3b14681b4b55` | `7ded689cad49331167e29fd88b38f38d3736d576` | 2 | 16 (7) | 155 / 222 |
| `saleor` | `89817cdd10423619d6d6be54a61ead11fca90cfa` | `1d707dcf6127b098c187a181e5ee344017cdb064` | 0 | 5 (1) | 302 / 1 |

La baseline di ciascuna è la scansione completa della base, fatta subito prima sulla stessa macchina (`--baseline-source base-scan`).

### Misura

| Pilota | Scansione completa della base (s) | **Scansione PR (s)** | Processo intero PR (s) | Finding | Nuovi / esistenti / risolti / spostati | Stato | Plugin più lento |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | 23,3 | **20,1** | 20 | 181 | 1 / 180 / 1 / 0 | `partial` ¹ | scancode, 13,8 s |
| `excalidraw` | 170,4 | **172,6** | 176 | 3.350 | 1 / 3.349 / 2 / 38 | `complete` | scancode, 158,8 s |
| `saleor` | 251,7 | **263,9** | 268 | 3.815 | 38 / 3.777 / 0 / 0 | `partial` ¹ | scancode, 246,2 s |

¹ Solo per i collegamenti simbolici non seguiti (`workspace-symlinks`, e quindi `baseline-partial`): nessun plugin fallito.

- Gli spostati sono compresi tra gli esistenti.
- **Baseline valida** sulle tre. **Tutti i finding nuovi stanno in file modificati dalla PR** (1 su 1, 1 su 1, 38 su 38; i 38 di `saleor` sono nell'unico file Python aggiunto).
- **La modalità PR non è più veloce di quella completa:** la PR non restringe i file analizzati (ADR-0009, `PROJECT.md` §5). Il tempo lo decide scancode: da 13,8 su 20,1 s a 246,2 su 263,9 s.
- **Gate** (modo `all`, senza configurazione): `excalidraw` esce con 1 per finding bloccanti; gli altri due con 2 (`partial-scan`), perché un report parziale non decide.

### Limiti

- Una sola esecuzione per caso.
- La macchina non era del tutto scarica: servizi dell'utente in container, quasi inattivi, e carico medio intorno a 2 su 20 thread prima di cominciare.
- PR piccole (5–16 file). Con la scansione completa dei file il tempo dipende dalle dimensioni del repository più che della PR; `saleor` è il più grande dei pilota.
- Il margine di `saleor` (2,3 volte) vale per questa macchina; un runner di CI con pochi core può essere più lento e non è stato misurato.

## X-07 — Auto-analisi con i livelli della Fase 2 (2026-11-26)

**Superata con la configurazione del prodotto** (variante A attiva), sia con i livelli provvisori sia con quelli da punteggio: `gate --fail-on critico,alto` esce con 0, nessun finding critico o alto aperto. **Con la variante B attiva non è superata** (sotto).

Clone pulito di `main` al commit `b10b9de`, CLI impacchettata con lo stesso codice del prodotto, tredici plugin con immagini firmate, 1.226 finding, `complete`, 96 s (94 s con i livelli da punteggio), `--offline`. Feed: osv-scanner, EPSS e KEV sincronizzati il 2026-11-26; **trivy del 2026-11-17** (avviso `feeds-stale`), perché in una cache nuova su questa macchina la sincronizzazione del suo database non è mai riuscita nei tentativi di oggi (causa non indagata; in CI il 2026-11-26 è riuscita). Per i livelli da punteggio, una copia della configurazione predefinita con `levels.source: score`, fuori dal repository.

| Livelli | Finding per livello (critico / alto / medio / basso) | Aperti (critico / alto / medio / basso) | Eccezioni applicate | `gate` |
| --- | --- | --- | --- | --- |
| Provvisori | 14 / 28 / 787 / 397 | 0 / 0 / 787 / 397 | 42 | 0 |
| Da punteggio, variante A | 14 / 0 / 118 / 1.094 | 0 / 0 / 94 / 1.090 | 42 | 0 |

- **Le 6 eccezioni di D-0015** (X-10) sono tutte applicate, ciascuna su un finding di licenza `alto` sotto i livelli provvisori. Due impronte non sono più quelle elencate in `gate-1.md`, come X-10 aveva già registrato.
- **Una delle 43 eccezioni non serve più:** il falso positivo di licenza su `doc/plan/fase-2.md` (scadenza 2027-05-09) non corrisponde a nessun finding. Toglierla è una scelta di chi l'ha approvata.
- **Con i livelli da punteggio** i 14 `critico` vengono tutti dall'override `license-forbidden-distributed` (eccepiti) e il punteggio da solo non produce nessun `alto` in A: i 27 finding eccepiti che erano `alto` diventano 23 `medio` e 4 `basso`. È il limite delle soglie non ritarate di X-02: qui il gate passa anche perché i livelli da punteggio quasi non arrivano ad `alto`.

### Con la variante B

Con `--variant B` e i livelli da punteggio il gate esce con **1**: tre finding `quality` aperti diventano `alto` (`PLR0911`, `PLR0912` e `C901`, punteggi tra 40,3 e 42,1; in A sono `medio` con 20,6). Riguardano la stessa funzione di `packages/ca-plugins/src/ca_plugins/runner.py`: complessità oltre quasi tutto il benchmark (G tra 0,96 e 1,0), in un file con molte modifiche e violazioni (P 0,93). Non sono falsi positivi. **Se X-06 propone B**, per tenere verde X-07 va semplificata quella funzione, oppure serve un'eccezione approvata o una ritaratura delle soglie.

## X-02 e X-03 per il terzo repository, `repo-3` (2026-11-27)

Commit fissato prima della scansione. Scansione completa `--offline` in 29 s (30 s il processo intero), CLI impacchettata da `package-cli.sh` dal codice di `main` dopo la PR #38 (correzioni di adattatori e di `ca-graph`; scoring `2+cf90f99e443e` e benchmark `1+35e3b0d58d49`, come per gli altri). Feed: osv-scanner e trivy del 2026-11-17, EPSS e KEV del 2026-11-26. **Differenze dagli altri due:** il pacchetto è più recente di quello di X-02, e EPSS e KEV sono di nove giorni dopo; il confronto tra A e B si fa dentro la stessa scansione e non ne dipende.

`complete`, nessun plugin fallito, 88 finding (53 `quality`, 2 `architecture`, 27 `dependency`, 6 `iac`), **G2.a al 100%**. Livelli provvisori (critico / alto / medio / basso): 0 / 21 / 30 / 37; A e B: 0 / 0 / 16 / 72 entrambe, nessun finding cambia livello tra A e B. Punteggi (mediana / 99% / massimo): A 0,5 / 10,5 / 10,5; B 1,7 / 10,5 / 10,5.

**Campione** con lo stesso seme, 20261118: 30 finding su 88 ammissibili, 8 strati (17 `quality`, 10 `dependency`, 2 `iac`, 1 `architecture`). Sul campione A e B hanno punteggi diversi su 18 finding, tau-b tra i due ordini 0,84, 8 dei primi 10 in comune: **le due varianti si distinguono poco**, più che su `repo-2` e meno che su `repo-1`. Il materiale è in `~/gate2-material/` (`valutazione-`, `ordinamento-`, `chiave-` e `report-repo-3`), con l'ordinamento vuoto. Il comando di calcolo usa `--report ~/gate2-material/report-repo-3.json`. Claude ha generato il materiale senza leggere il campione e **non ne fa un ordinamento**.

## X-04 — Risultati sugli ordinamenti del proprietario (2026-11-27)

`gate2.py score`, invariato, sui tre ordinamenti con le impronte registrate sopra (verificate prima del calcolo); report `-b` per i primi due repository. Campioni di 30, quindi primi 10 e almeno 6 in comune.

| Repository | A: tau-b, primi 10 | B: tau-b, primi 10 | Provvisori: tau-b, primi 10 | Soglia per A e B |
| --- | --- | --- | --- | --- |
| `repo-1` | −0,310, 1 | −0,250, 1 | 0,385, 5 | non raggiunta |
| `repo-2` | −0,584, 0 | −0,574, 0 | 0,548, 6 | non raggiunta |
| `repo-3` | −0,326, 1 | −0,301, 0 | 0,694, 7 | non raggiunta |
| Media dei tau-b | −0,407 | −0,375 | 0,542 | |

**Nessuna variante supera la soglia su alcun repository. G2.b non è superata.** Per il punto 4 della regola registrata il 2026-11-26, il gate resta sui livelli provvisori e A resta predefinita in via provvisoria. I livelli provvisori ordinano meglio di A e di B in tutti e tre i repository, ma **non sono validati nemmeno loro**: su `repo-1` non raggiungono la soglia.

**Pari merito al confine dei primi 10.** In `repo-2` e `repo-3` i primi 10 del proprietario cadono tutti dentro un gruppo alla pari (18 e 10 finding). Risolvendo i pari merito, sui due lati, in tutti i modi possibili: A e B non cambiano in nessun repository (da 0 a 1 in comune, il valore della tabella), quindi il loro esito non dipende da questa scelta. La sovrapposizione dei **livelli provvisori** invece sì: da 3 a 7 su `repo-1`, **da 1 a 10 su `repo-2`** (il 6 della tabella dipende dall'ordine dei fingerprint), da 7 a 9 su `repo-3`.

**Controllo del calcolo.** Un tau-b negativo su tutti i repository può indicare un errore di segno. Controlli: nell'ordinamento il gruppo «subito» occupa le prime posizioni, e i livelli provvisori concordano nello stesso verso; i punteggi di A di tutti i 1.738 finding delle tre scansioni coincidono (entro 0,011) con 100·G·P·E·C ricalcolato dai fattori del report. Non è emerso un errore di segno né di prodotto.

**Da dove viene il segno negativo (analisi fatta dopo il risultato, esplorativa: non entra nella regola).**

- In tutti e tre i campioni la prima posizione contiene **tutti e soli** i finding `dependency` (4, 18 e 10), alla pari tra loro.
- A e B li mettono in fondo. In A e in B, per una dipendenza fuori da KEV, P è `max(EPSS, 0,01)`, una probabilità di sfruttamento con mediana 0,01 in tutte e tre le scansioni; per `quality` e `architecture` in A, P è il percentile di churn del file, minimo 0,1 e, sulle scansioni intere, mediane di `quality` da 0,10 a 0,70. A parità degli altri fattori il prodotto confronta due grandezze diverse sulla stessa scala. È il comportamento scritto in §6 e in ADR-0021, non un difetto del codice. Il limite inferiore dal CVSS (S5-A1) alza il livello e non il punteggio, quindi non cambia questo ordine.
- **Togliendo le dipendenze** (26, 12 e 20 finding rimasti) A ha tau-b −0,078, 0,254 e 0,330; B −0,013, 0,299 e 0,417; i provvisori 0,336, 0,377 e 0,582. A e B restano sotto 0,5: il confronto tra categorie spiega il segno, ma **correggere solo quello non basta** su questi campioni.

**Limiti.** Un solo valutatore, autore del prodotto, su repository propri. Per i primi due repository esisteva un ordinamento di Claude, che il proprietario ha dichiarato di aver copiato e poi sostituito: che non abbia influito non è verificabile; `repo-3`, senza ordinamento di Claude, dà lo stesso esito. Il giudizio è raccolto in quattro gruppi con pari merito, non previsti dal protocollo del 2026-11-13. Le dipendenze non sono distinte tra loro, quindi questi campioni non dicono quale delle due varianti le ordini meglio al loro interno. Package di `repo-3` costruito dal codice corrente ed EPSS/KEV del 2026-11-26 (vedi sopra).

## X-06 — Proposta sulla variante predefinita (2026-11-27)

**A contro B.** B ha il tau-b medio più alto di 0,032, sotto lo 0,05 della regola, e nessuna delle due è candidata: la differenza non conta. Sui campioni i due ordini sono vicini (tau-b tra A e B: 0,71, 0,97 e 0,84).

**Raccomandazione:** applicare il punto 4 senza eccezioni.

1. Livelli e gate restano provvisori (`levels.source: provisional`); A resta predefinita in via provvisoria; A e B restano in ombra. La UI e i documenti non li presentano come un ordinamento validato.
2. G2.c si registra come «nessuna variante scelta» e G2.b come non superata in X-08.
3. **Nessuna modifica a formule o pesi su questi dati dentro la Fase 2.** Una correzione della scala di P per le dipendenze, tarata su questi tre ordinamenti, andrebbe provata su campioni nuovi (seme o repository diversi), ordinati prima di vederne i punteggi; questi tre servirebbero solo a svilupparla.

**Decisione dell'utente (2026-11-27): raccomandazione confermata** (ADR-0031, `PROJECT.md` §18).

## X-08 — Esito del Gate 2 (2026-11-27)

**Gate 2 non superato:** l'ordinamento non è validato.

| Condizione | Evidenza | Valore misurato | Esito |
| --- | --- | --- | --- |
| **G2.a** Entrambe le varianti calcolate in ombra | X-02 (2026-11-18), X-02 ripetuta con B (2026-11-26), X-02 di `repo-3` | 100% dei finding con fattori e punteggi di A e di B e versione della configurazione: sui tre pilota e sui primi due repository del proprietario in entrambe le misure, e sugli 88 finding di `repo-3` | **superata** sui report. Nel database non è misurata sui repository del gate: non c'è un server del pilota (I-06) |
| **G2.b** Ordinamento validato | X-04 | Tau-b di A da −0,584 a −0,310 e di B da −0,574 a −0,250; al massimo 1 dei primi 10 in comune; soglia 0,5 e 6 | **non superata**, su nessun repository |
| **G2.c** Variante predefinita scelta | X-06, ADR-0031, `PROJECT.md` §18 | Regola del 2026-11-26, punto 4 | **decisione registrata: nessuna variante scelta.** A resta predefinita in via provvisoria |
| **G2.d** Scansione PR sotto i 10 minuti | X-05 | 20,1, 172,6 e 263,9 s sulle PR di riferimento dei tre pilota | **superata**, con i limiti di X-05 |

**Effetto sul prodotto: nessun cambio di comportamento.** `levels.source: provisional`, gate sui livelli di ADR-0009, A e B in ombra.

**Scostamenti**

- **Rispetto a §13** non c'è un ordinamento "validato dai team": un solo valutatore, il proprietario, autore del prodotto, su repository propri (D2-03).
- **D2-10** prevedeva di attivare i livelli da punteggio dopo la scelta della variante: restano spenti (deciso il 2026-11-26, prima dell'ordinamento, e coerente con l'esito).
- **Raccolta del giudizio** in quattro gruppi con pari merito, con la dashboard locale, non prevista dal protocollo del 2026-11-13.
- **Ordinamenti dei primi due repository** consegnati prima come copie di quello di Claude, poi rifatti: l'indipendenza è una dichiarazione del proprietario.
- **`repo-3`** scansionato con un pacchetto più recente e con EPSS e KEV di nove giorni dopo.
- **Letteratura:** le definizioni di Martini et al. (ECSA 2018) e quelle degli smell e della Variante B non sono confrontate con le pubblicazioni (ADR-0020 e 0023 restano `Proposto`).

I limiti della misura sono in X-02, X-04 e X-05. §13 chiede di confermare i valori dopo il pilota: soglie dei livelli, pesi e fattori **non sono confermati**. La chiusura della Fase 2 con G2.b non superata è materia di X-09 e resta da decidere.

## X-09 — Chiusura della Fase 2 (2026-11-27)

**Decisione dell'utente: la Fase 2 si chiude con i limiti dichiarati.** §13 vuole che ogni fase si chiuda con un gate misurabile: il Gate 2 è misurato e **non superato** (X-08), e la chiusura non lo cambia. Il limite principale è che **l'ordine di priorità del prodotto non è validato**.

### Definition of Done (§17)

| Voce | Evidenza | Esito |
| --- | --- | --- |
| Test e copertura | 5.113 test Python superati e 519 saltati in locale, 117 test web; copertura di `ca-core` 99,0%, `ca-graph` 95,9%, `ca-integrations` 98,7%, `ca-api` 87,6% (minimo 80%, imposto sul totale); nessun test marcato `xfail`. `ca-cli` e `ca-plugins` non sono nella misura | soddisfatta |
| Schemi aggiornati e validati | `schema_export --check` e `openapi_export --check` | soddisfatta |
| Documentazione utente | `doc/utente/`, aggiornata il 2026-11-27 con l'esito del gate | soddisfatta |
| Telemetria per le operazioni lunghe | Durate nel report; metriche del server (B-13) | soddisfatta in forma minima: niente tracce, log OTLP né cruscotti (Fase 4) |
| Auto-analisi senza critici o alti nuovi | X-07; in CI l'Action con `fail-on: critico,alto` sul progetto, verde su `main` al commit `68f9a53` | soddisfatta con i livelli provvisori e le eccezioni approvate; con la Variante B e i livelli da punteggio non lo era (X-07) |

**CI verde su `main`.** La chiusura vale quando `verify` (con `server-integration`), `e2e` ed `e2e-action` sono verdi sul commit di `main` che la contiene; l'evidenza è la cronologia della CI.

**Voci di §13:** tutte spuntate tranne le integrazioni CI, per la parte rinviata (GitLab e pubblicazione). **ADR 0016..0030:** `Accettato` tranne 0020, 0023, 0024 e 0027, riaperti con motivo (`doc/adr/README.md`).

### Riporti

Proprietario di tutti: Riccardo Roveda, per la decisione che li sblocca.

| Voce | Stato alla chiusura | Cosa la sblocca |
| --- | --- | --- |
| D2-14 licenze dei motori e componenti nuovi | rinviata | la sua approvazione, prima di distribuire immagini |
| D2-16 destinazione privata e gratuita delle immagini | criterio deciso il 2026-11-10; nessuna immagine resa disponibile | la scelta di pubblicare |
| I-04 primo rilascio, I-07 plugin nuovi, N-09 Action e componente | rinviati | decisione di pubblicazione del 2026-11-10, D2-14, D2-16 |
| E-05 mirror dei feed | fuori dalla Fase 2 (D2-05) | un lavoro futuro che scelga di avere un mirror |
| E-04 origine dei feed | chiuso in parte: mancano OSV, trivy e il flag della CLI | solo lavoro |
| N-07, N-08 componente GitLab | scritto, mai eseguito su GitLab | D2-12 |
| I-06 ambiente del pilota con server | non realizzato | D2-06 |
| Ordinamento non validato (G2.b) | aperto | un lavoro sul punteggio provato su **campioni nuovi** (ADR-0031) |
| Definizioni confrontate con le pubblicazioni | aperto (ADR-0020, 0023) | i testi di §19 |

**Limiti che restano da dire a chi usa il prodotto:** livelli e punteggi non sono validati; un solo valutatore; le soglie dei livelli da punteggio non sono calibrate (X-02, X-07); la UI non è stata provata con un lettore di schermo (`PRODUCT.md`).
