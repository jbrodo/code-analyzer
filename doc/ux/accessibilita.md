# Criteri di accessibilità della Fase 2 (U-03)

Obiettivo: WCAG 2.2 livello AA sulle viste di `doc/ux/fase-2.md`. Scritto il 2026-11-13.

Ogni criterio dice cosa deve essere vero e come si verifica: **A** con un test automatico in W-08 (axe e test dei componenti), **M** a mano nella revisione U-05. Un criterio verificabile solo a mano ha comunque un passo preciso da eseguire.

## 1. Regole generali

| # | Criterio | WCAG | Verifica |
| --- | --- | --- | --- |
| G1 | Ogni pagina ha un titolo che nomina repository e vista, e un solo `h1` | 2.4.2, 1.3.1 | A |
| G2 | Regioni di pagina marcate: intestazione, navigazione, contenuto principale; un collegamento "Vai al contenuto" è il primo elemento raggiungibile | 1.3.1, 2.4.1 | A |
| G3 | Tutto ciò che si fa con il mouse si fa con la tastiera, senza trappole | 2.1.1, 2.1.2 | A per i componenti, M per i flussi completi |
| G4 | L'ordine del fuoco segue l'ordine visivo: barra superiore, filtri, tabella, pannello | 2.4.3 | M |
| G5 | Il fuoco è sempre visibile, con un indicatore di almeno 2 px e contrasto 3:1 rispetto allo sfondo, e non è coperto da elementi fissi (barra superiore, azioni fisse del pannello) | 2.4.7, 2.4.11, 1.4.11 | A per il contrasto, M per la copertura |
| G6 | Contrasto del testo almeno 4,5:1; 3:1 per testo grande, bordi dei campi e icone che portano significato. Vale per tema chiaro e scuro | 1.4.3, 1.4.11 | A |
| G7 | Nessuna informazione affidata al solo colore: livello, stato, novità ed esito dei plugin hanno sempre una parola | 1.4.1 | A: il nome accessibile contiene la parola; M sul resto |
| G8 | La pagina regge lo zoom al 200% e una larghezza di 320 px senza scorrimento orizzontale, salvo la tabella dei finding, che scorre dentro la propria regione | 1.4.4, 1.4.10 | M |
| G9 | Spaziatura del testo modificabile dall'utente senza perdita di contenuto | 1.4.12 | M |
| G10 | Bersagli dei controlli di almeno 24 per 24 px, o con spazio equivalente attorno | 2.5.8 | A |
| G11 | Nessun limite di tempo sulle azioni. Alla scadenza della sessione si torna all'accesso e poi alla stessa vista, con i dati del dialogo aperto conservati | 2.2.1 | M |
| G12 | Animazioni solo funzionali, disattivate con `prefers-reduced-motion`; nulla lampeggia | 2.3.3, 2.3.1 | A |
| G13 | Lingua della pagina dichiarata; il testo dei finding, che è in inglese o nella lingua dello strumento, non viene marcato con una lingua sbagliata | 3.1.1 | A |
| G14 | I nomi dei controlli sono coerenti tra le viste: la stessa azione ha lo stesso nome ovunque | 3.2.4 | M |
| G15 | Il contenuto dei finding è reso come testo: nessun markup proveniente dal report entra nell'albero di accessibilità | — (sicurezza, ADR-0029) | A |

## 2. Lista dei finding

La tabella è una tabella di dati con righe selezionabili, non una griglia modificabile.

| # | Criterio | WCAG | Verifica |
| --- | --- | --- | --- |
| L1 | Elemento `table` con didascalia che nomina repository e numero di finding; intestazioni di colonna con `scope="col"` | 1.3.1 | A |
| L2 | Ogni riga contiene un solo controllo raggiungibile con `Tab`: il titolo del finding, che apre il dettaglio. Il suo nome accessibile comprende livello e titolo | 2.4.4, 4.1.2 | A |
| L3 | Frecce su e giù, `j` e `k` spostano il fuoco tra le righe; `Home` e `Fine` vanno alla prima e all'ultima caricata; `Invio` apre il dettaglio | 2.1.1 | A |
| L4 | Le scorciatoie a un solo carattere (`j`, `k`, `/`) sono attive solo quando il fuoco è dentro la tabella. Altrove, e in ogni campo di testo, non fanno nulla: così non serve un'impostazione per disattivarle | 2.1.4 | A |
| L5 | La colonna ordinata dichiara il verso con `aria-sort`; il controllo di ordinamento è un pulsante nell'intestazione | 1.3.1, 4.1.2 | A |
| L6 | Il badge di livello ha come testo la parola del livello. Il colore non cambia il nome accessibile | 1.4.1 | A |
| L7 | `Nuovo` è testo nella riga, non un indicatore grafico | 1.4.1 | A |
| L8 | Percorsi troncati: il valore completo è nel nome accessibile e nel dettaglio, non solo in un suggerimento al passaggio del mouse | 1.3.1, 1.4.13 | A |
| L9 | Caricare altri finding avviene con un pulsante esplicito alla fine della tabella. Dopo il caricamento il fuoco resta sul pulsante e una regione di stato annuncia quante righe sono state aggiunte | 2.4.3, 4.1.3 | A |
| L10 | Cambiare un filtro non sposta il fuoco. Il numero di finding risultante viene annunciato da una regione di stato con `role="status"` | 3.2.2, 4.1.3 | A |
| L11 | I filtri sono controlli nativi o rispettano il modello ARIA corrispondente (gruppo di caselle, casella combinata); ogni filtro attivo è un pulsante "Rimuovi filtro {nome}" | 4.1.2, 1.3.1 | A |
| L12 | Stato di caricamento: la tabella ha `aria-busy` e le righe segnaposto sono nascoste alle tecnologie assistive | 4.1.3 | A |
| L13 | Stati vuoti ed errori sono testo nel flusso della pagina, con il pulsante di rimedio subito dopo; l'errore è annunciato con `role="alert"` | 3.3.1, 4.1.3 | A |
| L14 | La fascia di scansione parziale è testo prima della tabella nell'ordine di lettura, con il collegamento alla scansione | 1.3.2 | A |

## 3. Pannello di dettaglio

| # | Criterio | WCAG | Verifica |
| --- | --- | --- | --- |
| D1 | Il pannello è una regione con nome (il titolo del finding) e non un dialogo modale: la lista resta raggiungibile | 1.3.1, 4.1.2 | A |
| D2 | All'apertura il fuoco va al titolo del pannello; `Esc` lo chiude e riporta il fuoco alla riga di partenza | 2.4.3 | A |
| D3 | Le sezioni hanno intestazioni di livello coerente, nell'ordine di U-01 | 1.3.1, 2.4.6 | A |
| D4 | Fattori G, P, E, C e punteggi delle due varianti sono in una tabella o in un elenco di definizioni, mai solo in un grafico; ogni valore ha la sua etichetta per esteso | 1.1.1, 1.3.1 | A |
| D5 | Il registro delle modifiche è un elenco ordinato con data in formato leggibile e in `time` | 1.3.1 | A |
| D6 | Le azioni disattivate per ruolo restano raggiungibili da tastiera e dichiarano il motivo nel nome o nella descrizione accessibile | 4.1.2, 3.3.2 | A |
| D7 | Sotto i 768 px il pannello sostituisce la lista e ha un controllo "Torna alla lista" come primo elemento | 1.4.10, 2.4.3 | M |

## 4. Dialoghi di triage ed eccezione

| # | Criterio | WCAG | Verifica |
| --- | --- | --- | --- |
| T1 | Dialogo modale con nome e descrizione; il fuoco entra nel primo campo, resta nel dialogo, e alla chiusura torna al pulsante che lo ha aperto | 2.4.3, 4.1.2 | A |
| T2 | `Esc` chiude senza salvare. Se il dialogo contiene testo inserito, chiede conferma | 3.3.4 | A |
| T3 | Ogni campo ha un'etichetta visibile e associata; i campi obbligatori lo dicono nel testo dell'etichetta, non solo con un asterisco | 3.3.2, 1.3.1 | A |
| T4 | La scadenza si può scrivere come data, non solo scegliere da un calendario; il formato atteso è nell'etichetta | 2.1.1, 3.3.2 | A |
| T5 | Gli errori di validazione compaiono accanto al campo, associati con `aria-describedby`, e il fuoco va al primo campo in errore. L'errore dice cosa correggere | 3.3.1, 3.3.3 | A |
| T6 | Un errore del server lascia il dialogo aperto con i dati inseriti e mostra titolo e codice dell'errore | 3.3.1 | A |
| T7 | L'esito di un'azione è annunciato da una regione di stato, e lo stato nuovo è visibile nella riga | 4.1.3 | A |
| T8 | L'avviso "il gate della CI non legge le eccezioni del server" è testo nel dialogo, prima del pulsante di conferma nell'ordine di lettura. Il frammento da copiare è in un blocco di testo selezionabile, con un pulsante "Copia" che annuncia l'avvenuta copia | 1.3.2, 4.1.3 | A |
| T9 | L'autenticazione non richiede di ricordare o trascrivere nulla nella UI: è delegata all'IdP | 3.3.8 | M |

## 5. Scansioni

| # | Criterio | WCAG | Verifica |
| --- | --- | --- | --- |
| S1 | Elenco delle scansioni e tabella dei plugin sono tabelle di dati con didascalia e intestazioni | 1.3.1 | A |
| S2 | Stato della scansione ed esito di ogni plugin sono parole (`Completa`, `Parziale`, `Riuscito`, `Fallito`) | 1.4.1 | A |
| S3 | L'indicatore di stato nella barra superiore è un collegamento il cui nome dice stato, commit e tempo trascorso | 2.4.4 | A |
| S4 | Il tempo relativo ("2 ore fa") ha la data esatta nell'elemento `time` | 1.3.1 | A |

## 6. Come si verifica

- **W-08, automatico:** axe su ogni vista in ciascuno stato della tabella di U-01 (caricamento, vuoto, errore, parziale), nei due temi; test dei componenti per i criteri marcati A che axe non copre: gestione del fuoco, scorciatoie, regioni di stato, `aria-sort`. Un criterio A senza test è un difetto del task.
- **U-05, a mano:** i criteri marcati M, più una passata completa del flusso di triage solo da tastiera e una con un lettore di schermo, su lista, dettaglio ed eccezione. L'esito si registra criterio per criterio.
- Un test automatico verde non dimostra la conformità: axe copre una parte dei criteri. La revisione manuale non è facoltativa.
