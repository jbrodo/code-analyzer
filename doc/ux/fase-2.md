# UX della Fase 2 — Mappa delle pagine e flussi (U-01)

Stato: `IPOTESI` su D2-15 (perimetro proposto, da confermare) e su D2-02 per i ruoli. Scritto il 2026-11-13.

La UI della Fase 2 è una sola cosa: **la lista dei finding di un repository, ordinata per impatto**, con il dettaglio e il triage accanto. Non ci sono viste di portfolio, aggregati, trend né grafici: sono della Fase 4. Ogni numero mostrato porta a un'azione o spiega uno stato.

Token e componenti sono in U-02, i criteri di accessibilità in U-03, la resa dei fattori di punteggio e dei valori in ombra in U-04. Questo documento dice quali pagine esistono, cosa contengono e quali dati servono.

## 1. Pagine

| Pagina | Indirizzo | Scopo |
| --- | --- | --- |
| Repository | `/` | Scegliere un repository. Con un solo repository si passa direttamente alla sua lista |
| Finding | `/r/{repository}` | Vista centrale: lista ordinata, filtri, pannello di dettaglio |
| Finding, dettaglio aperto | `/r/{repository}/f/{finding}` | La stessa vista con il pannello aperto su un finding: è un indirizzo condivisibile, non una pagina diversa |
| Scansioni | `/r/{repository}/scans` | Elenco delle scansioni ricevute |
| Scansione | `/r/{repository}/scans/{scansione}` | Stato, plugin, avvisi; per una PR, i finding nuovi di quella scansione |
| Accesso | Gestito dall'IdP | La UI ha solo la pagina di ritorno e quella di errore di accesso |

Filtri, ordinamento e finding selezionato stanno nell'indirizzo: un collegamento copiato riapre la stessa vista.

Fuori dal perimetro: registrazione di tier ed esposizione di un repository (B-10 la offre dall'API; una pagina di impostazioni va confermata con D2-15), gestione di utenti e ruoli (è dell'IdP), SBOM e grafo (solo API, B-11).

### Struttura comune

- **Barra superiore:** selettore del repository; stato dell'ultima scansione; utente e ruolo.
- **Stato della scansione**, sempre visibile nella barra: `Completa` o `Parziale`, commit abbreviato, quanto tempo fa. È un collegamento alla pagina della scansione. Con `Parziale` riporta anche il numero di plugin falliti, in testo.
- Nessuna barra laterale di navigazione: le pagine sono tre.

## 2. Lista dei finding

### Contenuto

Tabella densa, una riga per finding.

| Colonna | Contenuto | Note |
| --- | --- | --- |
| Livello | `Critico`, `Alto`, `Medio`, `Basso` | Parola sempre presente; il colore la accompagna, non la sostituisce |
| Problema | Titolo; sotto, in piccolo, l'identificativo della regola | Testo semplice, mai interpretato come HTML o Markdown |
| Categoria | Qualità, architettura, test, SAST, dipendenze, licenze, segreti, IaC, salute | |
| Posizione | `percorso:riga` per il codice; pacchetto e versione per le dipendenze | Percorso troncato al centro, completo nel dettaglio |
| Stato | Aperto, in corso, accettato, falso positivo, risolto | Per `accettato`, l'origine dell'eccezione (vedi 4.3) |
| Novità | `Nuovo` se è comparso con l'ultima scansione | Testo, non un pallino |
| Prima rilevazione | Età: "3 giorni", "5 mesi" | Data esatta nel dettaglio |
| Assegnato a | Owner, se c'è | |

I punteggi in ombra di A e B non sono colonne predefinite: come e se mostrarli nella lista lo decide U-04, perché una colonna di punteggio accanto al livello attivo suggerirebbe un ordinamento prima che il Gate 2 lo abbia validato.

### Ordinamento

Predefinito: livello attivo dal più grave, e a parità di livello i finding nuovi prima degli esistenti, poi dal più recente. È una proposta: fino al Gate 2 il livello attivo è quello provvisorio di ADR-0009 (D2-10), che non ha un punteggio con cui ordinare dentro un livello. La decide ADR-0029.

### Nuovi ed esistenti

- Con l'ordinamento predefinito, dentro ogni livello i nuovi stanno in cima e portano la parola `Nuovo`.
- Un filtro rapido "Solo nuovi" restringe la lista. Il conteggio accanto al filtro dice quanti sono.
- Nella pagina di una scansione di PR la lista mostra solo i finding nuovi di quella PR: è la domanda che la PR pone.

### Filtri

Livello, categoria, stato, solo nuovi, strumento. Predefinito: stato `aperto` e `in corso`, tutti i livelli. Ricerca per testo su titolo, regola e percorso.

I filtri attivi sono visibili come elenco sopra la tabella, ciascuno rimovibile, con "Azzera filtri". Accanto, il numero di finding che la lista contiene con quei filtri.

### Tastiera

Frecce o `j`/`k` per muoversi tra le righe, `Invio` apre il dettaglio, `Esc` lo chiude e riporta il fuoco sulla riga, `/` porta il fuoco sulla ricerca. Le scorciatoie valgono solo con il fuoco nella tabella. Dettagli in `doc/ux/accessibilita.md`.

## 3. Dettaglio di un finding

Pannello a destra della lista, che resta visibile e navigabile. Su schermi stretti il pannello occupa la pagina.

Sezioni, in quest'ordine:

1. **Intestazione.** Livello, titolo, regola, categoria, strumenti di origine, stato, `Nuovo` se lo è.
2. **Come risolvere.** I passi di correzione, come testo. È la promessa di §1 e sta in alto. Se lo strumento non fornisce passi: "Questo strumento non fornisce indicazioni di correzione", con la regola e la documentazione citata come testo.
3. **Dove.** Percorso e righe con il commit della scansione; per una dipendenza, pacchetto, versione e catena transitiva; per una licenza, espressione SPDX e file o pacchetto. Il codice non si mostra: il server non lo ha (ADR-0016).
4. **Perché questo livello.** Origine del livello attivo (severità dello strumento, policy, predefinito). Sotto, i fattori G, P, E, C delle due varianti in ombra con evidenze e fonti, secondo U-04. Per una vulnerabilità: identificativi CVE e CWE, EPSS e KEV con la data dello snapshot e l'attribuzione di EPSS (ADR-0024); se un feed mancava, lo dice.
5. **Stato e storia.** Stato attuale, owner, scadenza; eccezioni con la loro origine; registro delle modifiche: chi, quando, cosa, motivazione. Prima e ultima rilevazione.
6. **Azioni** (sezione 4), in fondo e fisse al bordo del pannello.

Tutto il contenuto che viene dal report (titolo, messaggio, passi, evidenze, percorsi) si rende come testo. Nessun collegamento generato da quel contenuto è attivo senza essere mostrato per esteso.

## 4. Flussi

### 4.1 Triage

Dalla lista: apro un finding, leggo "Come risolvere" e "Perché questo livello", scelgo un'azione, passo al successivo senza tornare indietro (il fuoco torna alla riga, `j` va avanti).

| Azione | Effetto | Dati obbligatori | Ruolo |
| --- | --- | --- | --- |
| Prendi in carico | Stato `in corso`, owner | Owner (predefinito: chi agisce) | triage |
| Assegna | Cambia owner | Owner | triage |
| Segna come falso positivo | Stato `falso positivo` | Motivazione | approvatore |
| Accetta con eccezione | Stato `accettato` | Motivazione e scadenza | approvatore |
| Riapri | Stato `aperto` | Motivazione se si revoca un'eccezione | triage; approvatore per revocare |

`Risolto` non è un'azione: lo assegna il server quando il finding sparisce da una scansione completa (ADR-0018). La UI lo spiega dove lo mostra.

Le azioni non permesse dal ruolo sono visibili ma disattivate, con il motivo ("Serve il ruolo approvatore"): chi fa triage deve sapere che l'azione esiste e a chi chiederla. Un `lettore` non vede la sezione delle azioni.

Dopo un'azione la riga si aggiorna sul posto. Se con i filtri attivi il finding non appartiene più alla lista, resta visibile fino al prossimo cambio di filtro o ricaricamento, marcato con il nuovo stato: farlo sparire sotto il cursore fa perdere il punto.

### 4.2 Eccezione con motivazione e scadenza

Dialogo con due campi obbligatori: motivazione (testo) e scadenza (data futura). Mostra chi approva, cioè l'utente autenticato, non modificabile.

Il dialogo dice una cosa che l'utente non può indovinare: **il gate della CI non legge le eccezioni del server** (ADR-0018). Sotto la conferma mostra il frammento da aggiungere a `.code-analyzer.yml` per far valere l'eccezione anche nel gate, con fingerprint, motivazione e scadenza già compilati e un pulsante per copiarlo.

### 4.3 Eccezioni: due origini

| Origine | Come compare |
| --- | --- |
| Approvata sul server | "Accettato da {utente} fino al {data}", con la motivazione |
| Dichiarata nel repository | "Accettato nel repository (`.code-analyzer.yml`) fino al {data}. Approvatore dichiarato: {testo}, non verificato" |

Un'eccezione scaduta resta nella storia come scaduta e il finding torna aperto. Un'eccezione che scade entro 30 giorni lo dice nella colonna dello stato.

### 4.4 Stato della scansione

Pagina di una scansione:

- **Riepilogo:** tipo (completa o PR, con numero e branch), commit, inizio, durata, stato.
- **Se è parziale**, in cima e in chiaro: quali plugin sono falliti e cosa comporta. "I finding di questi strumenti non sono aggiornati. Nessun finding è stato segnato come risolto da questa scansione."
- **Plugin:** nome, versione, esito, motivo del fallimento, durata, firma, isolamento, snapshot dei feed con la loro data.
- **Avvisi:** codice e messaggio, uno per riga.
- **Per una PR:** finding nuovi, esistenti e risolti rispetto al branch base, con la lista dei nuovi.

Lo stesso avviso di scansione parziale compare come fascia sopra la lista dei finding finché la scansione corrente è parziale, con il collegamento a questa pagina.

## 5. Stati di ogni vista

| Stato | Lista dei finding | Dettaglio | Scansioni |
| --- | --- | --- | --- |
| Caricamento | Struttura della tabella con righe segnaposto; filtri già utilizzabili | Struttura delle sezioni | Righe segnaposto |
| Vuoto, nessun repository | "Nessun repository. Le scansioni arrivano dalla CI con `code-analyzer upload`", con il collegamento alla guida | — | — |
| Vuoto, nessuna scansione | "Nessuna scansione ricevuta per questo repository", stessa indicazione | — | Idem |
| Vuoto, nessun finding | "Nessun finding aperto", con stato e data dell'ultima scansione: zero finding da una scansione parziale non è una buona notizia, e la fascia lo dice | — | — |
| Vuoto per i filtri | "Nessun finding con questi filtri", con "Azzera filtri" | — | — |
| Errore | Titolo e codice dell'errore del server (ADR-0017), "Riprova"; i filtri restano | Idem, il pannello resta aperto | Idem |
| Sessione scaduta | Ritorno all'accesso, poi alla stessa vista con gli stessi filtri | Idem | Idem |
| Permesso negato | "Non hai accesso a questo repository" | — | — |
| Non trovato | — | "Finding non trovato o non più presente" | "Scansione non trovata" |
| Scansione parziale | Fascia sopra la lista | Nota nella sezione "Stato e storia" se il finding viene da un plugin fallito nella scansione corrente | Vedi 4.4 |
| Azione fallita | — | Il dialogo o il pannello resta aperto con l'errore del server e i dati inseriti | — |

Nessuna azione mostra un esito positivo prima della risposta del server.

## 6. Dati necessari e lacune per `architect`

Per ogni vista, cosa serve dall'API. Le righe marcate **Lacuna** non sono in §9.2 o non hanno una definizione: servono ad A-14 (ADR-0029), salvo dove è indicato un altro ADR.

| Vista | Dato | Stato |
| --- | --- | --- |
| Repository | Elenco dei repository visibili all'utente, con nome e ultima scansione (stato, inizio, commit) | **Lacuna** (nota: lacuna 2) |
| Barra superiore | Utente autenticato, ruoli, tenant | **Lacuna:** serve un endpoint sull'utente corrente (ADR-0019) |
| Lista | Finding con i campi della tabella; filtri per livello, categoria, stato, nuovi | In §9.2 |
| Lista | Filtro per strumento e ricerca per testo | **Lacuna** |
| Lista | Numero di finding con i filtri attivi, e numero dei nuovi | **Lacuna.** È un conteggio della lista, non un aggregato di portfolio |
| Lista | Ordinamento predefinito e ordinamenti ammessi; paginazione | **Lacuna** |
| Lista | Definizione di `Nuovo` fuori da una PR: rispetto a quale scansione | **Lacuna** (ADR-0025) |
| Dettaglio | Un finding per identificativo, con occorrenza corrente, eccezioni delle due origini e registro delle modifiche | **Lacuna** (nota: lacuna 2; registro in ADR-0018) |
| Dettaglio | Passi di correzione | **Lacuna:** il campo manca dal modello (ADR-0029, C-01) |
| Dettaglio | Origine del livello, fattori e punteggi delle due varianti, evidenze | Modello da ADR-0021; resa in U-04 |
| Dettaglio | Stato di EPSS e KEV per finding e identità degli snapshot | ADR-0024, C-04 |
| Azioni | Modifica di stato, owner ed eccezione, con errori distinti per ruolo e validazione | In §9.2; codici di errore in ADR-0017 |
| Azioni | Forma di `owner`: testo libero o identità di un utente | **Lacuna** (ADR-0019) |
| Eccezione | Durata massima ammessa di un'eccezione, se esiste | **Lacuna** |
| Eccezione | Fingerprint del finding, per il frammento di `.code-analyzer.yml` | Presente nel modello |
| Scansioni | Elenco delle scansioni di un repository con tipo, ref, PR, stato, inizio, durata | **Lacuna** (nota: lacuna 2) |
| Scansione | Plugin, avvisi e snapshot dei feed della scansione | **Lacuna:** §9.2 dice "stato e riepilogo" senza definirlo; i dati sono nel report |
| Scansione di PR | Finding nuovi, esistenti e risolti di quella scansione | **Lacuna:** §9.2 filtra i nuovi solo per repository |

Domande aperte per D2-15:

1. La registrazione di tier ed esposizione ha una pagina in Fase 2, o resta solo nell'API?
2. Il triage su più finding insieme (selezione multipla) entra in Fase 2? La proposta è no: P-07 ha tolto il caso che lo rendeva necessario, e un'eccezione vale per un finding.
