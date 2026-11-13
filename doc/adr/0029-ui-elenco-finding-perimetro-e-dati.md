# ADR-0029: UI dell'elenco finding, perimetro e dati

- Stato: Proposto, in `IPOTESI` su D2-15 (perimetro proposto, non ancora confermato dall'utente). Prove con C-01, C-08 e W-04..W-07
- Data: 2026-11-13
- Decisione umana richiesta: sì, D2-15 per il perimetro
- Riferimenti: §1, §4.1, §9.2, §13; ADR-0016, 0017, 0018; `doc/ux/fase-2.md` (U-01); lacune 1 e 2 del piano

## Contesto

§13 chiede "UI elenco finding" senza descrivere pagine. U-01 le ha definite: scelta del repository, lista dei finding con dettaglio e triage, scansioni. §9.2 non basta a servirle: mancano l'elenco dei repository e delle scansioni, il dettaglio di un finding, l'utente corrente, e il contenuto di "stato e riepilogo" di una scansione. §1 promette "i passi per risolverlo", ma `Finding` non ha un campo per questo.

Questo ADR fissa quali endpoint e quali campi servono alle viste di U-01. La forma esatta (nomi dei campi, esempi, codici di errore) è il contratto di C-08, nel flusso di ADR-0017.

## Perimetro

Entrano in Fase 2 le viste di U-01: repository, lista dei finding, dettaglio, triage ed eccezioni, scansioni e stato della scansione.

Restano fuori: aggregati, trend, grafici, viste su più repository, vista del grafo, gestione di utenti e ruoli. Proposta per le due domande di U-01, da confermare con D2-15:

- tier ed esposizione di un repository si registrano solo dall'API (ADR-0028), senza pagina;
- nessun triage su più finding insieme.

## Endpoint

Tutti sotto `/v1`, autenticati (ADR-0019), nel tenant dell'identità (ADR-0018). In grassetto quelli che §9.2 non ha.

| Metodo e percorso | Serve a | Contenuto |
| --- | --- | --- |
| **`GET /me`** | Barra superiore, azioni | Identità, ruoli, tenant |
| **`GET /repositories`** | Scelta del repository | Pagina di repository con nome, provider, branch principale e riepilogo della scansione corrente |
| **`GET /repositories/{id}`** | Barra superiore | Un repository, con tier ed esposizione se registrati |
| **`GET /repositories/{id}/scans`** | Scansioni | Pagina di riepiloghi: tipo, ref, numero della PR, commit, stato, inizio, durata |
| `POST /scans` | CI | Ingestione (ADR-0016) |
| `GET /scans/{id}` | Stato della scansione | Riepilogo più plugin, avvisi, snapshot dei feed e, per una PR, conteggi di nuovi, esistenti e risolti |
| `GET /scans/{id}/sarif` | Esportazione | SARIF aggregato |
| `GET /repositories/{id}/findings` | Lista | Pagina di finding in forma breve; vedi "Lista" |
| **`GET /findings/{id}`** | Dettaglio | Finding completo, occorrenza nella scansione corrente, eccezioni delle due origini, registro delle modifiche |
| `PATCH /findings/{id}` | Triage | Stato, owner, eccezione con motivazione e scadenza |
| `GET /repositories/{id}/sbom`, `/graph` | Solo API | B-11 |

`PATCH /repositories/{id}` per tier ed esposizione è di ADR-0028. I webhook e l'avvio degli agenti restano fuori (ADR-0016).

"Stato e riepilogo" di `GET /scans/{id}` è definito così: i campi del report che non sono finding. Plugin con versione, esito, motivo, durata, firma e isolamento; avvisi con codice e messaggio; stato; configurazione di gate effettiva; snapshot dei feed. Nessun dato nuovo: il server li ha dal report.

## Lista dei finding

`GET /repositories/{id}/findings`

- **Ambito.** Senza altro parametro: i finding della scansione corrente del repository (ADR-0018). Con `scan`: quelli di una scansione data, che è il modo di vedere una PR. Così i finding nuovi di una PR non richiedono un endpoint a parte.
- **Filtri.** `level`, `category`, `status`, `tool`, ciascuno ripetibile; `new` booleano, con il significato di ADR-0025; `q` per la ricerca: sottostringa senza distinzione tra maiuscole e minuscole su titolo, regola, percorso e purl, almeno due caratteri, nessuna espressione regolare.
- **Predefiniti.** Nessun filtro implicito sul server: "aperti e in corso" è il predefinito della UI, che lo mette nella richiesta. Un consumatore dell'API senza filtri riceve tutto.
- **Ordinamento.** Parametro `sort`. Predefinito `impact`: livello attivo dal più grave, poi i nuovi prima degli esistenti, poi prima rilevazione dalla più recente, poi `id`, così l'ordine è totale e stabile. Altri valori: `first_seen`, `path`, `score_a`, `score_b`. Dopo il Gate 2, dentro un livello `impact` userà il punteggio della variante predefinita: è una modifica del significato di un valore esistente e va annunciata come tale (ADR-0017).
- **Paginazione.** A cursore: `limit` (predefinito 50, massimo 200) e `cursor` opaco. La risposta porta `items` e `next_cursor`, nullo all'ultima pagina. Il cursore vale per la stessa combinazione di filtri e ordinamento; altrimenti è un errore di validazione. Nessuna paginazione a numero di pagina: l'elenco cambia a ogni ingestione.
- **Conteggi.** La risposta porta `total`, il numero di finding con i filtri attivi, e `total_new`. Sono conteggi della lista richiesta. Nessun conteggio per livello o per categoria: sarebbero i primi aggregati, e sono della Fase 4.
- **Forma breve.** Un elemento della lista ha i campi della tabella di U-01 più `id` e `fingerprint`: livello e sua origine, titolo, regola, categoria, strumenti, posizione, stato con l'origine dell'eccezione, `new`, prima e ultima rilevazione, owner, punteggio e livello delle due varianti in ombra. Evidenze, fattori e passi di correzione stanno solo nel dettaglio.

B-08 misura i tempi di risposta su un volume pari al pilota più grande. Se `total` risultasse troppo costoso, la regola di ripiego è un conteggio esatto fino a una soglia in configurazione e "almeno N" oltre, dichiarato da un campo booleano.

## Dettaglio e triage

`GET /findings/{id}` restituisce il `Finding` del contratto (stesso schema dei report, ADR-0017) e accanto, non dentro:

- l'occorrenza nella scansione corrente, con fattori ed evidenze delle due varianti;
- le eccezioni, ciascuna con origine (`server` o `repository`), motivazione, scadenza e approvatore, e per quelle del repository l'indicazione che l'approvatore è dichiarato e non verificato (ADR-0018);
- il registro delle modifiche, dal più recente.

`PATCH /findings/{id}`:

- Un corpo cambia una cosa: lo stato, l'owner, oppure crea o revoca un'eccezione. Richieste composte sono un errore di validazione, così ogni riga del registro ha un significato solo.
- `falso_positivo` richiede una motivazione. `accettato` si ottiene solo creando un'eccezione, con motivazione e scadenza futura obbligatorie. `risolto` non è assegnabile (ADR-0018).
- La durata massima di un'eccezione sta nella configurazione del server; predefinito 365 giorni. Oltre: errore di validazione con il limite nel messaggio.
- `approved_by` non è nel corpo: è l'identità autenticata.
- `owner` è un testo libero, al più 200 caratteri. Il server non ha un elenco di utenti da cui scegliere: gli utenti sono dell'IdP. ADR-0019 può restringerlo.
- Ruoli richiesti: quelli della tabella di U-01, imposti dal server. La UI li legge da `GET /me` per disattivare le azioni; la decisione è sempre del server.

## Passi di correzione

`Finding` riceve un campo facoltativo `remediation` (C-01, aggiunta compatibile):

| Campo | Contenuto |
| --- | --- |
| `text` | I passi, testo semplice |
| `references` | Elenco di indirizzi, come stringhe |
| `source` | `tool`, `rule` o `derived` |

Fonti, in ordine di preferenza:

1. **`tool`**: il testo di aiuto della regola nel SARIF del plugin (`help.text`) e il suo `helpUri`. Si usa solo la forma testuale; `help.markdown` si ignora.
2. **`rule`**: per le regole proprie del prodotto (policy di licenze, regole Semgrep incluse, finding `health`), un testo scritto con la regola.
3. **`derived`**: per una dipendenza vulnerabile di cui lo strumento riporta la versione corretta, una frase a schema fisso: aggiornare il pacchetto a quella versione o successiva. La versione viene dal plugin, la frase dal nucleo.

Senza nessuna delle tre il campo è nullo e la UI lo dice (U-01). Nessun testo generato: gli LLM arrivano in Fase 3 e restano distinti dal dato deterministico.

Regole di sicurezza:

- Il testo è sempre reso come testo. Né l'API né la UI lo interpretano come HTML o Markdown, e gli indirizzi in `references` non diventano collegamenti attivi senza essere mostrati per esteso.
- Lunghezza limitata e caratteri di controllo rimossi, come per gli altri testi liberi del report.
- Il testo di aiuto è della regola, non del risultato: è uguale per tutti i finding della stessa regola e non contiene contenuto del repository analizzato. Gli adattatori che oggi riducono le regole al solo `id` (ADR-0007) possono lasciare passare `help.text` e `helpUri`; l'invariante sui segreti di ADR-0012 non cambia, perché riguarda risultati e frammenti di codice.

L'estensione del contratto dei plugin (testo di aiuto nelle regole, versione corretta nelle proprietà) è un emendamento di ADR-0007 in A-16 e tocca `plugin-sarif-properties`.

## Conseguenze

- §9.2 guadagna quattro endpoint di lettura e la definizione di due esistenti; A-17 la aggiorna.
- Il contratto `finding` cresce di un campo facoltativo; i report della Fase 1 restano validi.
- La lista non offre conteggi per livello o categoria: i filtri della UI non mostrano quanti finding nasconde ciascun valore. È il prezzo di non introdurre aggregati prima della Fase 4.
- Finché gli adattatori non lasciano passare il testo di aiuto, "Come risolvere" è vuoto per quasi tutti i finding: i plugin nuovi (P-01..P-05) nascono con il testo, quelli della Fase 1 si aggiornano in un task da aggiungere al piano dopo A-16.
- Se D2-15 allarga il perimetro, ogni vista aggiunta torna qui prima di C-08.
