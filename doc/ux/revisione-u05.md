# Revisione visiva e di accessibilità: lista di controllo (U-05)

Serve a chi fa la revisione a mano. Gli audit automatici (axe in jsdom, e in Chrome con il contrasto attivo)
sono già verdi; qui c'è ciò che si vede solo guardando e usando la UI. Ogni scostamento va in fondo, con
gravità e criterio, e l'utente decide se correggerlo o accettarlo.

## Preparazione

```
deploy/docker/server/build-dev-image.sh        # richiede uv, bun 1.4.4 e docker
export CA_DEV_DB_PASSWORD="$(openssl rand -hex 16)"
docker compose -f deploy/compose/server-dev.yaml up -d --wait
CA_UPLOAD_ALLOW_LOOPBACK_HTTP=1 uv run python deploy/compose/seed_dev.py
```

Poi aprire `http://127.0.0.1:8000`: l'immagine di sviluppo serve anche la SPA (l'IdP finto resta sulla porta 9000).
Per rivedere modifiche alla SPA senza ricostruire l'immagine: `bun install --cwd web --frozen-lockfile` e
`bun run --cwd web dev` (poi `http://localhost:5173`).

All'accesso l'IdP finto fa scegliere un ruolo: usare «tutti i ruoli» per il triage, «lettore» per verificare
che le azioni non si vedano, «triage» per vedere le azioni da approvatore disattivate con il motivo.
Alla fine: `docker compose -f deploy/compose/server-dev.yaml down --volumes`.

I dati di prova: quattro scansioni (due complete, una PR, e per ultima una **parziale** con semgrep fallito),
finding di quattro livelli e di categorie diverse, una dipendenza con la sua catena, un segreto, una licenza,
punteggi A e B con il ripiego della B su qualità, passi di correzione, un'eccezione del repository e un
finding il cui titolo contiene markup (deve comparire come testo). Per l'elenco dei finding nuovi e dei risolti
si apre la pagina della scansione di PR.

Ripetere ciascuna passata in **tema chiaro e scuro** (preferenza di sistema) e, dove indicato, a larghezze diverse.

## 1. Flusso di triage solo da tastiera (1280 px)

- [ ] Tab dalla cima: «Vai al contenuto», marchio, repository, stato scansione, utente, ricerca, filtri, tabella.
- [ ] `j`/`k`/frecce/`Home`/`Fine` spostano il fuoco tra i titoli; `/` porta alla ricerca solo dalla tabella.
- [ ] `Invio` apre il pannello; il fuoco va al titolo; `Esc` lo chiude e il fuoco torna alla riga.
- [ ] Prendi in carico → dialogo: il fuoco entra nel campo, resta nel dialogo, `Esc` chiude (con testo: chiede).
- [ ] Accetta con eccezione: data scritta a mano, errori accanto al campo, il frammento YAML si legge e «Copia» funziona.
- [ ] Dopo l'azione la riga mostra il nuovo stato e non sparisce; il fuoco non finisce sul corpo della pagina.
- [ ] Il fuoco è sempre visibile (2 px) e mai coperto da barra o intestazione fissa.

## 2. Resa visiva (quello che l'automazione non vede)

- [ ] Livelli: i quattro badge si distinguono anche con gli occhi socchiusi; la parola è leggibile; la colonna è allineata.
- [ ] Densità della tabella: righe da 36 px leggibili, titolo e regola su due righe senza taglio.
- [ ] Percorsi troncati al centro: si riconosce il nome del file.
- [ ] Pannello a 480 px: le tabelle dei fattori A e B stanno affiancate senza schiacciarsi; le evidenze si leggono.
- [ ] Le due varianti hanno lo stesso peso visivo: nessuna appare preferita (ordine, colore, dimensione).
- [ ] Fascia di scansione parziale: si nota, ma non allarma più del dovuto; il collegamento è chiaro.
- [ ] Dialogo: larghezza, spaziatura, pulsante principale e annulla; l'avviso sul gate si nota prima della conferma.
- [ ] Pagine delle scansioni: tabelle dei plugin e riepilogo leggibili, la sezione della baseline di una PR è chiara.
- [ ] Stati: caricamento (rallentare la rete dagli strumenti del browser), vuoto, errore (fermare l'API con `docker compose stop api`).
- [ ] Gerarchia generale: si capisce subito dove si è e qual è l'azione successiva. Niente che sembri decorazione.

## 3. Criteri «M» di `doc/ux/accessibilita.md`

- [ ] **G4** ordine del fuoco: barra, filtri, tabella, pannello.
- [ ] **G8** zoom al 200% e 320 px senza scorrimento orizzontale della pagina (la tabella scorre nella sua regione).
- [ ] **G9** spaziatura del testo modificata dall'utente (estensione o foglio di stile): nessun testo perso.
- [ ] **G11** sessione scaduta: con un dialogo aperto e del testo scritto, ricaricare la pagina e riaprire il dialogo; il testo c'è.
      (Il dialogo non si riapre da solo: è noto.)
- [ ] **G14** la stessa azione ha lo stesso nome ovunque (Prendi in carico, Assegna, Segna come falso positivo, …).
- [ ] **D7** sotto i 768 px il pannello sostituisce la lista e ha «Torna alla lista» come primo elemento.
- [ ] **T9** nessuna password da ricordare o trascrivere nella UI.

## 4. Lettore di schermo (Orca su Linux, NVDA o VoiceOver altrove)

Lista, dettaglio e dialogo dell'eccezione, solo con la tastiera.

- [ ] Il titolo della pagina e dei pannelli si annuncia; la tabella ha didascalia, intestazioni e un solo controllo per riga.
- [ ] Cambiando un filtro si sente il numero di finding; «Carica altri» annuncia le righe aggiunte.
- [ ] Il livello si sente come parola; «Nuovo» si sente.
- [ ] Le azioni disattivate dicono il motivo.
- [ ] Il dialogo dice nome e descrizione; gli errori si sentono accanto al campo; «Copiato» si sente.
- [ ] Il cambio di stato dopo un'azione si annuncia.

## Cosa si sa già

- Il testo scritto in un dialogo sopravvive a un ricaricamento, ma il dialogo non si riapre da solo (G11).
- «Nuovo» compare su tutti i finding della prima scansione: è la definizione di ADR-0025.
- Gli intervalli dei livelli e i pesi non sono nella risposta del finding (lacuna di U-04, per A-14).
- Il contrasto è verificato sui token e, in Chrome, sulle viste elencate in `doc/plan/fase-2.md` (U-05).

## Esito del 2026-11-26

Revisione eseguita da Claude con la skill `impeccable` (comando `audit`), **al posto della revisione a mano** per decisione dell'utente. Server di sviluppo con i dati di `seed_dev.py`, Google Chrome senza finestra guidato dal protocollo di debug (loopback), temi chiaro e scuro, larghezze 1280, 767, 375 e 320 px, zoom al 200% emulato (640×400 a densità 2), spaziatura del testo di G9. In più, il rilevatore statico della skill su `web/src`, la build e i controlli sui token. **Non sostituisce una persona:** nessuna passata con un lettore di schermo, resa visiva giudicata su istantanee.

### Punteggio dell'audit: 15 su 20 (buono)

| Dimensione | Voto (0–4) | Nota principale |
| --- | --- | --- |
| Accessibilità | 3 | Tastiera, fuoco e dialoghi corretti; leggibilità debole allo zoom |
| Prestazioni | 3 | Giudicate solo dal pacchetto: 129 kB di JS e 5,8 kB di CSS compressi, nessuna immagine; tempi a runtime non misurati |
| Temi | 4 | Nessun colore fuori dai token; tema scuro leggibile |
| Adattamento allo schermo | 2 | Nessuno scorrimento orizzontale della pagina, ma barra alta, titoli illeggibili a 320 px, pannello che scorre di lato |
| Coerenza dell'implementazione | 3 | Sistema coerente; pochi difetti di layout con causa precisa |

Il rilevatore statico segnala un solo punto, la barra di 2 px sulla riga selezionata (`app.css:285`): **falso positivo** in questo contesto, è l'indicatore di selezione insieme allo sfondo.

### Scostamenti

Gravità: bloccante, seria, minore. **Decisione dell'utente del 2026-11-27: correggerli tutti.** Fatto: vedi «Correzioni» sotto la tabella.

| # | Vista | Cosa si è visto | Gravità | Criterio | Causa e correzione proposta |
| --- | --- | --- | --- | --- | --- |
| 1 | Elenco | Accanto a ogni livello compaiono due puntini («Critico ‥»), a tutte le larghezze | seria | resa visiva, livelli | `.col-level` è 104 px, etichetta e margini ne chiedono circa 124: portarla ad almeno 7,75rem (`app.css`) |
| 2 | Elenco, pannello | I titoli sono tagliati: 3 su 7 a 1280 px (281 px disponibili), tutti e 7 a 320 px (112 px), con il percorso troncato | seria | «titolo e regola su due righe senza taglio», G8 | Colonne fisse troppo larghe (posizione 272 px, in gran parte vuote) e `Problema` prende il resto: ridurle e dare una larghezza minima a `Problema` |
| 3 | Pannello | Barra di scorrimento orizzontale sempre presente nel pannello da 480 px | seria | G8, «le tabelle dei fattori stanno affiancate senza schiacciarsi» | Le tabelle A e B (`table.factors`) sporgono di 19 px |
| 4 | Barra in alto | Allo zoom 200% e su telefono la barra, fissa, occupa un quarto o più dell'altezza; allo zoom restano circa 111 px di tabella, meno di due righe | seria | G8, SC 1.4.10 (lo scorrimento resta in una sola direzione) | Barra compatta e non fissa sotto una certa altezza o larghezza |
| 5 | Tutte | L'etichetta «Repository» sta sopra il menu e tocca il bordo; la pagina scorre di 13 px anche quando tutto ci sta, e la barra delle azioni si sposta | seria | resa visiva | La barra è alta 61 px ma il layout ne sottrae 48 (`--size-topbar-height`): `.field` impone `flex-direction: column` e `.topbar .field-inline` non rimette `row` |
| 6 | Pannello | Due pulsanti principali in blu, «Prendi in carico» e «Accetta con eccezione» | minore | gerarchia, «qual è l'azione successiva» | Un solo pulsante principale (`TriageActions.tsx`) |
| 7 | Scansione di PR | «Vedi i 1 finding nuovi di questa scansione» | minore | lingua | Singolare e plurale in `ScanPage.tsx:94` |
| 8 | Dialogo | L'errore «Scrivi la motivazione.» resta dopo averla scritta, fino al nuovo invio | minore | T3, T5 | Togliere l'errore del campo quando cambia |
| 9 | Elenco | Con il fuoco sul riquadro della tabella (dodicesimo Tab) `j`, `k` e le frecce non fanno nulla; dalle righe funzionano | minore | L3, L4 | Dal riquadro, portare il fuoco alla prima riga |
| 10 | Elenco delle scansioni | La tabella è attaccata al collegamento «Torna ai finding» | minore | resa visiva | Spaziatura sopra la tabella |

### Correzioni (2026-11-27)

Rimisurate nello stesso Chrome sul server di sviluppo ricostruito, con gli stessi dati di prova.

| # | Prima | Dopo |
| --- | --- | --- |
| 1 | cella del livello 104 px per 119 di contenuto | nessuna cella tagliata a nessuna larghezza |
| 2 | titoli tagliati 3/7 a 1280 px, 7/7 a 320 px; percorsi lunghi tagliati in fondo | 0/7 a 1280, 767, 375 e allo zoom 200%; 1/7 a 320 px (il titolo di prova con markup ostile, il più lungo); nessun percorso tagliato |
| 3 | tabelle dei fattori 19 px oltre il pannello | pannello senza scorrimento laterale, tabelle affiancate, nessuna parola spezzata sui sette finding di prova |
| 4 | allo zoom 200% circa 111 px di tabella, meno di due righe | barra non fissa sotto 48rem di larghezza o 32rem di altezza: scorrendo, 6 righe intere allo zoom 200% e 7 a 320 px |
| 5 | barra 61 px, 13 px di scorrimento in più | barra 48 px, nessuno scorrimento in più a 1280×800 |
| 6 | due pulsanti principali | uno, «Prendi in carico» |
| 7 | «Vedi i 1 finding nuovi» | singolare, plurale e, con zero, una frase senza collegamento |
| 8 | l'errore restava dopo la correzione | sparisce quando il campo cambia (prova unitaria) |
| 9 | `j`, `k` e frecce inattivi sul riquadro | portano alle righe (prova unitaria e in Chrome per `j`) |
| 10 | tabella attaccata al collegamento | 13 px di spazio |

Corretto anche un difetto minore visto durante le misure: il contorno del fuoco sul titolo passava sul nome della regola. Il rilevatore della skill, rilanciato sui file modificati, segnala solo il falso positivo già detto. Prove web: 117 (erano 111).

### Cosa è risultato corretto

- Ordine del Tab dalla cima fino alla tabella (G4), fuoco sempre visibile con contorno di 2 px; «utente» non è un controllo.
- Dalle righe: `j`, `k`, frecce, `Home`, `Fine` e `/`; `Invio` apre il pannello e il fuoco va al titolo, `Esc` lo chiude e torna alla riga.
- Dialogo dell'eccezione: il fuoco entra nel campo e ci resta (14 Tab); errori accanto ai campi; con del testo, `Esc` chiede conferma con un avviso `role="alert"`.
- Le varianti A e B hanno lo stesso peso visivo.
- Sotto i 768 px «Torna alla lista» è il primo controllo del pannello (D7).
- Nessuno scorrimento orizzontale della pagina a 767, 375 e 320 px.
- I nomi delle azioni sono gli stessi ovunque (G14); nessuna password nella UI (T9).
- Ruolo «lettore»: nessuna azione di triage visibile.
- Stato di errore (API bloccata dal browser): messaggio, codice e «Riprova»; nessuna eccezione in console.
- Il titolo con markup ostile compare come testo.

### Non verificato

Lettore di schermo (sezione 4 della lista); il cambio di stato dopo un'azione confermata (nessuna azione è stata inviata); la copia del frammento negli appunti; lo stato di caricamento; il ricaricamento con la bozza (G11, coperto dai test); il contrasto non è stato rimisurato (controlli del 2026-11-18 con axe).

Il salvataggio del rapporto previsto dalla skill (`audit-storage`) non è stato eseguito: può inviarlo a un servizio esterno, e il progetto è privato.
