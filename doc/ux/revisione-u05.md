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

## Esito

| Vista | Cosa si è visto | Gravità (bloccante, seria, minore) | Criterio | Decisione |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |
