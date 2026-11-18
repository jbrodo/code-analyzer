# La dashboard

Decisioni: ADR-0029 (perimetro), ADR-0019 (accesso e ruoli), `doc/ux/` (come è fatta). La dashboard serve a
un'unica cosa: **la lista dei finding di un repository, con il dettaglio e il triage accanto**. Non ha
viste di portfolio, aggregati, trend né grafici (Fase 4).

**Stato.** Non esiste un'installazione ufficiale (D2-16): si prova con il compose di sviluppo
(`deploy/compose/server-dev.yaml`, `doc/ux/revisione-u05.md`), che ha un IdP finto senza password. Con un
IdP vero servono la configurazione degli emittenti del server e un `config.json` dell'ambiente
(`CA_API_AUTH_FILE`, `CA_API_WEB_CONFIG`, `CA_API_CSP_CONNECT`).

## Accesso e ruoli

L'accesso passa dall'IdP della tua organizzazione. Il token resta solo in memoria: ricaricando la pagina o
alla sua scadenza si rifà il giro dall'IdP e si torna alla stessa vista, con gli stessi filtri.

| Ruolo | Che cosa può fare |
| --- | --- |
| lettore | Vedere repository, finding, scansioni |
| triage | Prendere in carico, assegnare, riaprire |
| approvatore | In più: segnare un falso positivo, accettare con eccezione, revocarla |
| amministratore | Registrare tier ed esposizione di un repository (dall'API) |

Le azioni oltre il tuo ruolo si vedono e sono disattivate, con il motivo. Un lettore non vede la sezione delle azioni.

## La lista

Una riga per finding: livello (sempre a parole), problema e regola, categoria, posizione, stato, `Nuovo`, età
della prima rilevazione e a chi è assegnato. Predefinito: aperti e in corso, dal più grave; a parità di
livello i nuovi prima.

- **Filtri:** livello, categoria, stato, strumento, solo nuovi e ricerca (titolo, regola, percorso). Stanno
  nell'indirizzo: un collegamento copiato riapre la stessa vista. I filtri attivi sono pulsanti che si
  tolgono uno a uno, e «Azzera filtri» li toglie tutti.
- **«Nuovo»** sulla scansione corrente vuol dire visto per la prima volta in quella scansione; in una PR vuol
  dire nuovo rispetto al branch base.
- **Tastiera:** frecce o `j`/`k` tra le righe, `Home` e `Fine`, `Invio` apre il dettaglio, `Esc` lo chiude, `/`
  porta alla ricerca. Le scorciatoie valgono solo con il fuoco nella tabella.
- Sopra la tabella, una fascia gialla dice quando la scansione corrente è **parziale** (un plugin è fallito):
  i finding di quegli strumenti non sono aggiornati e nessun finding è stato segnato come risolto.

## Il dettaglio

Si apre a destra e ha, nell'ordine: **Come risolvere** (i passi, come testo), **Dove**, **Perché questo livello**
e **Stato e storia**. In «Perché questo livello» compaiono il livello attivo con la sua origine e i **punteggi
in ombra di A e B**, con la stessa struttura: fattori G, P, E, C con la loro evidenza e la formula con i
numeri veri. Non decidono il livello finché il Gate 2 non passa a `levels.source: score`. Dove la Variante B
non è definita (qualità, architettura) coincide con A e il blocco lo dice. Gli intervalli dei livelli non si
vedono ancora: non sono nella risposta del server.

Tutto ciò che viene dal report (titoli, messaggi, passi, evidenze, percorsi) è testo: mai interpretato come
HTML o Markdown, e i riferimenti non sono collegamenti attivi.

## Triage ed eccezioni

| Azione | Effetto | Serve |
| --- | --- | --- |
| Prendi in carico | `In corso`, con te come assegnatario | triage |
| Assegna | Cambia o toglie l'assegnatario | triage |
| Segna come falso positivo | `Falso positivo`, con la motivazione | approvatore |
| Accetta con eccezione | `Accettato` fino a una data futura, con la motivazione | approvatore |
| Riapri | Torna `Aperto` | triage |
| Revoca l'eccezione | Torna al suo stato | approvatore |

`Risolto` non si assegna da qui: lo decide il server quando il finding sparisce da una scansione completa. Un
finding risolto non si modifica.

**Importante per le eccezioni.** Il gate della CI non legge le eccezioni del server (ADR-0018). Il dialogo
mostra il frammento da aggiungere a `.code-analyzer.yml`, già compilato, con un pulsante «Copia»: senza
quello, l'eccezione vale per la dashboard e non per la pipeline. Un'eccezione dichiarata nel repository
compare a parte, con l'approvatore dichiarato e la nota «non verificato», e non si revoca dalla dashboard.
La durata massima di un'eccezione la fissa il server (365 giorni, `CA_API_EXCEPTION_MAX_DAYS`).

Il testo scritto in un dialogo sopravvive a un ricaricamento della pagina (si conserva nella scheda del
browser) e si cancella quando il dialogo si conclude; il dialogo però non si riapre da solo.

## Le scansioni

Dalla barra, il collegamento allo stato dell'ultima scansione porta alla sua pagina, e di lì all'elenco di
tutte. La pagina di una scansione ha il riepilogo (tipo, commit, durata, gate, configurazione di scoring), i
plugin con esito, firma, isolamento e snapshot dei feed, gli avvisi e, per una PR, nuovi, esistenti e risolti
rispetto alla baseline con il collegamento ai finding nuovi.

## Limiti

- Nessuna impostazione di tier ed esposizione dalla dashboard: si registrano dall'API (amministratore).
- Nessuna selezione multipla di finding.
- Nessun rinnovo silenzioso del token: alla scadenza si rifà l'accesso.
- La resa visiva e l'uso con un lettore di schermo non sono ancora stati rivisti a mano (U-05).
