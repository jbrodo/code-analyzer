# ADR-0028: Catalogo servizi

- Stato: Accettato il 2026-11-16 dall'utente (D2-04): registrazione sul server e file di contesto
- Data: 2026-11-16
- Decisione umana richiesta: sì (D2-04), presa il 2026-11-16
- Riferimenti: §4.3, §6.1, §8, §18; ADR-0014, 0016, 0018, 0019, 0025; incoerenza 8 del piano

## Contesto

Due fattori del punteggio dipendono da ciò che il repository è, non da ciò che contiene: C dal tier del servizio e E dalla sua esposizione su internet (§6.1). §8 li mette nel blocco `service` di `.code-analyzer.yml`; §4.3 mette il tier anche nella tabella `repositories`. Sono due fonti, e la prima è un file del repository analizzato: chi modifica il branch può dichiarare tier 3 e servizio interno, e abbassare ogni punteggio (ADR-0014).

ADR-0016 ha lasciato qui una domanda. Il server non ricalcola i punteggi: sono quelli del report prodotto dalla CLI. Tier ed esposizione registrati sul server devono quindi arrivare alla CLI prima dello scoring, oppure il server deve applicarli da sé.

## Opzioni

### Fonte

1. Catalogo esterno, con un adattatore per ciascun prodotto di catalogo.
2. **Registrazione sul server**, per repository, da parte di un `amministratore`.
3. Solo `.code-analyzer.yml`.

### Come il valore arriva allo scoring

1. Il server ricalcola C ed E all'ingestione: due insiemi di punteggi per la stessa scansione, e la regola di ADR-0016 cade.
2. `scan` interroga il server: la scansione dipende dalla rete e dal server, contro ADR-0016.
3. **Un file di contesto passato a `scan`**, che arriva da fuori dal repository, come la baseline di ADR-0025.

## Raccomandazione

Opzione 2 per la fonte, come raccomanda D2-04, e opzione 3 per il trasporto.

### Il contesto del servizio è un file

```
code-analyzer scan [PATH] --service-context <file>
```

- Il file contiene `tier`, `internet_facing`, `catalog_id` e l'origine che lo ha prodotto. Ogni valore può mancare. Ha un proprio schema in `schemas/` (C-05).
- Alla CLI non importa chi lo ha scritto. Vale la regola della baseline: il percorso viene solo dal flag, e un file dentro la directory analizzata è rifiutato, perché la PR potrebbe contenerlo.
- `scan` resta senza rete e senza dipendenza dal server.

Chi produce il file:

- **Con il server:** un comando nuovo, `code-analyzer service-context --server-url URL --output FILE`, che la pipeline esegue prima di `scan` con il proprio token OIDC. Il server risponde con i valori registrati per il repository del token. Exit 0 o 2, mai 1. Se il repository non è ancora noto al server, o il server non risponde, l'Action prosegue senza file, con un avviso.
- **Senza server:** chi gestisce la pipeline lo scrive o lo genera da dove vuole, per esempio da un catalogo esterno. È il modo in cui l'opzione 1 resta possibile senza un adattatore nel prodotto, ed è il modo delle scansioni del Gate 2 se non passano dal server.

### Precedenza e valori predefiniti

| Ordine | Fonte | Marcata nel report come |
| --- | --- | --- |
| 1 | File di contesto | `catalog` |
| 2 | Blocco `service` di `.code-analyzer.yml`, solo se manca il file di contesto | `repository` |
| 3 | Predefinito | `default` |

- La precedenza vale per singolo valore: un file di contesto con il solo tier lascia l'esposizione alla fonte successiva.
- Con un file di contesto presente, un blocco `service` che dice altro si ignora, con l'avviso `service-config-ignored`.
- Il blocco `service` usato come fonte è una dichiarazione non verificata: il report lo dice con l'avviso `service-from-repository`. In modalità PR vale quello del branch base (ADR-0025), quindi una PR non può abbassarlo per sé.
- Tier: 1, 2 o 3. Corrispondenza con C nella configurazione di scoring (C-03): 1,0, 0,7 e 0,4 secondo §6.1. Tier assente: C = 0,7.
- Esposizione: `true`, `false` o assente. Come un'esposizione assente entra in E lo fissa ADR-0022 insieme alla raggiungibilità.

Punto per ADR-0022: la sezione 3 del piano propone E = 0,3 senza registrazione, lo stesso valore della raggiungibilità ignota. Con quel valore un repository non registrato ottiene punteggi più bassi di uno registrato come interno (0,6): non registrare conviene. Un valore non inferiore a quello di "interno" toglie l'incentivo.

### Registrazione sul server

- `PATCH /v1/repositories/{id}` con `tier`, `internet_facing` e `catalog_id`, riservato al ruolo `amministratore` (ADR-0019). `catalog_id` è un'etichetta libera verso un catalogo esterno: il server la conserva e non la interpreta.
- La riga di `repositories` registra chi ha fatto l'ultima modifica e quando (due colonne in più rispetto ad ADR-0018, in C-07). Lo storico completo delle modifiche non entra in Fase 2.
- `GET /v1/service-context`, riservato alle identità di pipeline: restituisce il file di contesto per il repository del token. È una riga in più nella matrice di ADR-0019 e un endpoint in più per C-08.
- **Una modifica vale dalla scansione successiva.** I punteggi già registrati non cambiano, perché il server non li ricalcola. La UI mostra, per ogni scansione, i valori usati, che vengono dal report.
- Nessuna pagina di impostazioni in Fase 2 (ADR-0029): la registrazione si fa dall'API.

### Nel report

- Sezione `service_context` della scansione: tier, esposizione, `catalog_id`, e per ciascuno la fonte (`catalog`, `repository`, `default`). Con il file di contesto, anche la sua origine dichiarata.
- L'evidenza dei fattori C ed E di ogni finding porta il valore usato e la fonte, così un finding letto da solo spiega il proprio punteggio (§6.2, "pesi e soglie mostrati accanto al punteggio").
- Sono campi di C-01 e C-04.

### Limiti

- Un repository è un servizio. Un monorepo con più servizi di tier diverso riceve un solo valore: la mappa per percorso si rimanda.
- Il file di contesto è fidato quanto la pipeline che lo fornisce. Su un flusso che la PR può modificare, la PR può anche cambiare il file passato: è lo stesso limite di `--fail-on`, descritto in ADR-0027.

## Conseguenze

- `scan` guadagna `--service-context` e la CLI il comando `service-context` (A-16 su ADR-0010); l'Action li incapsula (ADR-0027).
- `code-analyzer-config` restringe `service.tier` a 1, 2, 3. Oggi lo schema accetta ogni intero positivo, ma la sezione era inerte: nessun file valido in uso cambia significato.
- K-05 legge il tier dal contesto risolto; K-04 l'esposizione; B-10 offre `PATCH` e `GET /v1/service-context`.
- Tra la registrazione di un nuovo tier e i punteggi aggiornati passa una scansione. Per un repository analizzato a ogni push è irrilevante.
- Se D2-04 sceglie il catalogo esterno, cambia solo chi produce il file: serve un adattatore al posto di B-10. Se sceglie il solo `.code-analyzer.yml`, il file di contesto e l'endpoint escono, e S-01 registra il punteggio manipolabile come rischio residuo.
