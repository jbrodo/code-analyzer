# ADR-0034: Golden set, protocollo di annotazione e Gate 3

- Stato: Accettato il 2026-11-27 dall'utente, prima della prima etichetta (G3-01)
- Data: 2026-11-27
- Decisione umana richiesta: sì (D3-02: definizioni e gate), presa il 2026-11-27
- Riferimenti: §10.3, §13, §14; ADR-0008, 0033; `doc/plan/fase-3.md`; `golden-set/README.md`

## Contesto

§13 chiede «precisione del triage ≥ 80% sul golden set» senza dire cosa sia vero, chi lo giudichi e su quali dati si misuri. Senza queste risposte il numero non significa nulla: se la grande maggioranza dei finding fosse di una classe, rispondere sempre con quella basterebbe.

## Deciso prima di questo testo

- Il golden set e il Gate 3 riguardano **solo Python** (D3-08). Per JavaScript e TypeScript i punti di codice sono troppo pochi (`doc/verifiche/fase-3.md`, V-F3.6). Un risultato del gate non dice nulla su altri linguaggi.
- **Annota l'utente, da solo** (D3-01). Un modello o un agente di coding non annota e le sue proposte non si mostrano a chi annota.
- Solo finding SAST; corpus di 30 repository pubblici; B101 escluso (D3-07).

## Decisione

### La domanda

«Il rischio che la regola descrive **c'è davvero in questo punto**, al commit mostrato?» La gravità non fa parte della domanda: la tratta il punteggio.

| Risposta | Quando |
| --- | --- |
| **vero** | La situazione esiste e in un uso realistico del programma può fare danno: va corretta o mitigata, anche se poco grave |
| **falso positivo** | Qui il rischio non c'è: il dato non è controllabile da chi non ha già quel potere, è già protetto, l'uso non riguarda la sicurezza, oppure il codice non è ciò che la regola crede |
| **non so** | Dopo circa cinque minuti, letto anche il codice collegato, non si riesce a decidere |

Casi da fissare, perché cambiano molte risposte:

1. **Chi attacca.** Un valore che decide solo chi già controlla la macchina o la configurazione (argomenti da riga di comando, variabili d'ambiente, file di configurazione) non rende «vero» il finding.
2. **Costrutto presente ma innocuo** (per esempio un hash debole per una chiave di cache, numeri casuali non usati per segreti): «falso positivo».
3. **Ipotesi sul futuro** («se un domani il valore arrivasse da fuori»): non contano. Si giudica il codice mostrato.
4. **Script, migrazioni, esempi** dentro il repository: si giudicano come il resto, con la regola 1.

Si può leggere tutto il repository al commit mostrato. Chi annota vede quindi più di quanto vedrà il motore (poche righe attorno al finding): una parte degli errori del motore può dipendere da questo, e la valutazione non li distingue.

### Campione

- **Unità:** un punto di codice, cioè repository, file e riga. Se più regole segnalano la stessa riga ne resta una, scelta dal seme.
- **Filtri**, in `golden-set/sampling.json`: file `.py`, fuori dai test e dal codice di terzi riconosciuto dal percorso. Regole escluse: B101; B105–B107, che sono segreti (D3-03); B401–B415, che segnalano il solo import di un modulo e non pongono una domanda sul punto di codice.
- **Tetto:** 20 punti per repository e regola. Il bacino è di **765 punti** da 15 repository (V-F3.7); con un tetto di 15 sarebbe di 673.
- **Estrazione:** uniforme nel bacino, senza stratificare, con seme registrato nel campione. La quota delle classi è quindi quella del bacino con il tetto, non quella dei finding in natura.
- **Insiemi disgiunti:** un punto estratto non entra in un altro insieme. Le 30 voci del pilota non entrano né nella calibrazione né nel test.

### Formato

In `golden-set/` stanno solo riferimenti a repository pubblici e risposte: `corpus.json`, `sampling.json`, `<insieme>.sample.json` (contratto `golden-sample`) e `<insieme>.labels.<annotatore>.g<giro>.json` (contratto `golden-labels`). Niente codice, messaggi dei tool, note, nomi di persone. Il campione non porta livello né punteggio. Messaggi, note, avanzamento e copie del codice restano in una cartella fuori dal repository.

Le etichette si consegnano una volta sola e portano il digest del campione. Il tempo per voce è quello in cui la pagina era visibile e in uso (si ferma dopo due minuti senza attività): è una stima, non include le ricerche fatte fuori dalla pagina.

### Un solo annotatore

L'accordo tra persone non si può misurare. Almeno una settimana dopo il pilota, **30 voci già annotate si riannotano** senza vedere le prime risposte, e si pubblica la quota di risposte uguali. Misura la stabilità del giudizio di una persona, **non la sua correttezza**: il Gate 3 misurerà quanto il motore è d'accordo con l'utente.

### Gate 3

Sull'insieme di test, chiuso prima di ogni addestramento e separato dall'addestramento **per repository**:

| Condizione | Misura |
| --- | --- |
| **G3.a** Precisione | Sulle decisioni che il motore non rimanda, precisione ≥ 0,80 sia per «vero» sia per «falso positivo» |
| **G3.b** Copertura | Il motore decide almeno il 50% dei finding del test |
| **G3.c** Meglio del banale | Accuratezza bilanciata più alta di quella della classe di maggioranza e della regola per `rule_id` |
| **G3.d** Solo in locale | Valutazione eseguita con la rete disattivata |

- Le voci «non so» restano contate e dichiarate, ma non entrano nel calcolo di G3.a–G3.c.
- Il test ha 200 voci con una risposta, di cui almeno 60 della classe meno frequente. Se non ci si arriva con il bacino, il gate **non è valutabile**: non si abbassa la soglia.
- Si pubblicano matrice di confusione, intervalli di confidenza e conteggi per classe e per repository.
- Soglie e condizioni non cambiano dopo aver visto i risultati. Un test usato non si riusa come test.

## Conseguenze

- Servono circa 630 etichette (30 di pilota, 100 di calibrazione, 200 di test, 300 per cominciare l'addestramento) su un bacino di 765: il margine per le voci «non so» è piccolo. Il pilota ne misura la quota; se è alta si rivedono tetto o corpus prima di proseguire.
- Cinque repository danno 536 dei 765 punti: la divisione per repository (G3-05) ha poca libertà, e il risultato pesa molto su pochi progetti.
- Le definizioni si possono correggere dopo il pilota, **prima** di estrarre gli altri insiemi, annotando qui il cambiamento; le risposte del pilota restano come sono.

## Modifiche dopo il pilota

### 2026-11-27 — Secondo pilota

Dopo il primo pilota (`doc/verifiche/fase-3.md`, V-F3.8) l'utente ha chiesto un **secondo pilota di 30 voci nuove** (insieme `pilota-2`). Il motivo: con tempi per voce molto sotto l'ipotesi del piano, dai soli numeri non si capisce se la quota delle classi descriva il corpus o il modo in cui si è risposto.

Fissato **prima di estrarlo**:
- Definizioni, filtri, tetto, gate e pagina di annotazione **non cambiano**.
- Le voci si estraggono con il seme `pilota-2` dallo stesso bacino, esclusi i punti del primo pilota. Nessuna delle 60 voci dei due pilota entra nella calibrazione o nel test.
- Le risposte del primo pilota restano come sono. **I due pilota non si sommano.** Quota delle classi e tempo per voce si riportano separatamente.
- La differenza tra i due non misura l'affidabilità di chi annota, perché le voci sono diverse.
- Lettura: se anche nel secondo pilota l'estremo alto dell'intervallo di Wilson al 95% per la classe meno frequente resta sotto il 30%, il Gate 3 così com'è scritto si considera non valutabile, e prima di annotare altro si decide come procedere (finding da valutare, obiettivo o ambito della Fase 3). Altrimenti il risultato non basta a dirlo, in un senso o nell'altro.
- La riannotazione di 30 voci prevista per un solo annotatore resta, su voci del secondo pilota.
