# ADR-0025: Baseline, modalità PR e finding nuovi

- Stato: Proposto. Scelta tecnica; la fonte della baseline segue D2-01 (decisa: il server non esegue scansioni). Prove con K-16, K-17, K-18 e L-01
- Data: 2026-11-13
- Decisione umana richiesta: no
- Riferimenti: §5 passi 2 e 9, §8, §9.1, §12.1; ADR-0008, 0009, 0010, 0011, 0014, 0016, 0018; misure in `doc/verifiche/scanner-fase-2.md` (V-06)

## Contesto

In Fase 1 `gate.mode: new-findings-only` è valutato come `all` (ADR-0009): senza un termine di confronto ogni finding è "nuovo". La Fase 2 deve distinguere nuovi, esistenti e risolti, e ADR-0014 chiede che in una PR la configurazione venga dal branch base, perché chi apre la PR può modificare `.code-analyzer.yml`.

§5 descrive una scansione di PR che analizza solo i file cambiati (passo 2) e assegna al Gate 2 la "scansione PR incrementale < 10 minuti". V-06 ha misurato che la scansione completa più lenta sui pilota dura 221 s e che il tempo è quasi tutto di un plugin (scancode).

Con ADR-0016 il server non esegue scansioni: la baseline non può venire da un'esecuzione sul server.

## Decisioni

### 1. La baseline è un report

La baseline è il report (`scan-report`) di una scansione completa del commit base. La CLI la riceve come file:

```
code-analyzer scan [PATH] --pr --base <commit> --baseline <file>
```

Alla CLI non importa da dove viene il file. Le fonti, in ordine di preferenza per le integrazioni (ADR-0027):

1. **Artefatto della CI:** il report prodotto dalla scansione del branch principale, conservato dalla CI e recuperato per commit. Non richiede il server.
2. **Scansione del base nello stesso job:** se l'artefatto non c'è. Costa una scansione completa in più, al massimo 221 s sui pilota (V-06).
3. **Server:** scaricare il report del commit base dall'API. Possibile con ADR-0016, non necessario in Fase 2: si aggiunge se una pipeline non può conservare artefatti.

Senza baseline la modalità PR non si blocca: avviso `baseline-missing`, e il gate valuta come `all`.

### 2. La baseline è un input fidato solo se arriva da fuori dal repository

Una baseline falsa nasconde finding facendoli passare per esistenti. Regole:

- Il percorso viene solo dal flag. Un file dentro la directory analizzata è rifiutato: la PR potrebbe contenerlo.
- Il file si valida contro lo schema del report, come ogni input.
- `repository.commit` della baseline deve essere uguale al commit passato con `--base`. Se differisce, la baseline è rifiutata con l'avviso `baseline-commit-mismatch`. La CLI non può verificare da sola che un commit diverso sia un antenato, e una baseline di un altro commit può nascondere finding: meglio valutare tutto.
- Deve essere una scansione completa, non di PR.
- Se la baseline è `partial`, i finding degli strumenti dei plugin falliti non hanno un termine di confronto: nella PR risultano tutti nuovi, con l'avviso `baseline-partial`.

Chi garantisce che l'artefatto venga dal branch principale è la CI: lo fissa ADR-0027 per ciascun provider (ambito delle cache, permessi dei job delle PR da fork).

### 3. Stati rispetto alla baseline

Confronto per fingerprint (ADR-0008), che non contiene il numero di riga: un finding spostato di riga nello stesso file è esistente.

| Stato | Condizione | `baselineState` nel SARIF |
| --- | --- | --- |
| `new` | Fingerprint presente nella scansione e assente dalla baseline | `new` |
| `existing` | Presente in entrambe | `unchanged`; `updated` se sono cambiati posizione o livello |
| `resolved` | Presente nella baseline, assente dalla scansione, e tutti gli strumenti che lo avevano prodotto sono riusciti in questa scansione | `absent` |

Un finding della baseline che manca perché il suo plugin è fallito non è risolto: resta fuori dai tre conteggi e il report lo dice.

**File spostati o rinominati.** Il percorso fa parte del fingerprint dei finding di codice e dei segreti, quindi un file rinominato produrrebbe una coppia risolto più nuovo, e con `new-findings-only` una PR di sola riorganizzazione bloccherebbe. Dopo il confronto per fingerprint c'è un secondo passaggio: tra i `new` e i `resolved` rimasti, di tipo codice o segreto, si accoppiano uno a uno quelli che hanno la stessa chiave senza percorso (regola, famiglia di strumenti, hash del contesto o del valore). La coppia diventa un solo finding `existing`, con il percorso precedente registrato. La chiave senza percorso è un campo nuovo di `Finding` (C-01), calcolato dalla normalizzazione con gli stessi ingredienti del fingerprint. Non serve leggere la storia git.

Limite: per le licenze rilevate nei file il secondo passaggio non si applica, perché la chiave senza percorso sarebbe la sola licenza. Un file con licenza vietata rinominato risulta nuovo.

Sul server l'identità resta il fingerprint (ADR-0018): dopo il merge il finding con il vecchio percorso si risolve e quello nuovo nasce senza lo stato di triage del primo. È un limite noto, da riprendere con l'identità dei finding in una fase successiva.

### 4. Nessuna restrizione ai file cambiati in Fase 2

In modalità PR tutti i plugin analizzano l'intero repository. Il passo 2 di §5 (`resolve_changed_files`) non entra in Fase 2.

Motivi:

- **Non serve al requisito.** La scansione completa più lenta dura 221 s contro un limite di 600 s. "Incrementale" si realizza nel risultato: la PR vede e blocca solo ciò che introduce.
- **Costa correttezza.** Un plugin ristretto non vede i finding dei file non cambiati, che andrebbero riportati dalla baseline; "risolto" dipenderebbe da quali file ha visto ciascun plugin; ogni plugin andrebbe classificato e provato.
- **Richiede la storia git.** Calcolare i file cambiati richiede di leggere gli oggetti git o di eseguire `git`, che oggi né il nucleo né l'immagine CLI fanno.

Per quando servirà, V-06 ha già classificato i plugin: si possono restringere bandit, semgrep e le licenze dei file di scancode; devono vedere tutto syft, osv-scanner, trivy e le licenze dei componenti; gitleaks va ristretto per intervallo di commit e non per file. Il primo candidato è scancode, che da solo determina la durata su due pilota su tre.

Criterio per riaprire la decisione: X-05 misura una scansione di PR sopra i 300 s su un pilota con i plugin della Fase 2 e `ca-graph`. Sotto quella soglia la restrizione non si implementa.

### 5. Configurazione dal branch base

In modalità PR con una baseline valida, la configurazione effettiva è quella con cui è stata prodotta la baseline, non quella del branch della PR.

- Il report registra la configurazione effettiva della scansione, per intero (C-04): gate, eccezioni, `paths.exclude`, plugin disattivati, policy di licenze. Oggi ne registra solo una parte.
- La CLI in modalità PR usa quella configurazione per tutto: quali plugin girano, quali percorsi si escludono, quali eccezioni valgono, quale policy di licenze si applica, quali livelli bloccano.
- Il `.code-analyzer.yml` della PR si legge solo per confrontarlo: se differisce, il report porta l'avviso `config-changed-in-pr` con le sezioni cambiate. Le modifiche valgono dalla prima scansione del branch principale dopo il merge.
- `--fail-on` resta la precedenza più alta, come in ADR-0009.

Conseguenza voluta: un'eccezione aggiunta nella stessa PR che introduce il finding non lo fa passare. L'eccezione va approvata e unita prima, con una PR sua, che non introduce finding e quindi passa. Chi introduce un problema non può anche accettarlo da solo nello stesso cambiamento.

Senza baseline non c'è una configurazione del base da usare: vale il file della PR, come in Fase 1, con l'avviso `pr-config-from-head` oltre a `baseline-missing`. La soglia fissata dalla CI con `--fail-on` resta l'unica difesa, come oggi.

### 6. Gate

| Modo effettivo | Blocca |
| --- | --- |
| `all` | Ogni finding aperto con livello bloccante |
| `new-findings-only`, con baseline valida | Solo i finding `new` aperti con livello bloccante |
| `new-findings-only`, senza baseline | Come `all`, con l'avviso `new-findings-only-as-all` |

- Una scansione completa non ha baseline in Fase 2: `new-findings-only` su una scansione completa resta valutato come `all`.
- Il report registra modo richiesto ed effettivo, come già fa.
- Un finding `existing` peggiorato di livello non blocca in `new-findings-only`: il confronto è per identità, non per livello. Compare come `updated` nel SARIF e nel riepilogo.
- La scansione parziale fa uscire `gate` con 2 anche in modalità PR (ADR-0009).

### 7. Nel report e nel SARIF

- Il report distingue il tipo di scansione (`full` o `pr`) e, per una PR, commit base e numero della PR se la CI lo passa: servono a `scans` (ADR-0018).
- Sezione `baseline`: commit, esito della validazione, conteggi di nuovi, esistenti e risolti, ed elenco dei risolti con fingerprint, regola, titolo e posizione.
- Ogni finding ha lo stato rispetto alla baseline, nullo quando non c'è baseline, e il percorso precedente se è stato accoppiato dal secondo passaggio.
- SARIF aggregato (ADR-0011): `baselineState` su ogni risultato; i risolti compaiono come risultati `absent`.

### 8. "Nuovo" fuori da una PR

Nei report delle scansioni complete lo stato rispetto alla baseline è nullo. Sul server "nuovo" ha un significato suo, che non dipende da questo ADR: un finding è nuovo se la sua prima rilevazione è la scansione corrente del repository (ADR-0018). È il valore del filtro `new` dell'API senza il parametro `scan` (ADR-0029); con `scan` su una PR, `new` è lo stato `new` di questa sezione.

### 9. Clone

Il confronto non legge la storia git: `fetch-depth: 1` basta. La profondità conta solo per gitleaks, che analizza i commit presenti nel clone e segnala già la copertura ridotta (ADR-0012). Per vedere un segreto aggiunto e rimosso dentro la stessa PR servono i commit della PR: lo indica la documentazione dell'Action (ADR-0027).

## Effetti sul piano

- **K-16** cambia oggetto: non calcola i file cambiati, ma legge e valida la baseline e ne ricava la configurazione effettiva.
- **C-01:** stato rispetto alla baseline, percorso precedente, chiave senza percorso. **C-04:** tipo di scansione, sezione `baseline`, configurazione effettiva per intero.
- **F-06:** resta com'è, più un file rinominato con un finding e una baseline con commit diverso.
- **A-16:** ADR-0010 con `--pr`, `--base`, `--baseline`; ADR-0011 con `baselineState`; ADR-0014 con la regola della configurazione dal base.
- **A-17:** §5 passo 2 rinviato, con il criterio di questa sezione.

## Conseguenze

- La modalità PR è una scansione completa più un confronto: nessun plugin cambia, nessuna dipendenza da `git`.
- Una PR costa quanto una scansione completa. Sui pilota resta sotto i 4 minuti; il margine si rimisura in X-05.
- Ogni pipeline deve conservare il report del branch principale, o pagare una seconda scansione per PR.
- Il report contiene la configurazione per intero. È già un artefatto riservato (ADR-0010) e la configurazione è un file del repository: nessun dato nuovo esce.
- L'approvazione di un'eccezione richiede una PR separata. È un passo in più, ed è il punto.

## Realizzazione dei contratti (C-01, C-04, 2026-11-17)

- `finding` 1.2: `baseline_state` (`new` o `existing`; `risolto` non è un valore, perché un finding risolto non è più nel report), `previous_path` (solo con `existing`, percorso relativo senza caratteri di controllo) e `pathless_key` (impronta degli ingredienti del fingerprint senza il percorso, per il secondo passaggio).
- `scan-report` 1.2: `scan`, `baseline` e `effective_config`. `baseline.status` vale `valid`, `missing` o `rejected`; per `rejected` il campo `reason` è un codice come `baseline-commit-mismatch` o `baseline-partial`. I conteggi `new` ed `existing` devono coincidere con lo stato dei finding, e con una baseline non valida nessun finding ha uno stato. `not_evaluated` conta i finding della baseline il cui plugin è fallito.
- **`effective_config` è facoltativo** e la CLI lo scrive da ora. Un report della Fase 1 non lo ha: usato come baseline non fornisce la configurazione del base, e K-16 deve trattarlo come tale (avviso e configurazione del file della PR, come per `pr-config-from-head`).
- Lo `updated` del SARIF (ADR-0011) non ha un campo nel finding: lo ricava K-17 confrontando posizione e livello con la baseline.

## Realizzazione di K-16 e K-17 (2026-11-17)

- `load_baseline` (K-16) riceve l'esito della porta `BaselineSource`. Il confronto «dentro la directory» è sul percorso (normalizzato): il chiamante deve passare percorsi già risolti, altrimenti un link simbolico lo aggirerebbe. Lo farà la CLI in L-01.
- `diff_baseline` (K-17). **Chi non è un plugin:** i finding della policy delle licenze (`ca-core`) dipendono dall'output di più plugin; si considerano valutabili solo se tutti i plugin sono riusciti.
- **Chiave senza percorso, regola di accoppiamento:** `pk1` non contiene l'indice di occorrenza (dipende dal file). Per questo il secondo passaggio accoppia solo gruppi di uno contro uno. Un finding `code` senza contesto di codice non ha la chiave.
- `updated` ha un campo (`baseline.updated`, i fingerprint) perché il SARIF si costruisce dal solo report. Il campo ha richiesto `scan-report` 1.3.
- **Non ancora fatto:** collegare tutto alla CLI (L-01) e il gate sui nuovi (K-18). Finché non ci sono, nessun report reale ha uno stato rispetto alla baseline.

## Realizzazione del gate e della CLI (K-18, L-01, 2026-11-17)

- `gate` legge il modo da `gate.effective_mode` e non da altro: il report è l'unico ingresso (ADR-0010). Il modello rifiuta `new-findings-only` effettivo senza una baseline valida.
- La CLI sostituisce la configurazione con quella della baseline **prima** di preparare il workspace, così esclusioni, plugin, eccezioni e policy sono quelli del base per tutta la scansione.
- Un file di baseline privato (0600) dentro il repository darebbe in più un avviso di workspace illeggibile: è comunque rifiutato prima.
- `--baseline-source` dichiara la fonte per il report; la CLI non può verificarla.
