# ADR-0026: Plugin di qualità, IaC e coverage

- Stato: Proposto. Scelta tecnica, con il parere di `security` in S-03. Passa ad `Accettato` con le prove di P-01..P-05 e K-21
- Data: 2026-11-16
- Decisione umana richiesta: no (D2-14 riguarda la distribuzione delle immagini, non queste scelte)
- Riferimenti: §6.3, §7.3, §8; ADR-0004, 0007, 0008, 0009, 0012, 0014, 0029; V-03, V-04 e V-08 in `doc/verifiche/scanner-fase-2.md`; incoerenze 15 e 25 del piano

## Contesto

§7.3 aggiunge ruff, eslint con typescript-eslint, checkov, hadolint e l'import di LCOV e Cobertura, senza dire con quale configurazione girano i linter, da dove entra un report di copertura, quali finding ne escono né cosa succede quando tre strumenti segnalano lo stesso problema.

V-04 ha mostrato che nessuno dei quattro motori è sicuro con le impostazioni predefinite: ruff scrive nel workspace, eslint esegue `eslint.config.js` del repository come codice, checkov chiama la rete e applica `.checkov.yaml` anche quando gli si indica un altro file, hadolint applica `.hadolint.yaml`. V-03 ha mostrato che ruff e checkov non danno una severità utile, che checkov mette frammenti dei file nel SARIF, che le metriche di complessità stanno solo nel testo dei messaggi, e che i percorsi nei report di copertura sono relativi alla cartella in cui girano i test.

## Opzioni per la configurazione dei linter

1. Usare la configurazione del repository: è ciò che il team si aspetta, ma per eslint è codice, e per tutti permette a chi modifica il branch di spegnere le regole senza che il report lo dica.
2. **Regole incluse nell'immagine, uguali per tutti i repository**; il repository può solo disattivare regole, in modo dichiarato.
3. Opzione 2 più una conversione dei file di configurazione del repository letti come dati: un interprete per ciascun formato, da mantenere a ogni versione dei motori.

## Raccomandazione

Opzione 2.

### Regole e configurazione

- Ogni immagine contiene il proprio insieme di regole in un file versionato con il plugin. Cambiarlo cambia la versione del plugin.
- **La configurazione del repository non si legge e non si esegue mai.** Non c'è un'opzione per attivarla.
- Il repository può disattivare regole con `plugins.<nome>.disable_rules`, un elenco di identificativi validati contro un modello fisso (C-05). Il filtro autorevole è nella normalizzazione, come per `paths.exclude` (ADR-0014). Il report elenca le regole disattivate accanto ai plugin disattivati. In modalità PR vale la configurazione del branch base (ADR-0025).
- Il repository non può attivare regole né cambiare soglie. Le soglie delle regole con una metrica (complessità, parametri, lunghezza, annidamento) vengono dalla configurazione di scoring (C-03) e arrivano al plugin in `/inputs/config.json`, che l'host genera (ADR-0014). Chi può sovrascriverle lo decide ADR-0021.
- I commenti di soppressione nel codice non nascondono finding: vale l'emendamento N-04 di ADR-0012.

Criterio per l'insieme iniziale: regole che indicano un errore probabile o un problema di manutenibilità misurabile. Fuori le regole di stile e di formattazione, e le regole di sicurezza di ruff, che ripetono quelle di bandit. Per eslint solo regole che non richiedono le informazioni di tipo: senza `node_modules` del progetto il controllo dei tipi non è affidabile. L'elenco esatto è nel file del plugin e si rivede con i dati di X-02.

### Invocazione per motore

Da V-04. Le voci marcate "da provare" non sono state verificate: P-01, P-02 e P-04 le provano prima di fissarle.

| Motore | Invocazione | Test obbligatorio |
| --- | --- | --- |
| ruff | Senza file di configurazione e senza cache (`--isolated`, `--no-cache`); regole e soglie passate dalla riga di comando; senza rispettare `.gitignore`, che altrimenti permette al repository di nascondere file (da provare); `--ignore-noqa` (da provare) | `ruff.toml` e `pyproject.toml` ostili; `.gitignore` che elenca un file con problemi; nessuna scrittura nel workspace |
| eslint | Cartella di lavoro nel workspace, `--no-config-lookup` con la configurazione dell'immagine, `--no-inline-config` (da provare). Parser e plugin risolti solo dall'immagine. Node 24, TypeScript 6.0.3. Uscita JSON nativa: il formattatore SARIF esterno non si usa (V-08) | `eslint.config.js` ostile; un pacchetto ostile in `node_modules` del workspace con il nome del parser |
| checkov | File passati uno per uno, `--skip-download`, `HOME` nel tmpfs, nessun modulo esterno scaricato. Solo i framework Dockerfile, Kubernetes e Terraform: gli altri, tra cui quello dei segreti, restano spenti. Uscita JSON nativa, l'unica che elenca i controlli saltati | `.checkov.yaml` ostile con `soft-fail` e controlli saltati; commento `checkov:skip` |
| hadolint | Cartella di lavoro fuori dal workspace; Dockerfile elencati dall'adattatore; `--disable-ignore-pragma` (da provare) | `.hadolint.yaml` ostile; commento `hadolint ignore` |

Altre regole per gli adattatori:

- I file da analizzare li elenca l'adattatore, non il motore.
- Un controllo che checkov riporta come saltato per un commento nel file torna a essere un finding.
- Limite noto di checkov con i file passati uno per uno: i riferimenti tra file Terraform possono non risolversi. P-03 lo misura su F-02; se serve, il ripiego è analizzare una copia nel tmpfs priva dei file di configurazione di checkov, che V-04 ha verificato come equivalente.
- Nessun testo dei file analizzati in `/out` (ADR-0007, ADR-0012). Oltre a `snippet` di checkov, i campioni di V-03 mostrano altri tre canali che gli adattatori chiudono: `fixes` nel SARIF di ruff; `source`, con il testo intero del file, e `suggestions` nel JSON di eslint. Il controllo del nucleo oggi rifiuta solo `snippet`: S-03 valuta se estenderlo.
- `uri` relativi al workspace, riscritti dall'adattatore: i quattro motori ne usano quattro forme diverse (V-03).
- Uscita 1 con finding non è un fallimento, per tutti e quattro.
- Testo di aiuto e indirizzo della regola passano nel SARIF dove il motore li fornisce (ADR-0029): ruff ed eslint sì. hadolint non emette le regole. Il testo di aiuto di checkov contiene il nome della risorsa analizzata, quindi è un dato del repository e non passa. Per questi due `remediation` resta vuoto finché il plugin non porta testi propri.

### Metriche per la Variante B

- Per le regole con una metrica l'adattatore estrae valore e soglia dal messaggio con un'espressione per regola e li mette nelle proprietà del risultato, come numeri. Un messaggio che non corrisponde all'espressione fa fallire il test di contratto del plugin, non la scansione: in scansione il finding resta, senza metrica, con un avviso.
- Il formato dei messaggi diventa parte di ciò che si riprova a ogni aggiornamento del motore.
- Nelle scansioni normali il motore gira con le soglie vere. La raccolta di tutti i valori, anche sotto soglia, serve solo a costruire la distribuzione di benchmark: è una modalità dell'adattatore che l'host attiva per la procedura di K-06 e che il repository non può chiedere. Forma dell'uscita e procedura sono di ADR-0023.

### Categoria, severità e livello provvisorio

| Plugin | `category` | `tool_severity` |
| --- | --- | --- |
| ruff | `quality` | Da una tabella per regola inclusa nel plugin: ruff dà `error` a tutto |
| eslint | `quality` | Dalla nostra configurazione: 2 diventa `medium`, 1 `low` |
| checkov | `iac` | Da una tabella per controllo inclusa nel plugin, dove c'è; altrimenti assente, mai `error` |
| hadolint | `iac` | Quella della regola: `error`, `warning`, `info`, `style` |
| coverage | `test` | `medium` |

Le tabelle sono dati del plugin, versionati e coperti dai test di contratto. Una regola senza voce vale `low` per ruff ed è senza severità per checkov.

Livelli provvisori fino al Gate 2 (D2-10), da aggiungere ad ADR-0009 in A-16:

- `iac`: resta la riga esistente. Un controllo di checkov senza severità è `medio`.
- `quality` e `test`: dalla severità, ma **mai sopra `medio`**. Prima che l'ordinamento sia validato nessun problema di qualità o di copertura blocca una CI che blocca su `critico` e `alto`.

Fingerprint: i finding di ruff, eslint, checkov e hadolint usano il `kind` `code` di ADR-0008, che oggi dice "sast, iac" e si estende a `quality` senza cambiare la formula.

### Report di copertura

Un report di copertura lo produce la CI prima della scansione e sta nel workspace come file non tracciato. Non serve un ingresso nuovo nel manifest: il plugin `coverage` legge file del workspace.

```yaml
plugins:
  coverage:
    reports:
      - path: backend/coverage.xml
        format: cobertura      # oppure lcov
        base_dir: backend      # cartella in cui sono girati i test
```

- `path` e `base_dir` sono relativi al workspace e controllati per contenimento come `plugins.semgrep.rules`: niente percorsi assoluti, niente `..`, solo file regolari, nessun collegamento simbolico che esce.
- Il plugin gira in un container come gli altri, con sola libreria standard. Un report è un input non fidato.
- I percorsi dentro il report si risolvono rispetto a `base_dir`. L'elemento `<source>` di Cobertura è un percorso di un'altra macchina e si ignora. Una voce che non corrisponde a un file del workspace si scarta e si conta.
- XML: il `DOCTYPE` con DTD esterna, che vitest emette, si ignora senza caricare nulla; un documento che dichiara entità viene respinto. Limiti su dimensione, profondità e numero di elementi.
- LCOV: i due dialetti di `FN` visti in V-03 sono entrambi letti. Valori non numerici in Cobertura (`NaN`) valgono "assente".
- Senza `plugins.coverage.reports` il plugin non gira e il report della scansione lo dice. Con un report configurato ma assente: avviso `coverage-report-missing`, plugin `ok`. Un report vuoto è valido. Un report che viola un limite o la forma fa fallire il plugin.

Finding prodotti, uno per file:

| `rule_id` | Quando | Evidenza |
| --- | --- | --- |
| `ca.coverage.low-file-coverage` | Copertura di riga del file sotto la soglia, per file con almeno un numero minimo di righe misurabili | Righe misurabili, righe coperte, rapporto, soglia |

Soglia e numero minimo stanno nella configurazione di scoring. Predefiniti: 0,5, il valore di §6.3, e 20 righe. Un file assente dal report non produce nulla: copertura ignota non è copertura zero. Nessun finding sul totale del repository.

Nuovo `kind` di fingerprint, senza toccare gli altri (A-16 su ADR-0008):

| `kind` | `rule_id` | `tool_family` | `normalized_location` | `component` |
| --- | --- | --- | --- | --- |
| `coverage` | id della regola | `coverage` | `path` | vuoto |

### Correlazione tra strumenti

checkov, hadolint e trivy segnalano in parte gli stessi problemi sugli stessi Dockerfile e manifest. ADR-0008 non fonde finding di strumenti diversi, e resta così: fonderli cambierebbe i fingerprint esistenti.

- `Finding` riceve un campo facoltativo, il **gruppo di correlazione** (C-01). Lo calcola il nucleo nella normalizzazione (K-21), non i plugin.
- Due finding sono nello stesso gruppo se hanno la stessa categoria, lo stesso file e la stessa **chiave canonica**. La chiave viene da una tabella di dati nel nucleo che associa `(strumento, regola)` a un problema, per esempio "container eseguito come root". Una regola senza voce non ha gruppo.
- La tabella parte dai casi di F-02 e cresce con i dati di X-02. È versionata; la sua versione è nel report.
- Il gruppo non cambia fingerprint, livello, punteggio né esito del gate. Serve a chi presenta i finding: il campione di G2.b prende un solo rappresentante per gruppo (X-03), il commento su una PR ne mostra uno e cita gli altri (ADR-0027), la UI può raggrupparli.
- Tra ruff e bandit non serve: le regole di sicurezza di ruff sono spente. Tra eslint e semgrep non c'è una tabella iniziale.

## Conseguenze

- Un team che usa già ruff o eslint vede regole diverse dalle proprie. È voluto: i finding di due repository sono confrontabili e la scansione non dipende da codice del repository. Va scritto nella documentazione utente (L-05).
- `plugins.<nome>.disable_rules` e `plugins.coverage` sono chiavi nuove di `code-analyzer-config` (C-05); il gruppo di correlazione e le proprietà della metrica sono campi nuovi di `finding` e `plugin-sarif-properties` (C-01). Aggiunte compatibili, con schemi e test di contratto aggiornati (`AGENTS.md` regola 1).
- Un report di copertura sta nel repository analizzato come la configurazione: una PR può portarne uno falso. È lo stesso limite di ADR-0014, e in modalità PR la configurazione che dice dove sta il report viene dal branch base.
- Senza controllo dei tipi eslint perde le regole più utili di typescript-eslint. Si rivaluta se un giorno il plugin potrà vedere le dipendenze installate.
- Ogni aggiornamento di un motore richiede di rieseguire i test con le configurazioni ostili e quelli sul formato dei messaggi. checkov pubblica quasi ogni giorno (V-01): la versione si aggiorna quando serve, non a ogni rilascio.
- I task P-01, P-03 e P-04 hanno ora il test con la configurazione ostile nell'accettazione, come P-02 (aggiornato con V-08).

## Realizzazione (P-01, P-02)

Scritta il 2026-11-17, a codice provato. Scostamenti e fatti nuovi rispetto al testo sopra.

- **Soglie nell'immagine.** La configurazione di scoring (C-03) non esiste ancora: le soglie sono nel plugin. ruff: complessità 10, ritorni 6, rami 12, argomenti 5, istruzioni 50 (i predefiniti del motore, scritti in chiaro). eslint: complessità 10, parametri 5, annidamento 4, righe per funzione 50. Quando C-03 esisterà le passerà l'host in `/inputs/config.json`, accanto a `disable_rules`.
- **Invocazioni provate su ruff 0.17.5 e eslint 10.14.0** (test con il motore reale e un repository ostile): ruff con `--isolated --no-cache --no-respect-gitignore --ignore-noqa`, cartella di lavoro fuori dal workspace; `pyproject.toml`, `ruff.toml` e `.ruff.toml` ostili senza effetto, `.gitignore` non nasconde file, `# noqa` e `# ruff: noqa` a livello di file ignorati. eslint con `--no-config-lookup -c <immagine> --no-inline-config`, cartella di lavoro nel workspace: `eslint.config.js` e `.mjs` ostili non eseguiti, un `typescript-eslint` ostile in `node_modules` del workspace non caricato, `eslint-disable` e `eslint-disable-next-line` ignorati, `.eslintrc` e `.eslintignore` senza effetto. Chiude S3-M2 per ruff ed eslint; resta hadolint (P-04).
- **Errori di sintassi** diventano finding `quality` con severità `high`: `invalid-syntax` per ruff, `parse-error` per eslint (dove `ruleId` è nullo).
- **Severità.** ruff: tabella per regola nell'adattatore (`invalid-syntax` e nomi non definiti `high`, bugbear e regole di metrica `medium`, il resto `low`). eslint: `medium` per le regole a livello errore della nostra configurazione, `low` per gli avvisi, `high` per gli errori di sintassi.
- **Nucleo.** `quality` ha il `kind` `code` di ADR-0008 (nessun cambio di formula). Il livello provvisorio è la severità, ma mai sopra `medio`: tetto in `LevelTable.capped`, dato e non logica. `plugin-sarif-properties` passa a 1.1 con `metric` (`value` e `threshold` interi), che la normalizzazione porta nell'evidenza del tool.
- **Immagine eslint.** Base Python come gli altri plugin, con il binario di Node copiato da `node:24-trixie-slim` per digest. Dipendenze da `package-lock.json` con integrità (98 pacchetti, tutti con licenza permissiva dichiarata), installate con `npm ci --ignore-scripts --omit=dev`. Esito di eslint: il JSON nativo, convertito dall'adattatore.
- **Immagini costruite e provate** nel profilo `hardened-container` sulle fixture di F-02: 145 MB (ruff) e 329 MB (eslint), stessi risultati dei test.
- **checkov (P-03).** Copia di lavoro nel tmpfs senza i nomi dei file di configurazione di checkov (la strada indicata da V-04 e S3-M3), solo Dockerfile, Terraform e YAML, senza collegamenti simbolici e con tetti. Senza `--quiet`, perché con quell'opzione il JSON non elenca i controlli saltati da un commento, che tornano finding. 339 MB, 96 pacchetti con hash.
- **coverage (P-05).** Nessun motore di terzi. Il `metric` di un finding di copertura ha `value` uguale alla copertura misurata e `threshold` a quella minima (il problema è un valore *sotto* la soglia, al contrario delle metriche di complessità). Soglia 50% e minimo 20 righe nell'immagine, in attesa di C-03. L'avviso `coverage-report-missing` previsto sopra non esce: il contratto dei plugin non ha un canale per gli avvisi.
- **Non fatto:** firma e SBOM con `build-image.sh` e `sign-local.sh` (richiedono syft e cosign, da scaricare come in X-07); misura di memoria, tempo e dimensione dell'uscita sui pilota (X-04, X-05): i valori nei manifest sono provvisori e lo dicono. `remediation` (ADR-0029) non passa ancora: il campo non esiste in `Finding` (C-01).
