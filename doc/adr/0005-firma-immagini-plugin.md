# ADR-0005: Firma e verifica delle immagini dei plugin

- Stato: Deciso il 2026-11-09 per il primo rilascio: GHCR `ghcr.io/jbrodo/code-analyzer/plugins/<plugin>` e firma Cosign con chiave custodita in un GitHub Actions Environment protetto. La pubblicazione richiede ancora approvazione esplicita.
- Data: 2026-11-08
- Decisione umana richiesta: sì per autorizzare ogni rilascio; registry e custodia della chiave per il primo rilascio sono decisi
- Riferimenti: §7.1, §7.2, §15

## Contesto

§7.2 richiede la verifica cosign prima dell'esecuzione, ma non dice chi firma, con quale identità, né come verificare senza rete. Il registry in §7.1 e §12.1 è un segnaposto (`registry.example.com`). Il repository è su GitHub, ma la specifica non fissa la CI del progetto.

## Opzioni

1. **Solo digest fissato:** garantisce l'integrità, non l'origine, e §7.2 chiede la firma.
2. **Cosign keyless (OIDC):** nessuna chiave da custodire, ma la verifica dipende dalla radice di fiducia e dal log pubblici; scomodo per self-hosted e air-gapped.
3. **Cosign con chiave, pubblica distribuita tramite la CLI, più digest fissato.**

## Raccomandazione

Opzione 3.

- Firmiamo noi tutte le immagini built-in, costruite in CI da scanner a versione fissata.
- Il registry del primo rilascio è GHCR, namespace `ghcr.io/jbrodo/code-analyzer/plugins/<plugin>`.
- La chiave privata sta nei segreti di un GitHub Actions Environment protetto, con approvazione del rilascio. Non è nel repository né nell'immagine.
- La chiave pubblica è un trust anchor fidato: la CLI installata la distribuisce con il pacchetto; nella modalità immagine CLI si monta in sola lettura da un percorso host fidato, esterno a workspace, work e cache. La CLI verifica con quella chiave; non la carica dal repository analizzato.
- I manifest built-in sono dati del pacchetto CLI e contengono il digest. Il rilascio costruisce e firma le immagini, poi inserisce i digest nei manifest e infine impacchetta la CLI. Lo schema richiede `@sha256:` sul manifest impacchettato.
- Si verifica il digest e si esegue quello stesso digest, mai un tag.
- La verifica deve funzionare senza accesso al log di trasparenza. Il comando esatto si fissa sulla versione di cosign adottata.
- Firma assente o non valida: nessun container parte e la scansione termina con exit 2. Non è un fallimento parziale di plugin, perché un `health` finding nasconderebbe una manomissione.
- Sviluppo: variabile `CA_INSECURE_ALLOW_UNSIGNED=1`, mai da `.code-analyzer.yml`. Il report segna `signature: skipped` e il gate esce con 2 senza `--allow-partial`.
- La CI del progetto firma con la stessa procedura, così i test E2E coprono il percorso reale.

## Conseguenze

- `cosign` a versione fissata è un prerequisito: incluso nell'immagine CLI, da installare per l'uso sull'host.
- La rotazione della chiave richiede l'aggiornamento coordinato dei segreti CI e della chiave pubblica fidata montata sugli host prima di distribuire immagini firmate con la nuova chiave.
- Ogni pubblicazione resta subordinata all'approvazione esplicita dell'utente e agli altri gate di rilascio, inclusa D-0015. La chiave pubblica montata deve essere gestita insieme alla chiave privata fidata: sostituirla cambia l'identità accettata dalla CLI.

## Emendamento dopo V-09

Data: 2026-11-08. Fissa i comandi provati in V-06 con cosign 3.1.4. L'opzione raccomandata non cambia; registry e custodia della chiave sono poi stati decisi in D-0005 il 2026-11-09.

- Firma: `cosign sign --yes --key k.key --tlog-upload=false --use-signing-config=false <immagine@digest>`.
- Verifica: `cosign verify --key k.pub --insecure-ignore-tlog=true <immagine@digest>`.
- `--allow-http-registry` serve solo al registry locale in HTTP dei test e non compare nei comandi di rilascio.
- Non è stato provato se `--use-signing-config=false` sia indispensabile: I-02 lo accerta prima di fissare il comando di rilascio.
- La verifica **richiede accesso al registry**: con registry non raggiungibile esce con 1. "Senza log di trasparenza" non significa "senza rete". Le firme non sono nell'immagine locale, quindi anche i test su immagini costruite in locale passano da un registry locale (I-02).
- Ogni esito diverso da 0 (1 per chiave errata o registry non raggiungibile, 10 per immagine non firmata) porta a exit 2: non serve distinguerli.
- Il digest si legge dal registry dopo il push. Quello di `RepoDigests` di un'immagine ritaggata ha fatto fallire la firma.
- `--offline` (ADR-0006, ADR-0010) impedisce la sincronizzazione dei feed, non l'accesso al registry. Un uso air-gapped richiede un registry raggiungibile dalla macchina di scansione: è un dato in più per D-0005.

## Emendamento dopo A-01

Data: 2026-11-08. Il tag `latest` è vietato in `image`, nel manifest sorgente e in quello impacchettato: il digest fissa i byte, ma un tag mobile rende il manifest non tracciabile rispetto a `version`. La decisione su registry e chiave è in D-0005.

## Emendamento: esito della verifica nel risultato e ordine di verifica

Data: 2026-11-08. Registry e chiave, decisi successivamente in D-0005, non cambiano l'ordine di verifica.

Confermato:

- `PluginRunResult.signature` sta nel risultato della porta: la verifica è dell'adattatore e il passo si limita a copiarla in `PluginRun.signature`, senza conoscere cosign (ADR-0002).
- Il verificatore resta un chiamabile interno a `ca-plugins`, `(manifest, riferimento) -> Signature`, e non una porta. Ha due soli esiti: `verified` o `skipped`, oppure `ScanAborted`. Non esiste un valore "firma fallita", perché quel caso non produce report.
- `CA_INSECURE_ALLOW_UNSIGNED=1` si legge solo dall'ambiente, nella radice di composizione. Salta il controllo dell'origine e basta.
- Il pull avviene anche con quella variabile. L'integrità resta garantita dal digest, si esegue lo stesso percorso del caso firmato e `create` continua a usare `--pull never`. Di conseguenza la variabile non rende superfluo il registry: se il pull fallisce, il plugin è `failed` e la scansione è parziale, come dopo una verifica riuscita.
- `verifier=None` su `OciExecutor` (nessun pull, `skipped`) è solo per i test con immagini locali: la radice di composizione passa sempre un verificatore.

Corretto:

- `signature` diventa obbligatorio, senza valore predefinito, anche nell'helper `_result` dell'adattatore. Il predefinito `skipped` era prudente per il gate, ma registrava come saltata una verifica mai tentata: oggi un errore di preparazione in `run`, che precede la verifica, scrive `skipped` anche in modalità firmata. Un'attestazione di sicurezza non ha un valore implicito.
- L'adattatore verifica prima di preparare l'esecuzione: dopo `isolation()` e prima delle directory e dei montaggi, sia in `run` sia in `sync_feeds`. Così ogni risultato riporta l'esito reale.
- Precisazione di "nessun container parte". Nessun container parte mai da un'immagine non verificata. In `run_many` si verificano tutte le immagini del lotto, poi si avvia il primo container: una verifica fallita nel lotto non ne avvia nessuno. Lo stadio precedente può aver già eseguito immagini verificate; l'esito resta exit 2 senza report, quindi non arriva alcun risultato parziale. La verifica di tutte le immagini prima del primo stadio richiederebbe un altro metodo nella porta e risparmierebbe solo tempo in un caso raro, senza aggiungere garanzie.
