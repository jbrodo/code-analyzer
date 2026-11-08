# Verifica degli scanner per la Fase 1

Esiti dei task V di `doc/plan/fase-1.md`. Stato: V-01..V-09 eseguiti il 2026-11-08 sulle versioni fissate; resta aperta la voce di V-05 sulla firma degli snapshot.

## V-01 — Versioni candidate

Rilevate il 2026-11-08 dalle release GitHub e da PyPI. Tutti i repository risultano non archiviati e con commit nelle ultime due settimane.

| Strumento | Versione | Pubblicata il | Ultimo push | Artefatto (linux amd64) | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| syft | v1.57.0 | 2026-11-05 | 2026-11-07 | `syft_1.57.0_linux_amd64.tar.gz` | `9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704` |
| osv-scanner | v2.7.0 | 2026-10-12 | 2026-11-07 | `osv-scanner_linux_amd64` | `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` |
| trivy | v0.76.2 | 2026-11-05 | 2026-11-06 | `trivy_0.76.2_Linux-64bit.tar.gz` | `bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf` |
| scancode-toolkit | v32.5.0 | 2026-01-15 | 2026-11-02 | `scancode_toolkit-32.5.0-cp312-none-any.whl` (PyPI) | `f6bc16880d495393c8475a77155ddc38a800c0b7f8f75e81a165a00fadb4ca06` |
| gitleaks | v8.30.1 | 2026-03-21 | 2026-10-28 | `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| semgrep | v1.184.0 | 2026-11-05 | 2026-11-06 | `semgrep-1.184.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-manylinux_2_34_x86_64.whl` (PyPI) | `d847abb8fb6fdde77d9e30a6bc869dbfcb68eff4142dcd77897c52635a7600d9` |
| bandit | 1.9.4 | 2026-02-25 | 2026-11-02 | `bandit-1.9.4-py3-none-any.whl` (PyPI) | `f89ffa663767f5a0585ea075f01020207e966a9c0f2b9ef56a57c7963a3f6f8e` |
| cosign | v3.1.4 | 2026-10-20 | 2026-11-05 | `cosign-linux-amd64` | `424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa` |

Note:

- I checksum sono quelli pubblicati da ciascun progetto, sui file di checksum delle release o su PyPI. I binari non sono stati scaricati né le firme verificate: lo faranno i task che costruiscono le immagini.
- Le immagini Docker ufficiali non sono state considerate: i digest si fissano quando si scelgono le basi delle immagini dei plugin.
- syft, trivy e semgrep sono usciti tre giorni prima della rilevazione. Se V-03..V-07 trovano regressioni, si scende alla release precedente.
- cosign è alla serie 3: i flag indicati in ADR-0005 vanno riscontrati in V-06.

## V-02 — Licenze

Lette dal file di licenza al tag fissato. Non è il parere legale (A-04).

| Elemento | Licenza letta | Rispetto a ADR-0015 |
| --- | --- | --- |
| syft, osv-scanner, trivy, bandit, cosign | Apache-2.0 | Confermato |
| gitleaks | MIT | Confermato |
| scancode-toolkit | `NOTICE`: Apache-2.0 per il codice, CC-BY-4.0 per i dati; include componenti di terzi con licenze anche copyleft, documentate da file `.ABOUT` | Confermato, con la precisazione sui componenti di terzi |
| semgrep (motore) | LGPL-2.1 | Confermato |
| regole `semgrep/semgrep-rules` | Semgrep Rules License v1.0 | Confermato che è una licenza propria; il testo completo è sul sito del produttore e non è stato valutato |
| trufflehog (ramo `main`) | AGPL-3.0 | Confermato |

## V-03 — Versioni CycloneDX emesse

| Strumento | `specVersion` predefinita | Altro |
| --- | --- | --- |
| syft 1.57.0 | 1.7 | Accetta anche `cyclonedx-json@1.6` |
| trivy 0.76.2 | 1.7 | |

Entrambi emettono già 1.7, quindi per K-03 basta un passaggio diretto. Versioni proposte in ingresso: 1.7, più 1.6 se serve.

## V-04 — Contenuto degli output

Campioni in `tests/fixtures/plugin-output/`, ricavati da un repository di prova con dipendenze vulnerabili, un segreto finto, codice insicuro e un file AGPL. Tutti i SARIF sono 2.1.0 con un solo `run`.

| Strumento | Severità | CVSS | Alias | Note |
| --- | --- | --- | --- | --- |
| trivy SARIF | `level`, tag `HIGH`, `security-severity` sulla regola | `cvssv3_baseScore` e `cvssv3_vector` sulla regola | Assenti | |
| osv-scanner SARIF | `security-severity` sulla regola | Nessun vettore | `deprecatedIds` sulla regola | Il JSON nativo ha `severity` con il vettore CVSS e `groups[].aliases`: serve se il vettore è richiesto |
| semgrep SARIF | `level` assente sul risultato, `defaultConfiguration.level` sulla regola | n/a | n/a | |
| bandit SARIF | `level`, `issue_severity`, `issue_confidence` | n/a | n/a | Il formato richiede l'extra `bandit[sarif]` |
| gitleaks SARIF | Né `level` né severità | n/a | n/a | Il valore del segreto risulta oscurato (`REDACTED`) con `--redact` |
| scancode JSON | n/a | n/a | n/a | Nessun SARIF. Campi utili: `detected_license_expression_spdx`, `license_detections` |

**Rilievo per ADR-0012 e K-10:** gitleaks oscura il segreto, ma bandit no. La regola B105 scrive il valore in chiaro in `message.text` e negli snippet (`region` e `contextRegion`). Finché resta così, il segreto esce dal container attraverso il SARIF di bandit. Il controllo strutturale previsto per gitleaks non basta: va esteso agli altri plugin, oppure vanno disattivate le regole B105, B106 e B107, già coperte da gitleaks, e rimossi gli snippet. Nel campione committato il valore è sostituito con `REDACTED-BY-FIXTURE`. Anche `partialFingerprints` di gitleaks contiene autore, email e messaggio del commit: dati personali da non propagare senza una scelta esplicita.

Tutti e tre leggono `bun.lock` sul pilota `fastapi/full-stack-fastapi-template`: syft 408 componenti npm, osv-scanner 627 pacchetti, trivy tipo `bun` con 22 vulnerabilità. I conteggi non coincidono e la differenza non è stata indagata.

## V-05 — Database offline

| | trivy | osv-scanner |
| --- | --- | --- |
| Scaricamento senza workspace | `trivy fs --download-db-only --cache-dir D`, poi `trivy config --cache-dir D <dir vuota>` per le regole di configurazione | `curl https://osv-vulnerabilities.storage.googleapis.com/<ecosistema>/all.zip` in `D/osv-scalibr/<ecosistema>/all.zip` |
| Scansione senza rete | `trivy fs --offline-scan --skip-db-update --skip-check-update --skip-version-check --disable-telemetry --cache-dir D` | `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=D osv-scanner scan source --offline-vulnerabilities --no-resolve` |
| Dimensione | 1,6 GB più 2,7 MB di regole | npm 210 MB, PyPI 36 MB |

Trivy funziona con `D` in sola lettura. **Aperto:** non è stato accertato se gli snapshot abbiano una firma verificabile.

Per ADR-0006:

- `--download-offline-databases` scarica solo gli ecosistemi trovati nei file analizzati: su un input con `requirements.txt` e un `package-lock.json` sintetico ha scaricato solo PyPI. Non rispetta l'invariante "senza workspace", quindi serve lo scaricamento diretto.
- Senza `--no-resolve`, osv-scanner tenta comunque la rete per risolvere le dipendenze di `requirements.txt`, con errori a video ma risultati prodotti.
- Se manca il database di un ecosistema, osv-scanner esce con 1, come quando trova vulnerabilità, e riporta risultati parziali (82 contro 87). L'adattatore deve quindi rilevare `could not load db` e marcare il plugin come fallito. Senza pacchetti da analizzare esce con 128.

## V-06 — Cosign senza log di trasparenza

Provato con cosign 3.1.4 su un registry locale, con chiave generata da `cosign generate-key-pair`.

- Firma: `cosign sign --yes --key k.key --tlog-upload=false --use-signing-config=false <immagine@digest>`.
- Verifica: `cosign verify --key k.pub --insecure-ignore-tlog=true <immagine@digest>`.
- Solo per il registry locale in HTTP si aggiunge `--allow-http-registry`.

| Caso | Exit |
| --- | --- |
| Firma valida | 0 |
| Chiave errata | 1 |
| Immagine non firmata | 10 |
| Registry non raggiungibile | 1 |

Conseguenze: la verifica richiede accesso al registry, quindi i test su immagini costruite in locale passano da un registry locale (I-02). Il digest va letto dal registry dopo il push: quello di `RepoDigests` di un'immagine ritaggata ha fatto fallire la firma. Tutti gli esiti diversi da 0 portano a exit 2 per ADR-0005, quindi non serve distinguerli. Non è stato provato se `--use-signing-config=false` sia indispensabile.

## V-07 — Restrizioni del container

Profilo ADR-0004: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256`, workspace in sola lettura, utente `65534:65534`, workspace di proprietà di un altro UID.

| Strumento | Solo profilo ADR-0004 | Con tmpfs `/tmp` e `HOME=/tmp` |
| --- | --- | --- |
| syft | OK | OK |
| bandit | OK | OK |
| trivy | **Fallisce** (non crea file temporanei) | OK, 56 risultati |
| semgrep | **Fallisce** (nessuna directory temporanea) | OK |
| scancode | **Fallisce** (nessuna directory temporanea) | OK |
| osv-scanner | OK con le opzioni di V-05 | OK con le opzioni di V-05 |
| gitleaks | **Falso negativo** | **Falso negativo** senza la correzione sotto |

Per ADR-0004 e ADR-0012:

- Il profilo deve includere `--tmpfs /tmp:rw,noexec,nosuid` e `HOME=/tmp`.
- **gitleaks su un repository di altro proprietario esce con 0 e zero risultati**, segnalando `dubious ownership` solo nel log. Serve `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/workspace`: con questa impostazione trova il segreto. L'adattatore deve impostarla e trattare quell'errore come fallimento del plugin, con un test dedicato.
- `/out` con permessi 755 di un altro UID non è scrivibile; con 777 sì, e l'host legge i file creati (`nobody`, 644).
- Un limite di 256 PID basta a scancode con `-n 2` e `-n 4`.

scancode 32.5.0 non si avvia con `pluggy` 1.7.0 (`did not find any 'pre_scan' hooks`), che è la versione risolta senza vincoli; funziona con 1.5.0 e 1.6.0. L'immagine deve fissare `pluggy` con un lock.

## V-08 — Durata di scancode

Su `saleor/saleor` al commit `1d707dcf6127b098c187a181e5ee344017cdb064` (4.726 file analizzati, circa 1,06 milioni di righe), con `--license --copyright -n 4 --timeout 120`, nel profilo V-07, limite 4 CPU e 8 GB, macchina a 20 core.

**249 secondi, il 41,5% del budget di 10 minuti, zero errori.** Sotto la soglia della metà, quindi nessuna contromisura per ora; X-04 misurerà l'insieme dei plugin.

## V-09 — Consolidamento

Esiti ricavati dal testo di V-01..V-08 e dai campioni in `tests/fixtures/plugin-output/`. Nessuna nuova esecuzione degli scanner. I presupposti impliciti sono indicati come tali.

### Esiti

| ADR | Affermazione | Esito | Fonte e nota |
| --- | --- | --- | --- |
| 0004 | Il profilo `hardened-container` elencato basta a eseguire gli scanner | `smentito` | V-07: trivy, semgrep e scancode non partono senza tmpfs e `HOME` |
| 0004 | Presupposto: un plugin non root scrive in `/out` senza permessi dedicati | `smentito` | V-07: 755 di altro UID non è scrivibile, 777 sì |
| 0004 | L'host legge i file che il plugin scrive in `/out` | `confermato` | V-07: file `nobody`, 644 |
| 0004 | Il limite di PID è sufficiente per scancode | `confermato` | V-07: 256 con `-n 2` e `-n 4` |
| 0004 | Il profilo vale anche con Podman e gVisor | `non verificabile` | Runtime assenti sulla macchina (R-02, R-05) |
| 0005 | Firma con chiave e verifica senza log di trasparenza funzionano | `confermato` | V-06, cosign 3.1.4 |
| 0005 | Firma assente o errata è rilevata prima dell'esecuzione | `confermato` | V-06: exit 10 e 1 |
| 0005 | Si può verificare senza rete (Contesto) | `smentito` | V-06: serve il registry; senza, exit 1 |
| 0005 | `--use-signing-config=false` è indispensabile | `non verificabile` | V-06 non l'ha provato (I-02) |
| 0006 | trivy sincronizza database e regole senza workspace | `confermato` | V-05 |
| 0006 | Lo scaricamento integrato di osv-scanner rispetta "senza workspace" | `smentito` | V-05: dipende dai file analizzati; serve il download diretto di `all.zip` |
| 0006 | Entrambi gli scanner lavorano senza rete | `confermato` | V-05: osv-scanner solo con `--no-resolve` |
| 0006 | trivy funziona con il database in sola lettura | `confermato` | V-05 |
| 0006 | osv-scanner funziona con il database in sola lettura | `non verificabile` | V-05 lo afferma solo per trivy (P-03) |
| 0006 | Gli snapshot hanno una firma propria | `non verificabile` | Voce aperta di V-05 |
| 0006 | Presupposto: il database mancante si distingue dall'exit | `smentito` | V-05: exit 1 come per le vulnerabilità; va rilevato `could not load db` |
| 0007 | scancode non produce SARIF | `confermato` | V-04 |
| 0007 | osv-scanner in SARIF perde il CVSS | `confermato` | V-04: punteggio presente, vettore assente |
| 0007 | osv-scanner in SARIF perde gli alias | `smentito` | V-04 e campione: `deprecatedIds` e testo di `message` |
| 0007 | gitleaks espone il valore se non si oscura | `non verificabile` | V-04 ha usato solo `--redact` (P-07) |
| 0007 | Gli scanner emettono una versione CycloneDX precedente alla 1.7 | `smentito` | V-03 e campioni: 1.7 |
| 0007 | I SARIF sono 2.1.0 | `confermato` | V-04 e campioni: un solo `run` |
| 0007 | Il formato nativo di trivy fornisce gli alias | `non verificabile` | Non campionato (P-04, T-08) |
| 0009 | scancode è il plugin più lento | `non verificabile` | Misurato solo scancode (X-04) |
| 0009 | scancode resta entro metà del budget sul pilota più grande | `confermato` | V-08: 249 s, 41,5% |
| 0009 | Le severità per `sast` e `iac` sono disponibili | `confermato` | V-04: per semgrep è sulla regola |
| 0009 | Il CVSS con versione è disponibile per le dipendenze | `confermato` | V-04: trivy v3 nel SARIF, osv-scanner solo nel JSON nativo |
| 0012 | Il valore del segreto non lascia il container | `smentito` | V-04: bandit B105 in `message` e snippet; campione semgrep con snippet |
| 0012 | Il controllo sul SARIF di gitleaks basta | `smentito` | V-04: va esteso a tutti i plugin; la CLI non conosce il valore |
| 0012 | Presupposto: gitleaks legge la storia anche se il proprietario è diverso | `smentito` | V-07: exit 0 e zero risultati |
| 0012 | Con `safe.directory` il segreto si trova | `confermato` | V-07 |
| 0012 | Presupposto: il SARIF oscurato porta solo posizione e hash | `smentito` | Campione: `snippet: "REDACTED"`; `partialFingerprints` con autore, email e messaggio |
| 0012 | La copertura ridotta su clone superficiale è segnalabile | `non verificabile` | Da provare in F-04 e P-07 |
| 0015 | syft, osv-scanner, trivy, bandit: Apache-2.0 | `confermato` | V-02 |
| 0015 | gitleaks: MIT | `confermato` | V-02 |
| 0015 | scancode: Apache-2.0, dati CC-BY-4.0 | `confermato` | V-02: include componenti di terzi anche copyleft |
| 0015 | Semgrep motore: LGPL-2.1 | `confermato` | V-02 |
| 0015 | Le regole del registry hanno una licenza propria | `confermato` | V-02 |
| 0015 | Quella licenza limita redistribuzione e SaaS | `non verificabile` | Testo non valutato (D-0015) |
| 0015 | trufflehog: AGPL-3.0 | `confermato` | V-02 |

Totale: 20 `confermato`, 11 `smentito`, 9 `non verificabile`.

### ADR riaperti ed emendati

Tutte le smentite sono già recepite negli ADR, quindi nessun task resta fermo per questo motivo.

| ADR | Esito | Task del piano interessati |
| --- | --- | --- |
| 0012 | **Riaperto** e aggiornato: l'invariante si estende a tutti i plugin. Resta `Proposto` | F-02, K-10, P-07, P-08, P-09, P-10, T-06 |
| 0004 | Emendato, resta `Accettato`: tmpfs, `HOME`, scrittura su `/out`. La scelta non è smentita | R-02, R-03, T-02, T-03, A-01 |
| 0006 | Emendato, resta `Accettato`: download diretto, elenco fisso, esiti di osv-scanner. La scelta non è smentita | R-06, P-03, P-05 |
| 0005 | Emendato, resta `Proposto`: comandi, accesso al registry, digest | R-04, I-02 |
| 0007 | Emendato, resta `Proposto`: 1.7, JSON nativo, exit degli adattatori | K-03, P-02, P-04, P-06, P-08, P-10 |
| 0009 | Nessuna modifica | X-04 misura l'insieme dei plugin |
| 0015 | Nessuna modifica | I rilievi di licenza vanno in D-0015 |

### Da portare alle decisioni dell'utente

Nessuna decisione è stata presa qui.

- **D-0005:** ogni scansione richiede l'accesso al registry per verificare la firma; l'uso air-gapped richiede un registry raggiungibile.
- **D-0012:** il livello resta da decidere. Con la decisione si conferma anche la disattivazione di B105, B106 e B107, con il costo indicato in ADR-0012.
- **D-0015:** scancode include componenti di terzi anche copyleft; il testo della licenza delle regole Semgrep non è stato valutato.

### Voci ancora aperte

- Firma degli snapshot (V-05).
- osv-scanner con `/feeds` in sola lettura (P-03): se fallisse, torna all'utente perché tocca il montaggio di ADR-0006.
- Differenza tra i conteggi di syft, osv-scanner e trivy su `bun.lock` (V-04): non indagata.
- V-04 indica B105, B106 e B107 come "già coperte da gitleaks", ma la copertura non è stata misurata. Il testo di V-04 non cita gli snippet di semgrep, che risultano dal campione.
