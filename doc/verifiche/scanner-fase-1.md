# Verifica degli scanner per la Fase 1

Esiti dei task V di `doc/plan/fase-1.md`. Stato: V-01..V-08 eseguiti il 2026-11-08 sulle versioni fissate, con una voce aperta in V-05; V-09 da eseguire.

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
