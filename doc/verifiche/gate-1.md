# Gate 1

Regola di misura e repository pilota (X-01). Decisione D-0009-B dell'utente, 2026-11-09. Si registrano solo durate e conteggi: i report dei pilota sono riservati e non si committano.

## Regola di misura

- Macchina di riferimento: il PC dell'utente, con le specifiche qui sotto.
- Scansione completa con `--offline` e snapshot dei feed fissato prima della misura. La sincronizzazione dei feed è esclusa dai 10 minuti e misurata a parte.
- Durata: `duration_seconds` del report, per ciascun pilota. Costruzione e firma delle immagini sono escluse.
- Configurazione: la policy di licenze di `.code-analyzer.yml` (X-03, D-0013), con quel file escluso dai finding.

## Macchina di riferimento

| Voce | Valore |
| --- | --- |
| CPU | Intel Core i9-10900K, 10 core, 20 thread |
| Memoria | 60 GiB |
| Disco | NVMe, ext4 |
| Sistema | Linux 7.0.0-43-generic |
| Docker | 27.3.1 |

## Snapshot dei feed

| Voce | Valore |
| --- | --- |
| Creato il | 2026-11-09T05:36:56Z |
| Database trivy aggiornato il | 2026-11-08T12:51:20Z |
| SHA-256 di `SNAPSHOT.json` | `5ef25e8599fcd5208b9461d5e07853227fbbdfb57b6f4fa5371f6e7fe1a222dd` |

## Repository pilota

Clone completo, nessuna modifica ai file versionati.

| Pilota | Commit | Data | File versionati | Dimensione | Linguaggi principali | Symlink versionati |
| --- | --- | --- | --- | --- | --- | --- |
| `fastapi/full-stack-fastapi-template` | `aabb90126964a164e02aff39e7c385bb0598236d` | 2026-11-03 | 252 | 9,8 MB | TypeScript, Python | 4 |
| `excalidraw/excalidraw` | `701b901a0f1ba3d0b390d9cdf63d112e25abac4b` | 2026-11-05 | 1.328 | 167 MB | TypeScript | 0 |
| `saleor/saleor` | `1d707dcf6127b098c187a181e5ee344017cdb064` | 2026-11-06 | 4.730 | 315 MB | Python | 2 |

## Misura (X-04)

2026-11-09. CLI impacchettata da `deploy/docker/package-cli.sh`, firma verificata, immagini sul registry locale, cloni su disco, `--offline`, snapshot sopra.

| Pilota | Stato | Durata | Finding | Critici | Alti | Medi | Bassi | `gate --fail-on critico,alto` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | `complete` | 19,7 s | 642 | 1 | 24 | 439 | 178 | 1 |
| `excalidraw/excalidraw` | `complete` | 146,2 s | 1.508 | 8 | 175 | 1.297 | 28 | 1 |
| `saleor/saleor` | `complete` | 247,7 s | 47.718 | 1 | 83 | 323 | 47.311 | 1 |

Il plugin più lento è scancode: 223,9 s su saleor. Su excalidraw bandit è saltato per linguaggio non rilevato.

Sincronizzazione dei feed, misurata a parte su un repository minimo con cache vuota: 23 s complessivi, 1,9 GB scaricati.

Configurazione per i pilota: oltre alla policy di licenze, `paths.exclude` su 6 symlink innocui, altrimenti il report è `partial` per la regola `workspace-symlinks`: 4 in `.agents/skills` e `.claude/skills` di full-stack-fastapi-template, rotti in un clone pulito perché puntano a `.venv`; `CLAUDE.md` e `saleor/graphql/CLAUDE.md` di saleor, che puntano ad `AGENTS.md`, analizzato al suo posto.

Rumore da rivedere in Fase 2: su saleor 47.276 finding su 47.718 sono `B101` di bandit.

Limiti confermati dalla misura, senza alcun `invalid_output` né tmpfs esaurito sui 3 pilota:

| Limite | Valore | Misura | Esito |
| --- | --- | --- | --- |
| `outputs.max_bytes` di bandit | 64 MiB | 19,2 MB su saleor, il margine più stretto (3,5 volte) | Confermato |
| `outputs.max_bytes` degli altri plugin | 4-16 MiB | Massimo 1,86 MB (syft su excalidraw), almeno 9 volte di margine | Confermato |
| tmpfs di `/out` e margine | `max_bytes` + almeno 16 MiB | Nessuna scrittura troncata | Confermato |
| `DEFAULT_MAX_BYTES` dei feed | 8 GiB | 1,9 GB scaricati, 4 volte di margine | Confermato |
| `FEEDS_MIN_FREE_BYTES` | 2 GiB | La soglia dipende dal ritmo di scrittura (T-03, ADR-0006), non dal picco, che non è stato misurato | Confermato |
| Costo dei container in più | | Scarto tra durata totale e plugin più lento: 6,4 s su fastapi, 8,4 s su excalidraw, 23,8 s su saleor | Sotto il 33% su fastapi, sotto il 10% sugli altri |

## Auto-analisi (X-05)

2026-11-09, clone pulito del commit `f01a7276a95fe6f5df56ea3c71f7085685a9b5a2`. Stato `complete`, 41,0 s, tutti i plugin `ok`, 2.241 finding. **Non superata:** `gate --fail-on critico,alto` esce con 1 per 25 finding (14 critici, 11 alti), tutti `ca.license`: 19 sono citazioni e 6 indicano licenze effettive di componenti nelle immagini (triage sotto). Fixture e casi vulnerabili sono esclusi da `.code-analyzer.yml`.

Riesecuzione del 2026-11-09 con le 19 eccezioni attive, su clone pulito: `complete`, 50,4 s, 19 finding `accettato`. **Ancora non superata:** `gate --fail-on critico,alto` esce con 1 per i 6 finding di licenza effettiva, in attesa di D-0015.

## Triage dei finding di licenza dell'auto-analisi

2026-11-09. Ogni occorrenza è stata letta. Fingerprint del commit `f01a7276a95fe6f5df56ea3c71f7085685a9b5a2`.

Il fingerprint dipende da percorso e licenze rilevate nel file: se queste cambiano, l'eccezione smette di valere e il finding torna, che è il comportamento voluto.

### Falsi positivi confermati (19): citazioni, nessuna dichiarazione di licenza nel file

Decisione dell'utente del 2026-11-09: riesaminate le 19 voci una per una e confermate come falsi positivi; eccezioni attive in `.code-analyzer.yml` con `approved_by: Riccardo Roveda` e scadenza 2027-05-09.

| Fingerprint | Livello | File | Licenze rilevate | Motivazione |
| --- | --- | --- | --- | --- |
| `sha256:98c725c476c7274fe354f272dcbfbc19fcd9998d86f871d864981ea4e500a980` | critico | `doc/PROJECT.md` | AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0 | Esempio della policy nella specifica (§8, riga 390) |
| `sha256:a1511fcb7c11535de172ad702038cff1b3e69fe425f4319b31677d0e1162d010` | critico | `doc/adr/0008-fingerprint-e-dedup.md` | AGPL-3.0-only | Vettore di prova del fingerprint (riga 208) |
| `sha256:1ca704571efca0d5d46ff30f63a98ec9a8c466481b522ee05af9022ae93e2a51` | critico | `doc/adr/0012-segreti-in-fase-1.md` | AGPL-3.0-only | Cita la licenza di trufflehog, non incluso in Fase 1 |
| `sha256:b216698e6fd6eaa482489127bebd7f520b5b22e1f670f6790d11a529cb7a34e3` | critico | `doc/adr/0013-policy-licenze.md` | AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0 | Testo della policy D-0013 |
| `sha256:c91ebc962d3cefef01df5e14e9d7701ddb47526a01cbb9857e979c1654a75ab5` | critico | `doc/adr/0015-regole-semgrep-e-licenze-motori.md` | AGPL-3.0-only | Tabella dei motori: la riga AGPL è trufflehog, non incluso in Fase 1 |
| `sha256:5ef93d70ce83cb60260eeb7a86c1c20cecc4e4aa427896c763ee6f2864a974e2` | critico | `doc/plan/fase-1.md` | AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0 | Testo di D-0013 e nota su trufflehog |
| `sha256:94a3ef4e814878c3f2048f5fb45dfb38f396af140ab1c175751ea1409ab2d901` | critico | `doc/utente/README.md` | AGPL-3.0-only | Esempio di configurazione (riga 78) |
| `sha256:08f526f996ec18048e139cc689c8734a4f3097c3f48417a046bcaa6cd4301d1b` | critico | `doc/verifiche/scanner-fase-1.md` | AGPL-3.0-only | Tabella delle licenze degli strumenti: la riga AGPL è trufflehog, non incluso in Fase 1 |
| `sha256:085ea34c3a6cc68acc999d15282fe0c48e46eef1c5cf71eccf0580ed35f50e77` | alto | `packages/ca-core/src/ca_core/policy/licenses.py` | GPL-3.0-only, GPL-3.0-or-later | Docstring del motore della policy (riga 5) |
| `sha256:7c235f43b02457fed9c774ef81d5a0d7c914f22b856b323f79799526b367df7c` | alto | `tests/contract/test_config_contract.py` | GPL-3.0-only | Dato di prova del contratto (riga 21) |
| `sha256:0e50968091f36c426f20470ff8d32d686fff9fc527deafc869509689b7a86e23` | critico | `tests/e2e/test_detection.py` | AGPL-3.0-only | Valore atteso in un'asserzione (riga 81) |
| `sha256:92ba68132cbaf93befa534627db59805be3a0e7616e7d9cdcf772d9a9eb90a8b` | alto | `tests/integration/test_scancode_image.py` | GPL-2.0-only | Stringhe scritte in file temporanei dal test (righe 78-102) |
| `sha256:f0ba277dcdead77b4c5962e1248048a09f96c53f21c0353cbe6b3c0a8a11074d` | critico | `tests/unit/core/test_fingerprint.py` | AGPL-3.0-only | Dati di prova del fingerprint |
| `sha256:e1b227eb03b9ac1700ab04a5020ad3e211422eb23b7761e77e0fdae7655c2574` | critico | `tests/unit/test_config_validate.py` | AGPL-3.0-only, AGPL-3.0-or-later | Configurazioni di prova |
| `sha256:be53f715d7de2a9951eda32b14c5676895b3b285a7e81133d2062087163f7581` | critico | `tests/unit/test_license_policy.py` | AGPL-3.0-only, SSPL-1.0 | Dati di prova del motore della policy |
| `sha256:90317ec063e7c58e6697b2b4d3e786c1097dc61f70825521639f67ea5e00e2fb` | critico | `tests/unit/test_models.py` | AGPL-3.0-only | Dati di prova del modello |
| `sha256:95036e554dc13e86d8732259efc638b97c4a7ab2b19ea1b364dc52d530d271bb` | alto | `tests/unit/test_pipeline_plugins.py` | GPL-3.0-only | Dati di prova della pipeline |
| `sha256:5d614f7644e99ba60b52da52b21339aab693a43c22ed5322d439804e8b44f598` | critico | `tests/unit/test_scancode_plugin.py` | AGPL-3.0-only | Dati di prova dell'adattatore |
| `sha256:733fef3ac4c9e19ffd235748b786c875ae4729813433255c41a04904169bbd47` | alto | `tests/unit/test_semgrep_plugin.py` | LGPL-2.1-only, LGPL-2.1-or-later | Asserzione sul testo degli avvisi (riga 406) |

### Non eccepibili come falsi positivi (6): componenti reali nelle immagini

Decisione dell'utente del 2026-11-09: restano aperti e riguardano D-0015, di cui Riccardo Roveda è il responsabile. La valutazione è ancora da completare; finché non sono valutati, X-05 non è superata e X-07 resta bloccato.

| Fingerprint | Livello | File | Licenze rilevate | Cosa indica |
| --- | --- | --- | --- | --- |
| `sha256:667700ee9555f29cd47c43f1fd6e971e5629ee74999a32ad3dd14afec3adcb26` | alto | `deploy/docker/LICENSES-SBOM.md` | LGPL-2.1-only | Inventario delle immagini: registra la licenza LGPL del motore semgrep |
| `sha256:664d75c1b5f53f8be721503bbbfb2a3221807e6f86bbe04c34f28616de27267f` | alto | `packages/ca-plugins/src/ca_plugins/builtin/gitleaks/licenses/THIRD-PARTY-NOTICES.md` | GPL-2.0-only | Pacchetto Debian `git` (GPL-2.0-only e altre) installato nell'immagine |
| `sha256:5eac6fac3bbc3371dbd16836ca34dd1620ebb72e2e7779dbfe1d1dedbf0dcdbd` | alto | `packages/ca-plugins/src/ca_plugins/builtin/scancode/licenses/THIRD-PARTY-NOTICES.md` | GPL-3.0-only | `libgomp1` (GPL-3.0 con GCC Runtime Library Exception) installata nell'immagine, e componenti binari GPL |
| `sha256:d82671dc1118d84f6508ea4521848c515fb8d2aa963740d7ab56efd7dce151e9` | alto | `packages/ca-plugins/src/ca_plugins/builtin/semgrep/Dockerfile` | LGPL-2.1-only | Commento alla riga 41 sul testo LGPL-2.1; il file non è LGPL, ma si riferisce al motore realmente installato |
| `sha256:60d5407fa3f6160171470b9d0a78209364afde530c01c10ed0b41fc58ae8af6b` | alto | `packages/ca-plugins/src/ca_plugins/builtin/semgrep/licenses/THIRD-PARTY-NOTICES.md` | LGPL-2.1-only, LGPL-2.1-or-later | Dichiara semgrep 1.184.0 sotto LGPL-2.1; i metadati della wheel dicono `LGPL-2.1-or-later` |
| `sha256:751669cbd33d79596c3763ea463028146c821c6d5b78a797efc3fe3a0bdbed80` | alto | `packages/ca-plugins/src/ca_plugins/builtin/semgrep/licenses/semgrep/LICENSE` | LGPL-2.1-only | Testo integrale LGPL-2.1 del motore semgrep, incluso nell'immagine |

## D-0015: materiale per la valutazione

Stato al 2026-11-09: **valutazione da completare.** Quanto segue è un'analisi preliminare e un inventario di fatti, non un parere legale né un'approvazione. I 6 finding restano aperti, X-05 non è superata e X-07 resta bloccato finché non c'è la valutazione umana della distribuzione.

Stato al 2026-11-10: **rinviata a I-06** per decisione dell'utente, con Riccardo Roveda come proprietario. X-05 è chiusa come scostamento e X-07 non è più bloccato da D-0015 (vedi "Decisioni del 2026-11-09 su licenze e chiusura"). I punti "Da chiarire" restano aperti e si valutano sugli SBOM della build di rilascio.

### Analisi preliminare

| Immagine | Analisi | Da chiarire |
| --- | --- | --- |
| semgrep | Classificazione prudenziale `LGPL-2.1-only`: il COPYRIGHT del tag v1.184.0 indica la versione 2.1, i metadati della wheel `LGPL-2.1-or-later`. L'adattatore avvia semgrep come processo separato. | Gli obblighi di redistribuzione del motore e delle sue dipendenze. `or later` non si approva senza chiarimento del titolare |
| gitleaks | `git` è installato da Debian e invocato separatamente: la sua presenza non implica da sola che il prodotto debba adottare la GPL. | La redistribuzione di `git` deve rispettare la GPLv2, compresi i requisiti sul sorgente, per il pacchetto concreto |
| scancode | L'eccezione GCC non è una deroga generale: riguarda specifici file runtime. L'SBOM segnala anche componenti con espressioni alternative o composte, tra cui `typecode-libmagic`, `extractcode-7z` e `intbitset`. | L'inventario dei binari e delle loro licenze, dai `.ABOUT` e dall'SBOM dell'immagine costruita; chiarire `unrar` nella dichiarazione di `extractcode-7z` |

### Inventario dell'immagine costruita

Dagli SBOM di `deploy/docker/package-cli.sh`, build del 2026-11-09. `git` e `libgomp1` non sono fissati nei Dockerfile: i valori valgono solo per questa build, e una valutazione deve riferirsi all'SBOM di un'immagine concreta.

| Immagine | Componente | Versione | Licenza dichiarata nell'SBOM |
| --- | --- | --- | --- |
| gitleaks | `git`, `git-man` | `1:2.47.3-0+deb13u1` | Apache-2.0, BSD-3-Clause, GPL-1.0-or-later, GPL-2.0-only, GPL-2.0-or-later, ISC |
| scancode | `libgomp1` | `14.2.0-19` | Non leggibile: l'SBOM riporta un hash al posto della licenza |
| scancode | `typecode-libmagic` | `5.39.210531` | Composta, comprende `bsd-new OR gpl-1.0-plus` |
| scancode | `extractcode-libarchive` | `3.5.1.210531` | apache-2.0 AND bsd-simplified |
| scancode | `extractcode-7z` | `16.5.210531` | apache-2.0 AND lgpl-2.1 and unrar and brian-gladman-3-clause |
| scancode | `intbitset` | `4.1.2` | LGPL-3.0-or-later |
| scancode | `gemfileparser2` | `0.9.4` | GPL-3.0-or-later OR MIT |
| semgrep | `semgrep` | `1.184.0` | LGPL-2.1-or-later (metadati della wheel) |

Oltre i 6 finding, gli SBOM riportano espressioni di licenza contenenti riferimenti GPL per 72 pacchetti Debian comuni alla base di tutte e 7 le immagini; gitleaks ne aggiunge 20 (92 in totale). Scancode riporta inoltre 2 pacchetti Python e semgrep 1. La policy di `.code-analyzer.yml` valuta il repository, non le immagini, quindi non li segnala. Questi conteggi descrivono dichiarazioni nei metadati SBOM, anche con espressioni alternative: non determinano da soli quali termini si applichino né se un insieme sia un'opera combinata o un'aggregazione. `unrar` compare nell'espressione di `extractcode-7z`, ma non negli avvisi di terze parti di scancode esaminati e resta da identificare e verificare.

Per la build del 2026-11-09 sono registrati i suffissi degli ID immagine sotto; i file SBOM originali erano in `/tmp` e non sono conservati qui. Per le prossime build di rilascio, usare una cartella di output persistente e conservare insieme immagini, digest e SBOM: `package-cli.sh` produce gli SBOM in `<cartella-di-uscita>/sbom/`. Le versioni APT non vengono fissate da questa decisione; l'evidenza va associata a ciascun rilascio concreto.

| Immagine | SBOM (suffisso del digest) |
| --- | --- |
| bandit | `fdbae26d8255` |
| gitleaks | `66d77d7804ca` |
| osv-scanner | `80074b915189` |
| scancode | `197b23dae5b5` |
| semgrep | `d9dbc7a73986` |
| syft | `717ca48a3130` |
| trivy | `2d5a97fcee8d` |

## Esito del Gate 1 (X-06)

2026-11-09. **Gate 1 superato**, con due scostamenti confermati dall'utente (§13: i valori sono da confermare dopo il pilota).

| Condizione | Valore misurato | Esito |
| --- | --- | --- |
| G1.a: 3 pilota scansionati | 3 report `complete`, schema valido, gate valutato | Superata, con lo scostamento 1 |
| G1.b: scansione completa < 10 minuti | Massimo 247,7 s (saleor) | Superata |
| G1.c: problemi noti delle fixture rilevati | E2E verdi; 2 attesi di licenza trovati per percorso e regola, senza la riga | Superata, con lo scostamento 2 |

Scostamenti:

1. I report sono `complete` grazie a `paths.exclude` su 6 symlink verificati come innocui; senza, 2 pilota su 3 darebbero `partial` per la regola `workspace-symlinks`.
2. Il finding di licenza su un file indica il percorso ma non la riga (ADR-0013), mentre l'atteso chiede la riga: i 2 test restano `xfail`.

L'auto-analisi (X-05) non è una condizione del Gate 1: non è superata, e blocca X-07.

## Decisioni del 2026-11-09 su licenze e chiusura

Licenza del prodotto: GPL-3.0-only, confermata dall'utente (`LICENSE`).

L'aggiunta di `LICENSE` ha fatto comparire 5 finding su file invariati: scancode attribuisce loro la licenza del progetto. Sono coperti da eccezioni con `approved_by: Riccardo Roveda` e scadenza 2027-05-09.

| Fingerprint | File | Motivazione |
| --- | --- | --- |
| `sha256:f64935e9020d0320f949cff2ae1807785e323a725d588d85c792efe677ca2aa8` | `LICENSE` | Testo della licenza del prodotto, scelta dall'utente il 2026-11-09 (GPL-3.0-only). |
| `sha256:37702b4c664627db904b72d0215e5210cf05afe720534dce16a437dc202c602e` | `packages/ca-core/src/ca_core/normalize.py` | Codice del progetto, senza citazioni di GPL: scancode gli attribuisce la licenza del progetto dopo l'aggiunta di LICENSE. |
| `sha256:34ad11f35998a0d4d0a21b9a85a5d355b5431239e3a9133bf4d929c59cb37fd7` | `packages/ca-plugins/src/ca_plugins/builtin/osv_scanner/licenses/THIRD-PARTY-NOTICES.md` | Finding comparso solo con l'aggiunta di LICENSE, file invariato: licenza del progetto attribuita da scancode. |
| `sha256:3a69785665770a9e542bae7dcda86fb16a571d23c6b90ac8eeeef0077457f78c` | `packages/ca-plugins/src/ca_plugins/builtin/syft/licenses/THIRD-PARTY-NOTICES.md` | Finding comparso solo con l'aggiunta di LICENSE, file invariato: licenza del progetto attribuita da scancode. |
| `sha256:dcbc2e54ada6869387b6bd6c1f18861a3f05341ccfd7886456769b47c4db7776` | `packages/ca-plugins/src/ca_plugins/builtin/bandit/licenses/THIRD-PARTY-NOTICES.md` | Finding comparso solo con l'aggiunta di LICENSE, file invariato: licenza del progetto attribuita da scancode. |

Per lo stesso motivo sono cambiati i fingerprint di due finding reali, che restano aperti: `semgrep` `sha256:34b2cabe48f609a22174cb3e2969a5aac68baedb2687c1ffd23cb3b2e2b604e9`, `gitleaks` `sha256:598f9caa0662863f332253f30976ef5f08f2fb2b29f020e37ad949ac4d05f1e2`.

semgrep 1.184.0 è classificato `LGPL-2.1-only`, lettura prudenziale: si ignora `or-later` dei metadati della wheel.

**X-05 chiusa come scostamento confermato dall'utente:** in Fase 1 non si distribuisce nulla. I 6 finding di licenza effettiva restano aperti e `gate --fail-on critico,alto` esce con 1. La valutazione completa di D-0015 (semgrep, `git`, `libgomp1`, `unrar`, base Debian) è condizione vincolante per I-06, insieme all'approvazione esplicita della pubblicazione.

## Scansione di prova su un repository Java

2026-11-10. Fuori dalla misura del Gate 1 (decisione dell'utente del 2026-11-08): Java/Kotlin resta in Fase 4, la prova serve solo a vedere cosa funziona già. CLI impacchettata da `deploy/docker/package-cli.sh`, firma verificata, feed sincronizzati in rete, nessun `.code-analyzer.yml`.

| Voce | Valore |
| --- | --- |
| Repository | `spring-projects/spring-petclinic` |
| Commit | `500158f732419217507c7656904b8e6aa1bcc0d6` (2026-09-29) |
| File versionati | 132, nessun symlink |
| Build | Maven (`pom.xml`) e Gradle |
| Stato del report | `partial` |
| Durata | 39,8 s |
| `gate --fail-on critico,alto` | 2 (`partial-scan`) |

| Plugin | Esito | Risultato |
| --- | --- | --- |
| trivy | `ok` | 39 finding, tutti IaC: 1 critico, 7 alti, 8 medi, 23 bassi (`.devcontainer/Dockerfile`, `k8s/`). Nessuna vulnerabilità di dipendenze |
| osv-scanner | `failed` (exit 3) | Legge `pom.xml` (28 pacchetti), poi `could not load db for Maven ecosystem`: lo snapshot contiene solo npm e PyPI |
| syft | `ok` | SBOM prodotto; contenuto Java non verificato |
| scancode | `ok`, 20,0 s | Policy di licenze non valutata (`license-policy-absent`) |
| gitleaks | `ok` | Nessun finding |
| bandit, semgrep | `plugin-skipped` | Linguaggio non rilevato: nessun SAST su Java |

Esiti:

1. **Difetto di Fase 1:** un `pom.xml` rende `partial` qualunque scansione, anche di un repository Python o JS/TS, perché osv-scanner fallisce su un ecosistema senza database invece di segnalarlo e proseguire. Non corretto.
2. Atteso, da Fase 4: database Maven nei feed, regole SAST per Java, rilevamento del linguaggio.
3. Non verificato: perché trivy non riporta vulnerabilità dal `pom.xml`; i componenti Java nell'SBOM di syft.

Nota operativa: con la cache dei feed su un tmpfs la sincronizzazione di trivy fallisce con `memoria esaurita`, perché le pagine scritte contano nel limite di memoria del container. Con la cache predefinita su disco funziona.

## Chiusura della Fase 1 (X-07)

2026-11-10. **Fase 1 chiusa.**

CI su `main`:

| Workflow | Task | Esecuzione | Esito |
| --- | --- | --- | --- |
| `verify` | O-01 | 42891196195 | Verde |
| `feeds-snapshot` | O-03 | 42891196470 | Verde; cache `feeds-snapshot-42891196470` salvata (262 MB) |
| `e2e` | O-02 | 42891196255 | Verde: 368 passati, 5 saltati, 3 `xfail`, 17 min 53 s |

Per arrivarci sono serviti due fix: il limite di CPU dei container sui runner a 2 CPU (`cd02b26`) e il percorso della cache dei feed, che conteneva `..` e non veniva salvato (`5a6ffeb`).

Voci di §13: tutte spuntate in `doc/PROJECT.md`. Immagine CLI (I-03) rinviata alla Fase 2.

Definition of Done (§17):

| Voce | Evidenza | Esito |
| --- | --- | --- |
| Test unitari e di contratto verdi; copertura ≥ 80% su `ca-core` | `uv run pytest -q`: 2287 passati, 306 saltati (richiedono Docker, eseguiti in `e2e`); copertura 98,51% | Soddisfatta |
| Schemi JSON aggiornati e validati | `python -m ca_core.schema_export --check` senza divergenze | Soddisfatta |
| Documentazione utente aggiornata | `doc/utente/README.md` | Soddisfatta |
| Telemetria per le operazioni lunghe | `duration_seconds` nel report, totale e per plugin (ADR-0010) | Soddisfatta |
| Nessun finding Critico/Alto nell'auto-analisi | 6 finding di licenza effettiva aperti | Scostamento confermato dall'utente (X-05) |

Decisioni:

| Decisione | Stato | Proprietario |
| --- | --- | --- |
| D-0013 | Chiusa il 2026-11-08 | Utente |
| D-0015 | Rinviata a I-06: valutazione sugli SBOM della build di rilascio | Riccardo Roveda |

ADR-0002, 0007, 0008, 0010, 0011, 0014 portati ad `Accettato`: le prove elencate in "Revisione A-01" sono nel codice. ADR-0005 e ADR-0015 restano aperti fino a I-06.

Passano alla Fase 2 o oltre:

- I-06, primo rilascio: bloccato da D-0015 e dall'approvazione esplicita della pubblicazione.
- I-03, immagine CLI.
- Difetto: osv-scanner fallisce su un ecosistema senza database (un `pom.xml` rende `partial` la scansione), vedi la scansione di prova Java.
- I due test `xfail` sulla riga dei finding di licenza (scostamento 2 del Gate 1).
- Il test `xfail` sull'avviso di gitleaks per il clone superficiale: l'avviso sta in `invocations` del SARIF e il nucleo non lo legge.
- Rumore: `B101` di bandit, 47.276 finding su saleor.
