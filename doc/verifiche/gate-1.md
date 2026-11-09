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

Decisione dell'utente del 2026-11-09: restano aperti. Riguardano D-0015, con responsabile da designare e valutazione da concordare. Finché non sono valutati, X-05 non è superata e X-07 resta bloccato.

| Fingerprint | Livello | File | Licenze rilevate | Cosa indica |
| --- | --- | --- | --- | --- |
| `sha256:667700ee9555f29cd47c43f1fd6e971e5629ee74999a32ad3dd14afec3adcb26` | alto | `deploy/docker/LICENSES-SBOM.md` | LGPL-2.1-only | Inventario delle immagini: registra la licenza LGPL del motore semgrep |
| `sha256:664d75c1b5f53f8be721503bbbfb2a3221807e6f86bbe04c34f28616de27267f` | alto | `packages/ca-plugins/src/ca_plugins/builtin/gitleaks/licenses/THIRD-PARTY-NOTICES.md` | GPL-2.0-only | Pacchetto Debian `git` (GPL-2.0-only e altre) installato nell'immagine |
| `sha256:5eac6fac3bbc3371dbd16836ca34dd1620ebb72e2e7779dbfe1d1dedbf0dcdbd` | alto | `packages/ca-plugins/src/ca_plugins/builtin/scancode/licenses/THIRD-PARTY-NOTICES.md` | GPL-3.0-only | `libgomp1` (GPL-3.0 con GCC Runtime Library Exception) installata nell'immagine, e componenti binari GPL |
| `sha256:d82671dc1118d84f6508ea4521848c515fb8d2aa963740d7ab56efd7dce151e9` | alto | `packages/ca-plugins/src/ca_plugins/builtin/semgrep/Dockerfile` | LGPL-2.1-only | Commento alla riga 41 sul testo LGPL-2.1; il file non è LGPL, ma si riferisce al motore realmente installato |
| `sha256:60d5407fa3f6160171470b9d0a78209364afde530c01c10ed0b41fc58ae8af6b` | alto | `packages/ca-plugins/src/ca_plugins/builtin/semgrep/licenses/THIRD-PARTY-NOTICES.md` | LGPL-2.1-only, LGPL-2.1-or-later | Dichiara semgrep 1.184.0 sotto LGPL-2.1; i metadati della wheel dicono `LGPL-2.1-or-later` |
| `sha256:751669cbd33d79596c3763ea463028146c821c6d5b78a797efc3fe3a0bdbed80` | alto | `packages/ca-plugins/src/ca_plugins/builtin/semgrep/licenses/semgrep/LICENSE` | LGPL-2.1-only | Testo integrale LGPL-2.1 del motore semgrep, incluso nell'immagine |
