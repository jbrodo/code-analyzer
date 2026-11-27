# Verifiche della Fase 3

Piano: `doc/plan/fase-3.md`. Misure e letture del 2026-11-27.

## V-F3.1 — Versione, checkpoint e licenze di Laya (task V3-01)

Fonti: indice PyPI, API di Hugging Face, contenuto dei due wheel scaricati in una cartella fuori dal repository. **Nessun codice di Laya è stato eseguito e nessun peso è stato scaricato.** Le licenze sono quelle **dichiarate** nei metadati: non è un parere legale, e i testi di licenza dei pesi e dei modelli di base non sono stati letti.

### Pacchetti

| Pacchetto | Versione | SHA-256 del wheel | Licenza dichiarata |
| --- | --- | --- | --- |
| `laya` | 0.5.5 (2026-11-26) | `0d5682b927b3803ef83e8850ebc6b88ac9bd7f00cf417c627d5f0b6560e1efde` | Permissiva; testo incluso nel wheel |
| `vegaml` (dipendenza obbligatoria di `laya`) | 0.20.1 | `fb194a5cb9e2d82ed0a4f7cc76f787759ca3bc64206a6578e712bd6d0eb33af8` | Permissiva; testo incluso nel wheel |

- Manutenzione: 82 versioni pubblicate di `laya` dal 2026-09-18, sei nell'ultima settimana circa. Il progetto ha poco più di due mesi.
- Dipendenze dichiarate di `laya`, senza extra: `torch`, `transformers`, `safetensors`, `huggingface_hub`, `numpy`, `vegaml`, `cryptography`.
- **Il codice non commerciale non è in `vegaml` 0.20.1.** `vegaml/learn/` è solo un rimando che importa `vegaml_learn`, un pacchetto separato non richiesto da nessuna dipendenza e solo per uso non commerciale. `vegaml-learn` resta escluso.
- In `laya`, per quanto risulta cercando gli `import`, `vegaml` è importato solo da `laya/vega.py` e `laya/learn.py`, e `vega.py` è caricato su richiesta. Installare senza `vegaml` per il percorso classico è da provare in V3-03.

### Pesi e modelli di base

| Repository su Hugging Face | Commit segnato come rivisto in `laya` 0.5.5 | `model.safetensors`: byte e SHA-256 a quel commit | Licenza dichiarata |
| --- | --- | --- | --- |
| `convaiinnovations/laya` (inglese) | `55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851` | 842609210, `891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c` | Permissiva |
| `convaiinnovations/laya-typed-decisions` | `1a793eb568e6718f15941d08f85432581df534e3` | 842609220, `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e` | Permissiva |
| `convaiinnovations/laya-multilingual` | `e4e9ddf21a7b1903b7acffd8814ad4307bf63a67` | 643835514, `9d628fd971b700382ac6f65920a86f149777b2e748e0c955fb3b19695aa8f204` | Permissiva |
| `answerdotai/ModernBERT-large` (base) | non usato da `laya` | — | Permissiva |
| `jhu-clsp/mmBERT-base` (base) | non usato da `laya` | — | Permissiva |

I commit rivisti non sono gli ultimi pubblicati, ma gli hash dei pesi di inglese e `typed-decisions` coincidono con quelli attuali. Nessun repository è ad accesso controllato.

### Dal codice del pacchetto (lettura mirata, non una revisione)

- I pesi sono in formato `safetensors`. Nessun uso di `trust_remote_code` e nessuna chiamata a `torch.load` o `pickle.load` trovata per nome.
- Il caricatore accetta una cartella locale e verifica gli SHA-256 passati dal chiamante, o in `LAYA_SHA256_DIGESTS`, prima di leggere i file. **Senza quella mappa non verifica nulla**, e **senza `LAYA_REVISION` non fissa il commit**: vanno impostati entrambi.
- Il modello si costruisce dalla configurazione `encoder/` inclusa nel checkpoint: dal codice non risulta un secondo download del modello di base. Da provare senza rete.
- Le chiamate di rete trovate per nome sono i download da Hugging Face e il client e server opzionali (`mcp`, `serve`). Cercando per nome non è emersa telemetria. **Una ricerca testuale non prova l'assenza di connessioni**: lo prova V3-03.
- Dati per l'addestramento (`laya/train.py`): righe con `state` (il testo), `questions` (per identificativo: tipo, istruzioni, criteri) e `gold` oppure `expected`. Le righe non convertibili vengono scartate e contate per motivo.
- Nel README del pacchetto una ricerca per parole chiave non trova misure su codice sorgente o finding di analisi statica.

### Il modello `laya` di Ollama

Il manifest locale indica come origine `laya:421m-english-bf16`: un file GGUF di 844026784 byte (`sha256:f78e1d7cba4fda48446fe66552c421d36119f927ff5e8b177a3bd3fbeb236427`), da cui il checkpoint **inglese**, non `typed-decisions`, con contesto 512. `ollama show --license` non restituisce nulla. Il formato è diverso da quello di Hugging Face, quindi gli hash non si confrontano: **la corrispondenza con i pesi pubblicati non è verificata**. Il piano non lo usa.

## V-F3.2 — Finding disponibili per il golden set (task V3-02)

Ramo `docs/piano-fase-3`, partito da `main` (`7ecfadd`). CLI impacchettata con `deploy/docker/package-cli.sh` (registry locale, chiave di prova), `scan --offline` con i feed in cache (avviso `feeds-stale`: non incide su SAST e IaC). I 10 repository di `scripts/benchmark/corpus.json` ai commit fissati. Tutti i plugin eseguiti hanno esito `ok` o `skipped`; quattro report sono `partial`, con l'avviso `workspace-symlinks`. «Fuori dai test» usa le regole di percorso di ADR-0022.

| Categoria | Tutti | Fuori dai test |
| --- | --- | --- |
| SAST | 1572 | 737 |
| IaC | 39 | 39 |

1611 finding, 1610 fingerprint distinti.

SAST fuori dai test:

| Repository | Finding | Senza B101 |
| --- | --- | --- |
| django | 346 | 303 |
| scrapy | 263 | 54 |
| saleor | 68 | 48 |
| httpx | 29 | 2 |
| flask | 12 | 6 |
| core | 7 | 7 |
| full-stack-fastapi-template | 5 | nessuno |
| express | 4 | 4 |
| excalidraw | 2 | 2 |
| vite | 1 | 1 |
| **Totale** | **737** | **427** |

- **Una regola pesa per il 42%:** B101 di bandit (`assert` fuori dai test) dà 310 finding. È più un'osservazione di qualità che una domanda di triage interessante.
- **Due repository pesano per l'83%:** django e scrapy, 609 finding su 737.
- Strumenti: bandit 634, semgrep 103. Regole distinte: 37. **I repository JavaScript e TypeScript** (core, excalidraw, express, vite) **ne danno 14.**
- Con un tetto per coppia repository e regola restano: 296 finding con tetto 10, 400 con 20, 470 con 30. Senza B101, 245 con 10 e 309 con 20.
- IaC: 39 finding, 11 regole, 3 repository.

**Esito: il corpus non basta.** Il piano chiede circa 630 etichette, con il test separato per repository: anche prendendo tutto, senza B101 si arriva a 427, e un test di 200 sarebbe dominato da django. IaC non ha volume per una valutazione propria. La quota di falsi positivi resta ignota: nessun finding è stato annotato o giudicato.

## V-F3.3 — Laya senza rete (task V3-03)

Download approvati dall'utente il 2026-11-27, dopo l'elenco di dimensioni. Contenitore di sperimentazione costruito fuori dal repository: **nessuna dipendenza nuova nel progetto**. La rete è servita solo a scaricare pacchetti e pesi; il codice è stato eseguito solo con la rete disattivata. Lo script di prova non è nel repository.

- Base: l'immagine Python 3.12 già fissata per digest in `deploy/docker/plugin-base/Dockerfile`.
- `torch` 2.15.0 per sola CPU (209,5 MB), `transformers` 5.24.1, `huggingface_hub` 2.5.0, `safetensors` 0.8.0, `numpy` 2.5.5, `cryptography` 50.0.2, più le loro dipendenze; circa 270 MB scaricati in tutto. Solo wheel. Immagine: 1,31 GB.
- `laya` 0.5.5 dal wheel con l'hash di V-F3.1, installato **senza dipendenze dichiarate**: `vegaml` non è presente.
- Pesi `convaiinnovations/laya-typed-decisions` al commit `1a793eb5…`: 846195716 byte con tokenizer e configurazioni. `model.safetensors` ha l'hash di V-F3.1.

| File | SHA-256 calcolato sul file scaricato |
| --- | --- |
| `model.safetensors` | `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e` |
| `rl_agent_config.json`, `encoder/config.json`, `tokenizer/tokenizer.json`, `tokenizer/tokenizer_config.json` | Passati tutti a `expected_sha256`; gli hash dei quattro file piccoli non hanno un riferimento pubblicato con cui confrontarli |

Esecuzione: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, utente non privilegiato, pesi e dati montati in sola lettura.

| Controllo | Esito |
| --- | --- |
| Interfacce di rete nel contenitore | Solo `lo` |
| Connessione di controllo verso l'esterno | Fallita (`Network is unreachable`) |
| Caricamento da cartella locale e una decisione per tipo (sì/no, scelta, punteggio) | Riusciti, **senza `vegaml`** |
| Hash sbagliato per i pesi | Rifiutato |
| Eventi di rete o di processo visti da `sys.addaudithook` (connessioni, risoluzione di nomi, processi), **anche senza** `HF_HUB_OFFLINE` | Nessuno |
| Moduli di `trust_remote_code` o `vegaml` caricati | Nessuno |

Limiti: l'audit hook vede il codice Python, non le connessioni aperte da librerie native. La garanzia è la rete disattivata, non l'assenza di eventi. È stato percorso solo il caricamento da cartella locale con `predict`; addestramento e calibrazione no.

Il caricamento ha dato un avviso: il checkpoint contiene una temperatura non valida per le scelte con 11 o più opzioni, sostituita con 0,5. Il triage usa risposte sì/no; la calibrazione resta comunque da rifare sui nostri dati (§10.3).

Nomi dei campi delle risposte, da usare in ADR-0036 al posto di quelli di §10.1: `noul` (probabilità del sì), `choice`, `score`, `probabilities`, `confidence`, `answer_confidence`, `action`; in `usage`: `input_tokens`, `state_tokens`, `state_tokens_dropped`, `truncated`, `truncated_questions`.

## V-F3.4 — Tempo e memoria su CPU (task V3-04, solo la parte CPU)

100 finding SAST del corpus di V-F3.2, fuori dai test e senza B101 (estratti con seme 20261127 dai 427). Evidenza: regola, messaggio e ±20 righe. Una domanda sì/no per finding, uno alla volta. Macchina di riferimento con 20 thread. **Le risposte non sono state valutate né conservate**: non ci sono etichette, e chi annoterà non deve vedere risposte di un modello.

| CPU e thread (`--cpus` e `OMP_NUM_THREADS` uguali) | Mediana per finding | 95° percentile | 100 finding | Memoria di picco | Caricamento |
| --- | --- | --- | --- | --- | --- |
| 4 | 0,87 s | 1,12 s | 83,5 s | circa 2,8 GB | 3,4 s |
| 8 | 0,52 s | 0,68 s | 51,3 s | circa 2,8 GB | 3,4 s |

- **Il numero di thread va fissato.** Con `--cpus 4` senza `OMP_NUM_THREADS` la mediana è stata di 4,05 s, circa 4,7 volte più lenta.
- **L'evidenza ci sta.** Il testo da valutare occupa da 166 a 565 token (mediana circa 390), l'intero ingresso al più 601: nessun troncamento con il limite del checkpoint. Con 512 token (checkpoint inglese) i casi più lunghi non ci starebbero.
- **Non misurati:** GPU (serve `torch` per CUDA, alcuni GB, e memoria libera sulla scheda), runner di CI, più decisioni per passaggio.

## V-F3.5 — Corpus proposto per il golden set (D3-07)

L'utente ha scelto il 2026-11-27 di arrivare a circa 30 repository pubblici: i 10 di `scripts/benchmark/corpus.json` più i 20 seguenti. **L'elenco attende la sua approvazione: nessuno di questi 20 è stato scaricato o scansionato.**

Criteri: soprattutto applicazioni; 8 con prevalenza di Python e 12 di JavaScript o TypeScript; non archiviati; ultimo rilascio indicato da GitHub (può non essere il ramo più recente); nessuna applicazione volutamente vulnerabile, che falserebbe la quota di veri positivi. `searxng/searxng` è stato scartato perché non ha rilasci né tag. Dati letti dall'API di GitHub il 2026-11-27; la licenza è la classe dichiarata da GitHub, non verificata sul testo. Il golden set conterrà solo riferimenti, non codice (G3-02). La dimensione è quella dichiarata da GitHub con la storia (circa 6,8 GB in tutto): le copie senza storia sono più piccole.

| Repository | Tag | Commit | Linguaggi principali | Licenza | Dimensione |
| --- | --- | --- | --- | --- | --- |
| `netbox-community/netbox` | `v4.7.6` | `4cfaa8f7b45fc2e8bf95309909880c70e80bef64` | Python 96%, HTML 2% | permissiva | 233 MB |
| `paperless-ngx/paperless-ngx` | `v3.5.1` | `35b0439195bbdb87a6d519152e6782abe0720c3b` | Python 63%, TypeScript 28% | copyleft forte | 233 MB |
| `healthchecks/healthchecks` | `v5.0.3` | `51a503531d845fc11d5ef270d576c59c300e3620` | Python 66%, HTML 19% | permissiva | 25 MB |
| `mealie-recipes/mealie` | `v3.31.0` | `c87f20d1293b6e7732afe1b25d07ed79152b75a8` | Python 63%, Vue 21% | copyleft di rete | 447 MB |
| `wagtail/wagtail` | `v8.1` | `99924bbfbfd5075f9d603771981111ffd9e4a1c1` | Python 77%, JavaScript 11% | permissiva | 258 MB |
| `ckan/ckan` | `ckan-2.12.1` | `3e9afe078125182454c36c8adfc96f545d119553` | Python 72%, CSS 11% | non identificata da GitHub | 230 MB |
| `indico/indico` | `v3.3.14` | `a42252ead3509f9b31db0691cc9af899ab18416e` | Python 56%, JavaScript 24% | permissiva | 275 MB |
| `DefectDojo/django-DefectDojo` | `3.5.300` | `cd0a4483a224707f72a0fc3112359089c1446b55` | Python 54%, HTML 37% | permissiva | 1053 MB |
| `TryGhost/Ghost` | `v6.79.0` | `11ae15f26fdd3529175cc9691b6f8c7254f7dfd5` | TypeScript 68%, JavaScript 29% | permissiva | 633 MB |
| `louislam/uptime-kuma` | `2.5.12` | `5aa5dec425f8a955b54e150636979a6927745ec5` | JavaScript 51%, Vue 34% | permissiva | 39 MB |
| `NodeBB/NodeBB` | `v4.16.9` | `9df08d2c0987fdce6047992e4274cb2cbfd1948d` | JavaScript 87%, Go Template 11% | copyleft forte | 113 MB |
| `requarks/wiki` | `3.6.1` | `ef6e6d5eb8913306f1d2916a99f7810ada94f042` | TypeScript 42%, Vue 36% | copyleft di rete | 51 MB |
| `umami-software/umami` | `v3.5.0` | `d3c62a805beda8643cb468924dda38617fb4c286` | TypeScript 98%, JavaScript 0% | permissiva | 34 MB |
| `hoppscotch/hoppscotch` | `2026.11.0` | `6177eae1875ea4cc8fc46604d65bf85478912d85` | TypeScript 67%, Vue 23% | permissiva | 98 MB |
| `immich-app/immich` | `v3.4.2` | `b6b4b80df113656bfa4872cab31c7319e89438a9` | TypeScript 55%, Dart 26% | copyleft di rete | 321 MB |
| `actualbudget/actual` | `v26.11.0` | `1766241e3f4b3c578e424c4fa15f1eb83c0da17d` | TypeScript 95%, JavaScript 3% | permissiva | 753 MB |
| `verdaccio/verdaccio` | `v7.1.2` | `162407d0bfd8333fd45ac7fc9dd1bc313c18a592` | TypeScript 95%, JavaScript 2% | permissiva | 683 MB |
| `parse-community/parse-server` | `8.6.123` | `e7ff814113e52ab5e1127c25670503966481046e` | JavaScript 98%, TypeScript 1% | permissiva | 156 MB |
| `medusajs/medusa` | `v2.23.1` | `c2e715d7ee2aafae72bf7d4866b8795536e968c5` | TypeScript 87%, JavaScript 12% | non identificata da GitHub | 902 MB |
| `payloadcms/payload` | `v3.94.2` | `d6297974e6a86dcfcd9ca11ff625d363b3ae11e9` | TypeScript 95%, CSS 2% | permissiva | 241 MB |
