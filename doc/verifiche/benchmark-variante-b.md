# Benchmark della Variante B (K-06)

Procedura ed esito della distribuzione di benchmark di ADR-0023 (D2-11). Il dato è `packages/ca-core/src/ca_core/scoring/benchmark.json`, contratto `scoring-benchmark`; lo legge `ca_core.scoring.benchmark`. Solo numeri e l'identità del corpus pubblico: nessun percorso, nome di funzione o testo del codice misurato.

## Corpus

Approvato dall'utente il 2026-11-26 (ADR-0023). Ultimo tag di rilascio stabile a quella data; il commit è quello puntato dal tag. Elenco con i commit in `scripts/benchmark/corpus.json`.

| Repository | Tag | Linguaggi misurati | Pilota |
| --- | --- | --- | --- |
| `saleor/saleor` | 3.23.50 | Python | sì |
| `fastapi/full-stack-fastapi-template` | 0.12.0 | Python, TS | sì |
| `excalidraw/excalidraw` | v0.18.1 | TS | sì |
| `pallets/flask` | 3.1.3 | Python | |
| `encode/httpx` | 0.28.1 | Python | |
| `scrapy/scrapy` | 2.20.0 | Python | |
| `django/django` | 6.1.3 | Python, JS | |
| `expressjs/express` | v5.3.0 | JS | |
| `vuejs/core` | v3.5.46 | TS | |
| `vitejs/vite` | v8.3.8 | TS | |

L'ultimo rilascio di httpx è del 2024-12; il repository è attivo, ma il tag è più citabile della punta del branch. django non pubblica release su GitHub: il tag è l'ultimo stabile tra i suoi tag.

## Procedura

1. Registry locale e CLI impacchettata con le immagini firmate: `docker compose -f deploy/compose/registry.yaml up -d --wait`, poi `COSIGN=… SYFT=… CA_KEY_DIR=<fuori dal repo> deploy/docker/package-cli.sh <pkg>`.
2. Raccolta (unico passo con la rete, i `git clone`):
   `COSIGN=… CA_COSIGN_PUBLIC_KEY=<pkg>/cosign.pub python3 scripts/benchmark/benchmark.py collect --work <fuori dal repo> --python <pkg>/venv/bin/python`.
   Per ogni repository: clone superficiale al tag, controllo del commit, `scan` con ruff, eslint e ca-graph tramite `scan_child.py`, che compone il `Context` con `{"benchmark": true}` per ruff ed eslint e limiti di uscita e tempo più larghi. La CLI non ha un'opzione per la modalità benchmark. Un repository già misurato non si riscansiona.
3. Aggregazione, senza rete: `uv run python scripts/benchmark/benchmark.py aggregate --work <stessa cartella> --version <n>`, poi `… check`.

Un report vale se ca-graph e almeno uno tra ruff ed eslint sono `ok` e nessun plugin è fallito; lo stato `partial` dovuto a collegamenti simbolici non seguiti è ammesso (saleor, fastapi, django e vite ne hanno). I file di test si scartano con le regole fisse di ADR-0022.

## Esito del 2026-11-26 (versione 1)

Pacchetto da `package-cli.sh` sull'albero di lavoro di K-06 (13 plugin, ruff, eslint e ca-graph alla versione 1.0.0 del plugin), macchina di sviluppo con venti core. Durate delle scansioni: da 6 s (httpx) a 192 s (django), circa 9 minuti in tutto.

| Regola | Repository | Osservazioni | Mediana | 99% | Massimo | F(soglia) | Valori distinti sopra soglia |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ruff `C901` (10) | 6 | 20 437 | 2 | 10 | 75 | 0,991 | 19 |
| ruff `PLR0911` (6) | 6 | 14 825 | 1 | 4 | 18 | 0,999 | 5 |
| ruff `PLR0912` (12) | 6 | 10 452 | 2 | 13 | 62 | 0,988 | 23 |
| ruff `PLR0913` (5) | 6 | 15 675 | 2 | 12 | 25 | 0,958 | 13 |
| ruff `PLR0915` (50) | 6 | 17 047 | 3 | 32 | 143 | 0,998 | 19 |
| eslint `complexity` (10) | 5 | 17 066 | 1 | 22 | 212 | 0,960 | 51 |
| eslint `max-depth` (4) | 5 | 15 609 | 1 | 6 | 9 | 0,970 | 5 |
| eslint `max-lines-per-function` (50) | 5 | 16 357 | 6 | 159 | 10 680 | 0,939 | 133 |
| eslint `max-params` (5) | 5 | 13 284 | 1 | 5 | 29 | 0,991 | 8 |

| Smell | Ambito | Repository | Smell | Mediana della dimensione | Massimo |
| --- | --- | --- | --- | --- | --- |
| Cyclic Dependency | modulo | 7 | 55 | 4 | 818 |
| Cyclic Dependency | pacchetto | 8 | 26 | 4 | 135 |
| Hub-Like Dependency | modulo | 9 | 441 | 10 | 115 |
| Unstable Dependency | pacchetto | 7 | 94 | 3 | 18 |

Le osservazioni contano le funzioni (per `max-depth`, i blocchi) con valore da 1 in su: i motori non riportano gli zeri, e l'indice non ne dipende (ADR-0023). Il numero di repository dei Python e dei JS/TS segue i linguaggi presenti.

Esempi di intensità con le soglie attuali, `(F(v) − F(t)) / (1 − F(t))`: complessità 20 dà 0,88 con ruff e 0,68 con eslint, 40 dà 0,98 e 0,94; sei argomenti (uno sopra la soglia di ruff) danno 0,10, dieci danno 0,60.

## Cosa ha trovato la procedura

- **Risoluzione della coda.** Con 101 quantili la parte sopra soglia cadeva in 1–6 punti. Ora la griglia ha 281 livelli: ogni 1% fino al 90%, ogni 0,1% fino al 99%, poi ogni 0,01% (ADR-0023).
- **eslint e i nomi dei file.** L'adattatore scriveva l'`uri` senza codifica percentuale: una cartella `#` di vite faceva fallire il plugin. Corretto (ADR-0004, emendamento per K-06).
- **Collegamenti simbolici.** eslint e ruff seguono i file collegati e li segnalano, e l'host, che non li legge, faceva fallire il plugin (vite). Ora i due adattatori scartano quei risultati. Gli altri adattatori non sono stati provati su collegamenti né su nomi di file insoliti: controllo da fare (ADR-0004).
- **Dimensioni dei cicli.** Pochi smell per tipo (26–55 per i cicli) con code molto lunghe (un ciclo di 818 moduli): la distribuzione delle dimensioni dei cicli è la meno stabile del benchmark.
- **Hub-Like.** 441 smell su nove repository; 123 (28%) hanno fan-in e fan-out di 1, cioè una dimensione di 2. ADR-0020 lo prevedeva: senza una guardia sul grado l'hub dà rumore, perché sui grafi reali la mediana del grado è spesso 0 o 1. La distribuzione delle dimensioni lo assorbe in parte (un hub piccolo ha G basso), ma la guardia resta da fare.

## Rifarlo

Si rifà con una `version` nuova quando cambia un plugin che misura (ruff, eslint, ca-graph), le regole o le soglie della modalità benchmark, o il corpus. Non si rifà da sé: nessuna scansione lo ricalcola (D2-11).
