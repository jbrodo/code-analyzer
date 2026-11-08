# ADR-0014: Configurazione di Fase 1 e confini di fiducia

- Stato: Proposto; confermati il 2026-11-08 in revisione tecnica (A-01) lo schema e i montaggi. Filtro, eccezioni e `config validate` non esistono ancora (K-08, K-09, L-02)
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §5, §7, §8, §17

## Contesto

`.code-analyzer.yml` (§8) sta nel repository analizzato, quindi è un input non fidato, ma contiene anche il gate e le eccezioni. Mancano: l'esclusione di percorsi (servirà subito per `node_modules` e per le fixture vulnerabili di questo stesso monorepo, altrimenti l'auto-analisi di §17 non può passare) e il comportamento delle chiavi di fasi successive. `approved_by` è testo libero: non autentica nessuno.

## Opzioni

1. Schema con le sole chiavi di Fase 1: i file conformi a §8 falliscono la validazione.
2. Schema completo di §8, con le chiavi future accettate e inerti.

## Raccomandazione

Opzione 2.

Il repository può decidere: `languages`, `paths.exclude`, `gate`, `licenses`, `plugins.disable`, opzioni per plugin, `exceptions`.

Il repository non può mai decidere: immagine, digest, verifica della firma, livello di isolamento, modalità di rete, montaggi, comando dei plugin, origini dei feed. Questi valori vengono solo dal pacchetto CLI, dai flag o dall'ambiente.

- Schema con `additionalProperties: false` e `version: 1`. `service`, `scoring` e `agents` sono validati, inerti in Fase 1 e segnalati nel report.
- Nuova chiave `paths.exclude` (glob relativi), con predefiniti per `node_modules`, `.venv`, `dist`, `.git` e gli artefatti di output. Il filtro autorevole è nella normalizzazione; passare le esclusioni allo scanner è solo un'ottimizzazione. L'esclusione di `.git` non vale per gitleaks.
- `plugins.semgrep.rules`: percorsi relativi al workspace, controllati per contenimento.
- Eccezioni applicate in Fase 1: fingerprint corrispondente e `expires` non superata imposta `status = accettato`. Se scaduta, viene ignorata con avviso. VEX resta fuori.
- `config validate` è un controllo offline: schema, espressioni SPDX, date, percorsi.

## Conseguenze

- In CI chi modifica il branch può indebolire gate ed eccezioni modificando il file: limite noto di Fase 1. Il report elenca sempre plugin disattivati, eccezioni ed esclusioni. Con `--fail-on` la CI fissa la soglia. In Fase 2 la modalità PR deve leggere la configurazione dal branch base.
- `approved_by` è una dichiarazione finché non esiste un RBAC (lacuna 3, Fase 2).
- §8 va integrato con `paths.exclude`; il monorepo avrà un proprio `.code-analyzer.yml` che esclude `tests/fixtures/` e `golden-set/`.

## Emendamento dopo A-01

Data: 2026-11-08. Esito della revisione di `inputs` nel manifest. La scelta non cambia.

- `inputs.config` è un JSON generato dall'host con la sola parte pertinente al plugin, dopo la validazione: mai il file del repository, che contiene gate ed eccezioni non utili al plugin. Confermato.
- Montaggi fissi `/inputs/sbom.cdx.json` e `/inputs/config.json`, in sola lettura e decisi dal contratto: confermati, il repository non può decidere i montaggi. `x-mount-path` nello schema è solo documentazione.
- `inputs.*` ammette `none` o `optional`, e con `optional` il file può mancare: confermato. L'SBOM montato è una copia validata dall'host, mai il file in `/out` del plugin che l'ha prodotto.
- Una richiesta di esecuzione con un ingresso che il manifest dichiara `none` è un errore, così un input non dichiarato non può arrivare al container.

## Revisione A-01

Data: 2026-11-08. Resta `Proposto`: lo schema c'è, l'applicazione delle regole no.

Confermato:

- `code-analyzer-config` è chiuso, ha `version: 1` e `paths.exclude`, e non offre chiavi per immagine, digest, firma, isolamento, rete, montaggi, comando o feed. `service`, `scoring` e `agents` sono validati e il report li elenca in `inert_sections`.
- I percorsi di montaggio sono costanti del contratto (`ca_core/models/plugin_manifest.py`). `PluginRunRequest` rifiuta un ingresso che il manifest dichiara `none`.

Da provare:

- Filtro autorevole e predefiniti: K-08. Eccezioni: K-09. `config validate`: L-02. Montaggi reali e `config.json` generato dall'host: R-02, K-16.

Lo schema accetta percorsi assoluti o con `..` e lo stesso livello in `block_on` e `warn_on`, che il modello rifiuta: entrambi esprimibili, si correggono con l'emendamento di C-03. Il contenimento vero resta a runtime.
