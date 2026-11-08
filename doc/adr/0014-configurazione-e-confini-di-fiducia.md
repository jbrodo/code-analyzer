# ADR-0014: Configurazione di Fase 1 e confini di fiducia

- Stato: Proposto
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
