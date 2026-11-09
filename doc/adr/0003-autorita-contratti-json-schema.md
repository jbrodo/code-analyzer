# ADR-0003: Autorità dei contratti JSON Schema

- Stato: Accettato il 2026-11-08 in revisione tecnica (A-01); vedi "Revisione A-01" in fondo
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §2, §3, §4.1, §16 regola 1; lacuna 12 (solo il principio: l'OpenAPI arriva in Fase 2)

## Contesto

§4.1 scrive i modelli in Pydantic, §3 pubblica `schemas/*.json` e §16 chiede di aggiornarli entrambi. Sono due copie dello stesso contratto senza una fonte dichiarata. In Fase 1 i consumatori indipendenti sono chi scrive `.code-analyzer.yml`, chi legge il report JSON e i plugin.

## Opzioni

1. Schemi e modelli scritti a mano e allineati da test: due fonti.
2. JSON Schema canonico, modelli generati: si discosta da §4.1 e aggiunge un generatore.
3. Modelli Pydantic come sorgente, schemi esportati e versionati in `schemas/`, allineamento verificato in CI.

## Raccomandazione

Opzione 3, coerente con §2 (OpenAPI generata) e §4.1.

- L'artefatto autorevole per i consumatori è il file in `schemas/`; il modello Pydantic è il suo generatore.
- La modifica di un contratto è una PR che tocca modello e schema esportato insieme; la revisione parte dal diff dello schema. Il task del contratto precede sempre i task che lo implementano.
- CI: l'esportazione con `--check` fallisce se `schemas/` non è allineato.
- Test di contratto, fixture e report CLI si validano contro i file in `schemas/`, senza importare i modelli.
- Modelli con `extra="forbid"`; ogni schema ha `$id` e versione. Dentro una versione maggiore sono ammesse solo aggiunte compatibili; il resto richiede una nuova versione maggiore.
- Schemi di Fase 1: `finding`, `plugin-manifest`, `code-analyzer-config` (§3) e il nuovo `scan-report` (ADR-0010).
- Gli schemi ufficiali SARIF 2.1.0 e CycloneDX sono copiati e fissati nel repository: la validazione non usa la rete e risolve `$ref` solo da percorsi locali ammessi.
- In Fase 2 l'OpenAPI seguirà lo stesso flusso: esportata, versionata, verificata in CI.

## Conseguenze

- Una sola fonte per contratto e diff revisionabili.
- Il rischio "contratto scritto dopo l'implementazione" si controlla con l'ordine dei task, non con lo strumento: il planner deve mettere modelli ed export per primi.
- Modifiche proposte a §4.1 da ADR-0008 e ADR-0009 entrano nello schema `finding` fin dalla prima esportazione.

## Emendamento dopo A-01

Data: 2026-11-08. Esito della revisione dei contratti dei plugin. La scelta (opzione 3) non cambia.

- `plugin-sarif-properties` è uno schema di Fase 1: serve perché gli adattatori nelle immagini non importano `ca-core` (C-05).
- `extra="forbid"` vale anche per `PluginSarifProperties`, senza eccezioni (ADR-0007).
- Un'invariante che JSON Schema non può esprimere, come due percorsi di `outputs` diversi tra loro, vive nel validatore del modello ed è descritta nella `description` dello schema. Si copre con un test sul modello: è l'unico caso in cui il test di contratto non basta.

## Revisione A-01

Data: 2026-11-08. `Accettato`: il flusso scelto è in funzione e verificato.

Evidenze:

- `ca_core/schema_export.py` genera i cinque schemi di Fase 1, ciascuno con `$id` e `x-schema-version`. `--check` è verde e gira in `.github/workflows/verify.yml`.
- `tests/contract/` valida contro i file in `schemas/` con `jsonschema`, a rete bloccata.
- Gli schemi esterni sono fissati con SHA-256 in `schemas/vendor/SOURCES.json`; `ca_core/schema_validation.py` rifiuta i `$ref` fuori catalogo.

Il report della CLI non esiste ancora: la sua validazione contro `schemas/` arriva con T-07 e riusa lo stesso meccanismo, quindi non condiziona la decisione. La revisione ha trovato vincoli solo nel modello che lo schema può esprimere: sono errori di applicazione, da correggere con gli emendamenti di C-01..C-05 e C-07 del piano, e non cambiano la scelta.

### Dove vive un'invariante

Questa regola precisa l'ultimo punto dell'emendamento precedente. Il modello resta il generatore, ma un consumatore esterno vede solo lo schema: ciò che lo schema può dire, lo deve dire.

| Tipo di vincolo | Dove vive | Prova |
| --- | --- | --- |
| Esprimibile in JSON Schema 2020-12, anche con `if`/`then`, `contains`, `not`, `uniqueItems` o `allOf` su un enum finito | Nello schema, con `json_schema_extra` se Pydantic non lo genera, e nel modello | Caso non valido in `tests/contract/` |
| Confronto tra valori della stessa istanza, o unicità per chiave in un array di oggetti | Validatore del modello e `description` nello schema | Test sul modello |
| Dipende da un altro documento, come il manifest | Normalizzazione, con `description` nello schema | Test della normalizzazione |

`uniqueItems` confronta gli elementi interi e non una loro chiave, e `$data` non è standard: per questo unicità di `plugins[].name`, `tool` primo di `tools`, `end_line` non precedente a `start_line` e percorsi di `outputs` diversi restano nel secondo tipo.

Un'alternativa per l'unicità sarebbe `plugins` come oggetto indicizzato dal nome. Scartata: cambia la forma del report per un caso che il modello già rifiuta, e l'emettitore è solo Code Analyzer.

### `tests/contract/`

Confermata, anche se assente da §3: è il livello "Contratto" di §14 e ha una regola propria rispetto a `tests/unit/`, cioè leggere gli artefatti pubblicati senza importare i modelli. §3 si aggiorna con A-03.

Unica eccezione ammessa: i file `test_*_model_equivalence.py`, che importano il modello per verificare che modello e schema accettino gli stessi casi. Stanno in file separati, così la regola resta controllabile sugli altri.

### Versione degli schemi

Finché non esiste un rilascio, una correzione che allinea lo schema a ciò che il modello già rifiutava non cambia la versione: nessun documento valido per il prodotto diventa non valido. Dal primo rilascio vale la regola della versione maggiore.

## Emendamento per R-09: schemi nel pacchetto installato

Data: 2026-11-09. `vendor_schema_store()` cerca `schemas/vendor` risalendo l'albero dei sorgenti, quindi una CLI installata esce con 2 ("schemi fissati non utilizzabili"). La scelta (opzione 3) non cambia.

Due casi distinti:

- **Contratti del progetto** (`schemas/*.schema.json`). A run time non servono file: `publish` usa `Contract.render()` dal modello installato. La fonte resta il modello, l'artefatto per i consumatori resta `schemas/`, e `schema_export --check` non cambia.
- **Schemi di terzi fissati** (SARIF, CycloneDX e dipendenti, `SOURCES.json`). Servono a run time, e sono l'unica cosa da impacchettare.

Opzioni per i secondi:

1. **File reali nel pacchetto `ca-core`, cartella `schemas/vendor` come symlink verso di essi.** Una sola copia, nel wheel senza configurazione.
2. Copia in `ca-core` con controllo CI sull'uguaglianza: due copie, proprio ciò che questo ADR evita.
3. File in `schemas/vendor` e symlink dentro il pacchetto: dipende da come il backend di build tratta i symlink e la cartella di destinazione non è nel modulo.
4. Hook di build che copia: `uv_build` non ha hook.

Decisione: opzione 1.

- `git mv schemas/vendor packages/ca-core/src/ca_core/vendor_schemas`, poi `schemas/vendor` diventa il symlink relativo `../packages/ca-core/src/ca_core/vendor_schemas`. Provato con `uv build` il 2026-11-09: la cartella finisce nel wheel, senza dover configurare nulla. I percorsi `ROOT / "schemas" / "vendor"` dei test e `check` di `schema_export`, che guarda solo il primo livello di `schemas/`, restano validi.
- Lettura: nuovo classmethod `SchemaStore.packaged()` in `schema_validation.py`, con `importlib.resources.files("ca_core").joinpath("vendor_schemas")` e `as_file`, come `load_packaged_manifest` per i manifest; il costruttore carica tutto in memoria, quindi il contesto può chiudersi subito. `ca-core` resta senza infrastruttura: è libreria standard.
- `vendor_schema_store()` diventa una chiamata a `SchemaStore.packaged()`, mai più una ricerca nell'albero.

Conferma dello SHA. `SchemaStore.__init__` verifica già ogni file contro `SOURCES.json`, ma il manifest è nella stessa cartella e prova solo la coerenza interna. Si ancora nel codice: `VENDOR_MANIFEST_SHA256` in `schema_validation.py`, valore attuale `f585c7cf10428a2323bb03def6013bb20e5cac7497f52e1c3b97c3aadfa2035b`. `packaged()` lo controlla prima di costruire lo store e solleva `SchemaRefusedError`; il costruttore resta invariato per i test che usano cartelle costruite a mano. Aggiornare uno schema fissato tocca così, in una stessa modifica revisionabile, file, `SOURCES.json` e costante.

Test: `tests/contract/test_packaged_schemas.py` costruisce il wheel di `ca-core` con `uv build`, lo installa in un ambiente pulito e, fuori dal repository, apre `SchemaStore.packaged()` e valida un SARIF minimo. Serve `uv`, nessuna rete.

Effetto collaterale da segnalare a D-0015: gli schemi di terzi entrano nel pacchetto distribuito, e questo emendamento non valuta le loro licenze.
