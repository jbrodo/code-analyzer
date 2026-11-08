# ADR-0003: Autorità dei contratti JSON Schema

- Stato: Proposto
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
