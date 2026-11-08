<!-- Sync Impact Report
Version change: not established -> 1.0.0 (initial adoption)
Modified principles: none (initial adoption)
Added sections: Vincoli tecnici; Workflow di sviluppo e qualità
Removed sections: none
Follow-up TODOs: none
-->

# Code Analyzer Constitution

## Core Principles

### I. Evidenza deterministica
I finding mostrati all'utente MUST derivare da evidenze verificabili prodotte da scanner o
analisi deterministiche. Gli LLM MAY spiegare i finding e proporre correzioni, ma MUST NOT
essere l'unica fonte per crearli, sopprimerli o chiuderli. Ogni modifica generata richiede
revisione umana prima del merge.

### II. Contratti interoperabili
I formati pubblici e gli output interoperabili MUST rispettare gli standard adottati dal
progetto. Ogni modifica a modelli o schemi MUST aggiornare nella stessa modifica gli schemi,
le fixture e i test di contratto interessati. Le decisioni tecniche MUST seguire gli ADR
accettati; gli ADR proposti non sono decisioni approvate.

### III. Privilegio minimo e controllo umano
Scanner e plugin MUST ricevere solo i permessi e gli accessi necessari; l'accesso alla rete
è disabilitato salvo autorizzazione esplicita. Le modifiche proposte dagli agenti MUST
restare soggette a revisione umana e non possono essere unite automaticamente.

### IV. Verifiche riproducibili
Ogni modifica comportamentale MUST essere coperta da test pertinenti, inclusi i casi di
errore rilevanti. I test MUST essere deterministici e non chiamare servizi esterni né LLM
a pagamento. Prima di completare una modifica si eseguono i controlli esistenti pertinenti.

### V. Confini architetturali espliciti
Le dipendenze tra pacchetti MUST rispettare i confini definiti nel progetto. `ca-core` MUST
restare indipendente da framework, rete e processi esterni. Nuove astrazioni o dipendenze
si introducono solo quando necessarie a soddisfare un requisito verificabile.

## Vincoli tecnici

- Il backend usa Python 3.12 o superiore e gestisce le dipendenze con `uv`.
- I finding usano SARIF 2.1.0; gli SBOM usano CycloneDX 1.7.
- Workspace e input degli scanner sono in sola lettura; output e rete seguono le policy
  definite in `doc/PROJECT.md` e negli ADR accettati.
- Le modifiche ai contratti condivisi mantengono coerenti produttori, consumatori, schemi
  e test di contratto.

## Workflow di sviluppo e qualità

- Le nuove funzionalità seguono il flusso Spec Kit: specifica, piano, task, implementazione
  e verifica finale. Chiarimento, checklist e analisi di coerenza si aggiungono quando
  riducono ambiguità o rischio.
- Le skill Spec Kit si invocano nella chat di GitHub Copilot, una alla volta; gli artefatti
  generati in `specs/` si revisionano prima di avviare l'implementazione.
- Ogni modifica è verificata con i test e i controlli di qualità pertinenti; i gate e le
  decisioni ancora proposte restano espliciti e non si considerano approvati per inferenza.

## Governance

Questa costituzione governa le specifiche e il lavoro degli agenti. Se entra in conflitto
con un requisito o una decisione tecnica, il conflitto MUST essere chiarito prima
dell'implementazione; non si risolve ignorando uno dei documenti. Ogni revisione MUST
verificare la conformità ai principi applicabili. Le modifiche alla costituzione passano
da `/speckit-constitution`, richiedono revisione umana e incrementano la versione secondo
SemVer: MAJOR per cambi incompatibili, MINOR per nuovi principi o vincoli sostanziali,
PATCH per chiarimenti non semantici.

**Version**: 1.0.0 | **Ratified**: 2026-11-08 | **Last Amended**: 2026-11-08
