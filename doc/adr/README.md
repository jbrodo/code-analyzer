# Architecture Decision Record

Decisioni necessarie prima di implementare la Fase 1 (`doc/PROJECT.md` §13). `Proposto` significa che la decisione attende conferma: dove indicato serve l'utente, negli altri casi basta la revisione tecnica.

| ADR | Titolo | Stato | Decisione umana |
| --- | --- | --- | --- |
| [0001](0001-verso-dipendenze-pacchetti.md) | Verso delle dipendenze tra i pacchetti | Accettato | No |
| [0002](0002-motore-scansione-senza-temporal.md) | Motore di scansione indipendente da Temporal | Proposto | No |
| [0003](0003-autorita-contratti-json-schema.md) | Autorità dei contratti JSON Schema | Proposto | No |
| [0004](0004-esecuzione-plugin-e-isolamento.md) | Esecuzione dei plugin e livelli di isolamento | Proposto | Sì |
| [0005](0005-firma-immagini-plugin.md) | Firma e verifica delle immagini dei plugin | Proposto | Sì |
| [0006](0006-feed-vulnerabilita-offline.md) | Database delle vulnerabilità in Fase 1 | Proposto | Sì |
| [0007](0007-contratto-output-plugin.md) | Adattatori, ordine dei plugin, versioni dei formati | Proposto | No |
| [0008](0008-fingerprint-e-dedup.md) | Algoritmo di fingerprint e deduplicazione | Proposto | No |
| [0009](0009-livelli-e-gate-fase-1.md) | Livelli e gate senza scoring né baseline | Proposto | Sì |
| [0010](0010-contratto-cli-e-artefatti.md) | Contratto della CLI e artefatti di scansione | Proposto | No |
| [0011](0011-sarif-aggregato.md) | Struttura del SARIF aggregato | Proposto | No |
| [0012](0012-segreti-in-fase-1.md) | Rilevamento dei segreti in Fase 1 | Proposto | Sì |
| [0013](0013-policy-licenze.md) | Valutazione della policy di licenze | Proposto | Sì |
| [0014](0014-configurazione-e-confini-di-fiducia.md) | Configurazione e confini di fiducia | Proposto | No |
| [0015](0015-regole-semgrep-e-licenze-motori.md) | Regole Semgrep e licenze dei motori | Proposto | Sì |

## Lacune rinviate

Numerazione di `.claude/agents/architect.md`.

| Lacuna | Fase |
| --- | --- |
| 1 Dashboard (UI elenco finding) | 2; portfolio in 4 |
| 2 API insufficienti per la UI | 2 |
| 3 RBAC | 2 |
| 4 Scoring ombra | 2 |
| 5 Fattori non definiti | 2 |
| 6 Soglie discontinue | 2 (ADR-0009 usa già intervalli semiaperti per CVSS) |
| 10 `agent_runs` | 3 |
| 11 Multi-tenancy | 2 (progettazione con il primo schema DB); packaging in 4 |
| 12 OpenAPI | 2 (principio in ADR-0003) |
| 13 Evidenza decisionale | 3 |
