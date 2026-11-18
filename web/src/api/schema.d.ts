// GENERATO da schemas/openapi.json con `bun run types`: non modificare a mano.
// Il lint fallisce se non coincide con il contratto del server (ADR-0017).

export interface paths {
    readonly "/v1/findings/{id}": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Dettaglio di un finding */
        readonly get: operations["getFinding"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        /**
         * Triage di un finding
         * @description Un corpo cambia una cosa sola. `falso_positivo` richiede una motivazione; `accettato` si ottiene solo creando un'eccezione, con motivazione e scadenza futura; `risolto` non è assegnabile. `approved_by` è l'identità autenticata. Ruoli: `triage` per stato `aperto` o `in_corso` e owner; `approvatore` per falso positivo ed eccezioni.
         */
        readonly patch: operations["patchFinding"];
        readonly trace?: never;
    };
    readonly "/v1/health": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /**
         * Get Health
         * @description Il processo è vivo. Non controlla database né archivio.
         */
        readonly get: operations["getHealth"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/me": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /**
         * Identità, ruoli e tenant
         * @description L'unico endpoint che risponde 200 a un utente autenticato senza ruoli.
         */
        readonly get: operations["getMe"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/repositories": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Repository del tenant */
        readonly get: operations["listRepositories"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/repositories/{id}": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Un repository, con tier ed esposizione se registrati */
        readonly get: operations["getRepository"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        /** Registra tier ed esposizione (ADR-0028) */
        readonly patch: operations["patchRepository"];
        readonly trace?: never;
    };
    readonly "/v1/repositories/{id}/findings": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /**
         * Finding di un repository
         * @description Senza `scan`: la scansione corrente (ADR-0018). Con `scan`: quella data, che è il modo di vedere una PR. Nessun filtro implicito sul server. Ordine totale e stabile; paginazione a cursore, che vale solo per la stessa combinazione di filtri e ordinamento.
         */
        readonly get: operations["listFindings"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/repositories/{id}/graph": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Grafo dei moduli della scansione corrente */
        readonly get: operations["getRepositoryGraph"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/repositories/{id}/sbom": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** SBOM CycloneDX della scansione corrente */
        readonly get: operations["getRepositorySbom"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/repositories/{id}/scans": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Scansioni di un repository, dalla più recente */
        readonly get: operations["listRepositoryScans"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/scans": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        readonly get?: never;
        readonly put?: never;
        /**
         * Registra una scansione già eseguita (ingestione)
         * @description Corpo `multipart/form-data`: `report` (obbligatoria, `scan-report`), `sarif`, `sbom` e `graph` (facoltative). Ogni parte è un input non fidato, validato contro `schemas/`; un artefatto non valido respinge tutta la richiesta. Idempotente per (repository, SHA-256 del report): 201 la prima volta, 200 con lo stesso `id` alla ripetizione, 409 se la ripetizione porta artefatti diversi. Il repository del report deve coincidere con quello del token (403 `repository-mismatch`); oltre i limiti di dimensione 413.
         */
        readonly post: operations["createScan"];
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/scans/{id}": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Stato e riepilogo di una scansione */
        readonly get: operations["getScan"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/scans/{id}/sarif": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** SARIF aggregato della scansione */
        readonly get: operations["getScanSarif"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
    readonly "/v1/service-context": {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        /** Contesto del servizio del repository del token (ADR-0028) */
        readonly get: operations["getServiceContext"];
        readonly put?: never;
        readonly post?: never;
        readonly delete?: never;
        readonly options?: never;
        readonly head?: never;
        readonly patch?: never;
        readonly trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /**
         * Baseline
         * @description Esito del confronto con la baseline (ADR-0025, §7). I conteggi quadrano con i finding.
         */
        readonly Baseline: {
            /** Commit */
            readonly commit?: string | null;
            /**
             * Existing
             * @default 0
             */
            readonly existing: number;
            /**
             * New
             * @default 0
             */
            readonly new: number;
            /**
             * Not Evaluated
             * @description Finding della baseline che mancano perché il loro plugin è fallito: non sono né risolti né esistenti e il report lo dice (ADR-0025).
             * @default 0
             */
            readonly not_evaluated: number;
            /**
             * Reason
             * @description Codice dell'avviso (`baseline-commit-mismatch`, `baseline-partial`...).
             */
            readonly reason?: string | null;
            /** Resolved */
            readonly resolved?: readonly components["schemas"]["ResolvedFinding"][];
            readonly source?: components["schemas"]["BaselineSourceKind"] | null;
            readonly status: components["schemas"]["BaselineStatus"];
            /**
             * Updated
             * @description Fingerprint degli `existing` con posizione o livello cambiati: il SARIF li marca `updated` (ADR-0011, ADR-0025).
             */
            readonly updated?: readonly string[];
        };
        /**
         * BaselineSourceKind
         * @enum {string}
         */
        readonly BaselineSourceKind: "ci-artifact" | "base-scan" | "server";
        /**
         * BaselineState
         * @description Stato rispetto alla baseline (ADR-0025). Un finding `risolto` non è nel report: sta nella
         *     sezione `baseline` di `scan-report`. Assente: nessuna baseline valida.
         * @enum {string}
         */
        readonly BaselineState: "new" | "existing";
        /**
         * BaselineStatus
         * @enum {string}
         */
        readonly BaselineStatus: "valid" | "missing" | "rejected";
        /** Body_createScan */
        readonly Body_createScan: {
            /** Graph */
            readonly graph?: string | null;
            /**
             * Report
             * @description `scan-report`
             */
            readonly report: string;
            /** Sarif */
            readonly sarif?: string | null;
            /** Sbom */
            readonly sbom?: string | null;
        };
        /**
         * Category
         * @enum {string}
         */
        readonly Category: "quality" | "architecture" | "test" | "sast" | "dependency" | "license" | "secret" | "iac" | "health";
        /**
         * Confidence
         * @description §4.3. `osservato` (dati di esecuzione) non è prodotto in Fase 2.
         * @enum {string}
         */
        readonly Confidence: "dichiarato" | "dedotto" | "osservato";
        /**
         * CreateException
         * @description `approved_by` non è nel corpo: è l'identità autenticata (ADR-0019).
         * @example {
         *       "action": "create-exception",
         *       "expires": "2027-06-30",
         *       "reason": "Accettato fino alla migrazione"
         *     }
         */
        readonly CreateException: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            readonly action: "create-exception";
            /**
             * Expires
             * Format: date
             * @description Futura; non oltre il massimo configurato dal server.
             */
            readonly expires: string;
            /** Reason */
            readonly reason: string;
        };
        /**
         * Ecosystem
         * @enum {string}
         */
        readonly Ecosystem: "pypi" | "npm";
        /**
         * Edge
         * @description Da un modulo a un modulo (`target` è un percorso) o a un pacchetto esterno (un nome).
         */
        readonly Edge: {
            readonly confidence: components["schemas"]["Confidence"];
            /**
             * Dynamic
             * @default false
             */
            readonly dynamic: boolean;
            /**
             * External
             * @default false
             */
            readonly external: boolean;
            /**
             * Imports
             * @description Import che sostengono l'arco.
             */
            readonly imports: number;
            /** Source */
            readonly source: string;
            /** Target */
            readonly target: string;
            /**
             * Type Only
             * @default false
             */
            readonly type_only: boolean;
        };
        /**
         * EnrichmentSnapshot
         * @description Snapshot EPSS o KEV usato (ADR-0024): basta a riprodurre un punteggio a posteriori.
         */
        readonly EnrichmentSnapshot: {
            /** Content */
            readonly content?: {
                readonly [key: string]: string;
            };
            /**
             * Downloaded At
             * Format: date-time
             */
            readonly downloaded_at: string;
            /**
             * Feed
             * @enum {string}
             */
            readonly feed: "epss" | "kev";
            /**
             * Origin
             * @enum {string}
             */
            readonly origin: "public" | "mirror" | "cache";
            /** Sha256 */
            readonly sha256: string;
        };
        /** Entrypoint */
        readonly Entrypoint: {
            readonly confidence: components["schemas"]["Confidence"];
            readonly kind: components["schemas"]["EntrypointKind"];
            /** Path */
            readonly path: string;
        };
        /**
         * EntrypointKind
         * @enum {string}
         */
        readonly EntrypointKind: "package-metadata" | "main-module" | "web-application" | "html-entry" | "convention";
        /**
         * ExceptionOrigin
         * @enum {string}
         */
        readonly ExceptionOrigin: "server" | "repository";
        /** ExceptionRecord */
        readonly ExceptionRecord: {
            /** Approved By */
            readonly approved_by: string;
            /**
             * Approved By Verified
             * @description Falso per `repository`: è una dichiarazione, non verificata (ADR-0018).
             */
            readonly approved_by_verified: boolean;
            /**
             * Expires
             * Format: date
             */
            readonly expires: string;
            /**
             * Id
             * Format: uuid
             */
            readonly id: string;
            readonly origin: components["schemas"]["ExceptionOrigin"];
            /** Reason */
            readonly reason: string;
            /** Revoked At */
            readonly revoked_at?: string | null;
        };
        /** External */
        readonly External: {
            readonly ecosystem: components["schemas"]["Ecosystem"];
            /** Name */
            readonly name: string;
        };
        /** FeedSnapshot */
        readonly FeedSnapshot: {
            /** Origin */
            readonly origin: string;
            /**
             * Sync Failed
             * @description Sincronizzazione fallita: usato lo snapshot precedente.
             * @default false
             */
            readonly sync_failed: boolean;
            /**
             * Synced At
             * Format: date-time
             */
            readonly synced_at: string;
        };
        /** Finding */
        readonly Finding: {
            readonly baseline_state?: components["schemas"]["BaselineState"] | null;
            readonly category: components["schemas"]["Category"];
            /**
             * Correlation
             * @description Gruppo di correlazione (K-21, ADR-0026): finding di strumenti diversi sullo stesso problema nello stesso file. Non cambia fingerprint, livello né esito del gate.
             */
            readonly correlation?: string | null;
            /** Cve */
            readonly cve?: readonly string[];
            /** Cwe */
            readonly cwe?: readonly string[];
            /** Due Date */
            readonly due_date?: string | null;
            /** Evidence */
            readonly evidence?: {
                readonly [key: string]: unknown;
            };
            /** Fingerprint */
            readonly fingerprint: string;
            /**
             * First Seen
             * Format: date-time
             */
            readonly first_seen: string;
            /** Id */
            readonly id: string;
            readonly impact?: components["schemas"]["ImpactFactors"] | null;
            /**
             * Last Seen
             * Format: date-time
             */
            readonly last_seen: string;
            readonly level?: components["schemas"]["Level"] | null;
            readonly level_source?: components["schemas"]["LevelSource"] | null;
            /** License Spdx */
            readonly license_spdx?: string | null;
            readonly location: components["schemas"]["Location"];
            /** Message */
            readonly message: string;
            /** Owner */
            readonly owner?: string | null;
            /**
             * Pathless Key
             * @description Impronta degli ingredienti del fingerprint senza il percorso (ADR-0025): serve ad accoppiare un finding dopo un cambio di percorso. Non è un identificativo.
             */
            readonly pathless_key?: string | null;
            /**
             * Previous Path
             * @description Percorso nella baseline di un finding accoppiato dopo uno spostamento di file (ADR-0025, secondo passaggio). Solo con `baseline_state` `existing`.
             */
            readonly previous_path?: string | null;
            readonly remediation?: components["schemas"]["Remediation"] | null;
            /** Rule Id */
            readonly rule_id: string;
            /** Score */
            readonly score?: number | null;
            /** @default aperto */
            readonly status: components["schemas"]["Status"];
            /** Title */
            readonly title: string;
            /**
             * Tool
             * @description Primo di `tools` in ordine lessicografico (vincolo del modello, non dello schema).
             */
            readonly tool: string;
            /**
             * Tools
             * @description Tutti i tool di origine.
             */
            readonly tools: readonly string[];
            /**
             * Variant Scores
             * @description Punteggi in ombra di A e B (D2-10). Varianti uniche (vincolo del modello).
             */
            readonly variant_scores?: readonly components["schemas"]["VariantScore"][];
        };
        /** FindingDetail */
        readonly FindingDetail: {
            /**
             * Events
             * @description Dal più recente.
             */
            readonly events?: readonly components["schemas"]["FindingEvent"][];
            /** Exceptions */
            readonly exceptions?: readonly components["schemas"]["ExceptionRecord"][];
            readonly finding: components["schemas"]["Finding"];
            readonly occurrence?: components["schemas"]["Occurrence"] | null;
        };
        /** FindingEvent */
        readonly FindingEvent: {
            /** Action */
            readonly action: string;
            /** Actor */
            readonly actor: string;
            /**
             * At
             * Format: date-time
             */
            readonly at: string;
            readonly from_state?: components["schemas"]["Status"] | null;
            /** Reason */
            readonly reason?: string | null;
            readonly to_state?: components["schemas"]["Status"] | null;
        };
        /**
         * FindingListItem
         * @description Forma breve (ADR-0029): evidenze, fattori e passi di correzione stanno nel dettaglio.
         * @example {
         *       "category": "sast",
         *       "fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         *       "first_seen": "2026-11-17T12:00:00Z",
         *       "id": "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a10",
         *       "last_seen": "2026-11-17T12:00:00Z",
         *       "level": "alto",
         *       "level_a": "alto",
         *       "level_b": "alto",
         *       "level_source": "tool_severity",
         *       "new": true,
         *       "path": "app/run.py",
         *       "rule_id": "B602",
         *       "score_a": 49,
         *       "score_b": 49,
         *       "start_line": 3,
         *       "status": "aperto",
         *       "title": "Chiamata a subprocess con shell=True",
         *       "tools": [
         *         "bandit"
         *       ]
         *     }
         */
        readonly FindingListItem: {
            readonly category: components["schemas"]["Category"];
            /** @description Origine dell'eccezione che rende il finding `accettato`. */
            readonly exception_origin?: components["schemas"]["ExceptionOrigin"] | null;
            /** Fingerprint */
            readonly fingerprint: string;
            /**
             * First Seen
             * @description Nullo per un finding visto solo in una PR (ADR-0018).
             */
            readonly first_seen?: string | null;
            /**
             * Id
             * Format: uuid
             */
            readonly id: string;
            /** Last Seen */
            readonly last_seen?: string | null;
            readonly level?: components["schemas"]["Level"] | null;
            readonly level_a?: components["schemas"]["Level"] | null;
            readonly level_b?: components["schemas"]["Level"] | null;
            readonly level_source?: components["schemas"]["LevelSource"] | null;
            /**
             * New
             * @description Nuovo rispetto alla baseline (ADR-0025); assente senza baseline.
             */
            readonly new?: boolean | null;
            /** Owner */
            readonly owner?: string | null;
            /** Path */
            readonly path?: string | null;
            /** Rule Id */
            readonly rule_id: string;
            /** Score A */
            readonly score_a?: number | null;
            /** Score B */
            readonly score_b?: number | null;
            /** Start Line */
            readonly start_line?: number | null;
            readonly status: components["schemas"]["Status"];
            /** Title */
            readonly title: string;
            /** Tools */
            readonly tools: readonly string[];
        };
        /**
         * FindingPage
         * @example {
         *       "items": [],
         *       "total": 0,
         *       "total_new": 0
         *     }
         */
        readonly FindingPage: {
            /** Items */
            readonly items: readonly components["schemas"]["FindingListItem"][];
            /** Next Cursor */
            readonly next_cursor?: string | null;
            /**
             * Total
             * @description Finding con i filtri attivi.
             */
            readonly total: number;
            /**
             * Total New
             * @description Di questi, i nuovi rispetto alla baseline.
             */
            readonly total_new: number;
        };
        /**
         * Gate
         * @description Configurazione di gate effettiva. IPOTESI D-0009-A: `effective_mode` va tolto con essa.
         *
         *     `block_on` e `warn_on` sono quelli di `.code-analyzer.yml`, non risolti: il valore
         *     predefinito e la precedenza di `--fail-on` stanno nel gate (ADR-0009), mai nel report.
         */
        readonly Gate: {
            /** Block On */
            readonly block_on?: readonly components["schemas"]["Level"][] | null;
            readonly effective_mode: components["schemas"]["GateMode"];
            readonly mode: components["schemas"]["GateMode"];
            /** Warn On */
            readonly warn_on?: readonly components["schemas"]["Level"][] | null;
        };
        /**
         * GateMode
         * @description Modo richiesto. Quello effettivo lo registra il report (ADR-0009, ADR-0025):
         *     `new-findings-only` vale come `all` su una scansione completa o senza baseline valida.
         * @enum {string}
         */
        readonly GateMode: "all" | "new-findings-only";
        /** Graph */
        readonly Graph: {
            /** Edges */
            readonly edges?: readonly components["schemas"]["Edge"][];
            /** Entrypoints */
            readonly entrypoints?: readonly components["schemas"]["Entrypoint"][];
            /** Externals */
            readonly externals?: readonly components["schemas"]["External"][];
            readonly history: components["schemas"]["History"];
            /** Modules */
            readonly modules?: readonly components["schemas"]["Module"][];
            /** Packages */
            readonly packages?: readonly components["schemas"]["Package"][];
            readonly stats: components["schemas"]["Stats"];
            /**
             * Version
             * @constant
             */
            readonly version: 1;
        };
        /** Health */
        readonly Health: {
            /**
             * Status
             * @constant
             */
            readonly status: "ok";
        };
        /** History */
        readonly History: {
            /**
             * Commits Read
             * @default 0
             */
            readonly commits_read: number;
            /** Head Time */
            readonly head_time?: string | null;
            readonly status: components["schemas"]["HistoryStatus"];
            /** Window Days */
            readonly window_days: number;
        };
        /**
         * HistoryStatus
         * @description ADR-0022: con `superficiale` e `assente` il churn è ignoto, mai un conteggio inventato.
         * @enum {string}
         */
        readonly HistoryStatus: "completa" | "superficiale" | "assente";
        /** ImpactFactors */
        readonly ImpactFactors: {
            /** C */
            readonly c: number;
            /** E */
            readonly e: number;
            /** Evidence */
            readonly evidence?: {
                readonly [key: string]: unknown;
            };
            /** G */
            readonly g: number;
            /** P */
            readonly p: number;
            /** Variant */
            readonly variant: string;
        };
        /**
         * Isolation
         * @enum {string}
         */
        readonly Isolation: "gvisor" | "hardened-container";
        /**
         * Language
         * @enum {string}
         */
        readonly Language: "python" | "javascript" | "typescript" | "tsx";
        /**
         * Level
         * @enum {string}
         */
        readonly Level: "critico" | "alto" | "medio" | "basso";
        /**
         * LevelSource
         * @description IPOTESI D-0009-A: origine del livello provvisorio. Togliere con il campo `level_source`.
         * @enum {string}
         */
        readonly LevelSource: "tool_severity" | "policy" | "default" | "score" | "override";
        /** Location */
        readonly Location: {
            /** Commit */
            readonly commit?: string | null;
            /** Dependency Path */
            readonly dependency_path?: readonly string[];
            /**
             * End Line
             * @description Non precedente a `start_line` (vincolo del modello, non dello schema).
             */
            readonly end_line?: number | null;
            /** Path */
            readonly path?: string | null;
            /** Purl */
            readonly purl?: string | null;
            /** Repository */
            readonly repository: string;
            /** Start Line */
            readonly start_line?: number | null;
        };
        /**
         * Me
         * @example {
         *       "issuer": "https://idp.example",
         *       "name": "Ada",
         *       "roles": [
         *         "lettore",
         *         "triage"
         *       ],
         *       "subject": "user-42",
         *       "tenant": "acme"
         *     }
         */
        readonly Me: {
            /** Email */
            readonly email?: string | null;
            /** Issuer */
            readonly issuer: string;
            /** Name */
            readonly name?: string | null;
            /** Roles */
            readonly roles: readonly components["schemas"]["Role"][];
            /** Subject */
            readonly subject: string;
            /** Tenant */
            readonly tenant: string;
        };
        /**
         * Metrics
         * @description Calcolate dall'host sul grafo (G-04, G-08). Solo archi interni al repository.
         */
        readonly Metrics: {
            /** Fan In */
            readonly fan_in: number;
            /** Fan Out */
            readonly fan_out: number;
            /** Instability */
            readonly instability: number;
            /** Pagerank */
            readonly pagerank?: number | null;
        };
        /** Module */
        readonly Module: {
            /** Churn */
            readonly churn?: number | null;
            readonly language: components["schemas"]["Language"];
            readonly metrics?: components["schemas"]["Metrics"] | null;
            readonly parse: components["schemas"]["ParseStatus"];
            /** Path */
            readonly path: string;
            /**
             * Test
             * @default false
             */
            readonly test: boolean;
        };
        /**
         * Occurrence
         * @description Occorrenza nella scansione corrente, con fattori ed evidenze delle due varianti.
         */
        readonly Occurrence: {
            /** Commit */
            readonly commit: string;
            /**
             * Scan Id
             * Format: uuid
             */
            readonly scan_id: string;
            /** Variant Scores */
            readonly variant_scores?: readonly components["schemas"]["VariantScore"][];
        };
        /**
         * Outcome
         * @enum {string}
         */
        readonly Outcome: "ok" | "failed";
        /**
         * Package
         * @description Una cartella con almeno un modulo (ADR-0020). Derivato dall'host.
         */
        readonly Package: {
            readonly metrics: components["schemas"]["Metrics"];
            /** Modules */
            readonly modules: number;
            /** Path */
            readonly path: string;
        };
        /**
         * ParseStatus
         * @enum {string}
         */
        readonly ParseStatus: "completa" | "parziale";
        /** PluginRun */
        readonly PluginRun: {
            /** Digest */
            readonly digest: string;
            /**
             * Duration Seconds
             * @description Secondi.
             */
            readonly duration_seconds: number;
            /** Failure */
            readonly failure?: string | null;
            readonly feed?: components["schemas"]["FeedSnapshot"] | null;
            readonly isolation: components["schemas"]["Isolation"];
            /** Name */
            readonly name: string;
            readonly outcome: components["schemas"]["Outcome"];
            readonly signature: components["schemas"]["Signature"];
            /** Version */
            readonly version: string;
        };
        /**
         * Problem
         * @example {
         *       "code": "report-schema-invalid",
         *       "errors": [
         *         {
         *           "message": "valore non ammesso",
         *           "pointer": "/findings/0/level"
         *         }
         *       ],
         *       "status": 422,
         *       "title": "Il report non è valido",
         *       "type": "about:blank"
         *     }
         */
        readonly Problem: {
            readonly code: components["schemas"]["ProblemCode"];
            /** Detail */
            readonly detail?: string | null;
            /** Errors */
            readonly errors?: readonly components["schemas"]["ProblemError"][] | null;
            /**
             * Required Role
             * @description Con un 403 per ruolo: il ruolo richiesto (ADR-0019).
             */
            readonly required_role?: string | null;
            /** Status */
            readonly status: number;
            /**
             * Title
             * @description Testo breve, uguale per ogni occorrenza del tipo.
             */
            readonly title: string;
            /**
             * Type
             * @description URI stabile del tipo di problema.
             * @default about:blank
             */
            readonly type: string;
        };
        /**
         * ProblemCode
         * @description Enum del contratto: aggiungere un valore a una risposta è incompatibile (ADR-0017).
         * @enum {string}
         */
        readonly ProblemCode: "unauthenticated" | "forbidden" | "not-found" | "validation-failed" | "report-schema-invalid" | "payload-too-large" | "repository-mismatch" | "artifacts-conflict" | "state-conflict" | "invalid-cursor" | "rate-limited" | "not-implemented" | "internal-error";
        /** ProblemError */
        readonly ProblemError: {
            /**
             * Message
             * @description Cosa non va, mai il valore ricevuto.
             */
            readonly message: string;
            /**
             * Pointer
             * @description JSON Pointer nel corpo, oppure il nome del parametro.
             */
            readonly pointer: string;
        };
        /**
         * Remediation
         * @description I passi per risolvere un finding (ADR-0029). Sempre testo semplice: né l'API né la UI lo
         *     interpretano come HTML o Markdown. È della regola, non del risultato: nessun contenuto del
         *     repository analizzato. Nessun testo generato (gli LLM sono della Fase 3).
         */
        readonly Remediation: {
            /** References */
            readonly references?: readonly string[];
            readonly source: components["schemas"]["RemediationSource"];
            /** Text */
            readonly text: string;
        };
        /**
         * RemediationSource
         * @enum {string}
         */
        readonly RemediationSource: "tool" | "rule" | "derived";
        /**
         * ReportStatus
         * @enum {string}
         */
        readonly ReportStatus: "complete" | "partial";
        /** RepositoryPage */
        readonly RepositoryPage: {
            /** Items */
            readonly items: readonly components["schemas"]["RepositorySummary"][];
            /** Next Cursor */
            readonly next_cursor?: string | null;
        };
        /**
         * RepositoryPatch
         * @description Registrazione di tier ed esposizione (ADR-0028). Solo `amministratore`.
         */
        readonly RepositoryPatch: {
            /** Catalog Id */
            readonly catalog_id?: string | null;
            /** Internet Facing */
            readonly internet_facing?: boolean | null;
            /** Tier */
            readonly tier?: number | null;
        };
        /**
         * RepositorySummary
         * @example {
         *       "default_branch": "main",
         *       "id": "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11",
         *       "internet_facing": true,
         *       "name": "acme/shop",
         *       "provider": "github",
         *       "tier": 1
         *     }
         */
        readonly RepositorySummary: {
            /** Catalog Id */
            readonly catalog_id?: string | null;
            /** @description La scansione corrente (ADR-0018), se ce n'è una. */
            readonly current_scan?: components["schemas"]["ScanSummary"] | null;
            /** Default Branch */
            readonly default_branch?: string | null;
            /**
             * Id
             * Format: uuid
             */
            readonly id: string;
            /** Internet Facing */
            readonly internet_facing?: boolean | null;
            /** Name */
            readonly name: string;
            /**
             * Provider
             * @enum {string}
             */
            readonly provider: "github" | "gitlab";
            /** Tier */
            readonly tier?: number | null;
        };
        /**
         * ResolvedFinding
         * @description Un finding della baseline assente ora, con tutti i suoi strumenti riusciti (ADR-0025).
         */
        readonly ResolvedFinding: {
            /** Fingerprint */
            readonly fingerprint: string;
            /** Path */
            readonly path?: string | null;
            /** Rule Id */
            readonly rule_id: string;
            /** Title */
            readonly title: string;
        };
        /** RevokeException */
        readonly RevokeException: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            readonly action: "revoke-exception";
            /**
             * Exception Id
             * Format: uuid
             */
            readonly exception_id: string;
        };
        /**
         * Role
         * @description ADR-0019. Un utente può averne più d'uno; `amministratore` non include `approvatore`.
         * @enum {string}
         */
        readonly Role: "lettore" | "triage" | "approvatore" | "amministratore";
        /**
         * ScanDetail
         * @description I campi del report che non sono finding (ADR-0029): il server li ha dal report.
         */
        readonly ScanDetail: {
            /** @description Solo per una scansione di PR: conteggi di nuovi, esistenti, risolti. */
            readonly baseline?: components["schemas"]["Baseline"] | null;
            /** Enrichment */
            readonly enrichment?: readonly components["schemas"]["EnrichmentSnapshot"][];
            readonly gate: components["schemas"]["Gate"];
            /** Plugins */
            readonly plugins: readonly components["schemas"]["PluginRun"][];
            readonly scoring?: components["schemas"]["ScoringInfo"] | null;
            readonly summary: components["schemas"]["ScanSummary"];
            /** Warnings */
            readonly warnings: readonly components["schemas"]["Warning_"][];
        };
        /**
         * ScanKind
         * @enum {string}
         */
        readonly ScanKind: "full" | "pr";
        /** ScanPage */
        readonly ScanPage: {
            /** Items */
            readonly items: readonly components["schemas"]["ScanSummary"][];
            /** Next Cursor */
            readonly next_cursor?: string | null;
        };
        /** ScanRef */
        readonly ScanRef: {
            /**
             * Id
             * Format: uuid
             */
            readonly id: string;
        };
        /**
         * ScanSummary
         * @example {
         *       "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
         *       "duration_seconds": 412.5,
         *       "id": "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a10",
         *       "kind": "full",
         *       "ref": "refs/heads/main",
         *       "repository_id": "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11",
         *       "started_at": "2026-11-17T12:00:00Z",
         *       "status": "complete"
         *     }
         */
        readonly ScanSummary: {
            /** Commit */
            readonly commit: string;
            /** Duration Seconds */
            readonly duration_seconds: number;
            /**
             * Id
             * Format: uuid
             */
            readonly id: string;
            readonly kind: components["schemas"]["ScanKind"];
            /** Pull Request */
            readonly pull_request?: number | null;
            /** Ref */
            readonly ref?: string | null;
            /**
             * Repository Id
             * Format: uuid
             */
            readonly repository_id: string;
            /**
             * Started At
             * Format: date-time
             */
            readonly started_at: string;
            readonly status: components["schemas"]["ReportStatus"];
        };
        /**
         * ScoringInfo
         * @description Quale configurazione di scoring ha prodotto i punteggi (G2.a, D2-10).
         */
        readonly ScoringInfo: {
            /**
             * Active Variant
             * @enum {string}
             */
            readonly active_variant: "A" | "B";
            /** Config Version */
            readonly config_version: string;
            /**
             * Shadow
             * @description A e B calcolate entrambe: la seconda non decide il livello.
             * @default true
             */
            readonly shadow: boolean;
        };
        /** ServiceContextFile */
        readonly ServiceContextFile: {
            /** Catalog Id */
            readonly catalog_id?: string | null;
            /** Internet Facing */
            readonly internet_facing?: boolean | null;
            /**
             * Origin
             * @description Chi ha prodotto il file, dichiarato da chi lo scrive.
             */
            readonly origin?: string | null;
            /** Tier */
            readonly tier?: number | null;
            /**
             * Version
             * @description Versione del formato del file.
             */
            readonly version: number;
        };
        /** SetOwner */
        readonly SetOwner: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            readonly action: "set-owner";
            /** Owner */
            readonly owner?: string | null;
        };
        /**
         * SetStatus
         * @example {
         *       "action": "set-status",
         *       "reason": "Input già validato a monte",
         *       "status": "falso_positivo"
         *     }
         */
        readonly SetStatus: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            readonly action: "set-status";
            /**
             * Reason
             * @description Obbligatoria per `falso_positivo`.
             */
            readonly reason?: string | null;
            /**
             * Status
             * @enum {string}
             */
            readonly status: "aperto" | "in_corso" | "falso_positivo";
        };
        /**
         * Signature
         * @description Firma assente o non valida non genera un report (exit 2, ADR-0005): resta `skipped`.
         * @enum {string}
         */
        readonly Signature: "verified" | "skipped";
        /**
         * SortKey
         * @enum {string}
         */
        readonly SortKey: "impact" | "first_seen" | "path" | "score_a" | "score_b";
        /** Stats */
        readonly Stats: {
            /** Files Parsed */
            readonly files_parsed: number;
            /**
             * Files Partial
             * @default 0
             */
            readonly files_partial: number;
            /**
             * Files Skipped Name
             * @default 0
             */
            readonly files_skipped_name: number;
            /**
             * Files Skipped Size
             * @default 0
             */
            readonly files_skipped_size: number;
            readonly unresolved?: components["schemas"]["Unresolved"];
        };
        /**
         * Status
         * @enum {string}
         */
        readonly Status: "aperto" | "in_corso" | "accettato" | "falso_positivo" | "risolto";
        /**
         * Unresolved
         * @description Import che non hanno prodotto archi, per motivo: contati, mai inventati.
         */
        readonly Unresolved: {
            /**
             * Computed
             * @default 0
             */
            readonly computed: number;
            /**
             * Config Extends
             * @default 0
             */
            readonly config_extends: number;
            /**
             * Entrypoint Missing
             * @default 0
             */
            readonly entrypoint_missing: number;
            /**
             * Missing
             * @default 0
             */
            readonly missing: number;
            /**
             * Outside Workspace
             * @default 0
             */
            readonly outside_workspace: number;
        };
        /**
         * VariantScore
         * @description Punteggio in ombra di una variante (D2-10, ADR-0018): si calcolano A e B insieme, e ciascuna
         *     porta i suoi fattori con la loro evidenza. La forma esatta dei fattori è di ADR-0021 (A-06,
         *     ancora da scrivere): qui solo ciò che ADR-0018 già fissa.
         */
        readonly VariantScore: {
            readonly impact: components["schemas"]["ImpactFactors"];
            readonly level: components["schemas"]["Level"];
            /** Score */
            readonly score: number;
            /**
             * Variant
             * @enum {string}
             */
            readonly variant: "A" | "B";
        };
        /**
         * Warning_
         * @description Avviso del motore, ad es. `exception-expired`, `new-findings-only-as-all`.
         */
        readonly Warning_: {
            /** Code */
            readonly code: string;
            /** Message */
            readonly message: string;
            /** Subject */
            readonly subject?: string | null;
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    readonly getFinding: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["FindingDetail"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly patchFinding: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody: {
            readonly content: {
                readonly "application/json": components["schemas"]["SetStatus"] | components["schemas"]["SetOwner"] | components["schemas"]["CreateException"] | components["schemas"]["RevokeException"];
            };
        };
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["FindingDetail"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Lo stato attuale non permette la modifica. */
            readonly 409: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getHealth: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["Health"];
                };
            };
        };
    };
    readonly getMe: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["Me"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly listRepositories: {
        readonly parameters: {
            readonly query?: {
                readonly cursor?: string | null;
                readonly limit?: number;
            };
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["RepositoryPage"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getRepository: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["RepositorySummary"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly patchRepository: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody: {
            readonly content: {
                readonly "application/json": components["schemas"]["RepositoryPatch"];
            };
        };
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["RepositorySummary"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly listFindings: {
        readonly parameters: {
            readonly query?: {
                readonly category?: readonly components["schemas"]["Category"][] | null;
                readonly cursor?: string | null;
                readonly level?: readonly components["schemas"]["Level"][] | null;
                readonly limit?: number;
                readonly new?: boolean | null;
                /** @description Sottostringa, senza espressioni regolari. */
                readonly q?: string | null;
                readonly scan?: string | null;
                readonly sort?: components["schemas"]["SortKey"];
                readonly status?: readonly components["schemas"]["Status"][] | null;
                readonly tool?: readonly string[] | null;
            };
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["FindingPage"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getRepositoryGraph: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["Graph"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getRepositorySbom: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description CycloneDX 1.7. */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/vnd.cyclonedx+json": unknown;
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly listRepositoryScans: {
        readonly parameters: {
            readonly query?: {
                readonly cursor?: string | null;
                readonly limit?: number;
            };
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["ScanPage"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly createScan: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        readonly requestBody: {
            readonly content: {
                readonly "multipart/form-data": components["schemas"]["Body_createScan"];
            };
        };
        readonly responses: {
            /** @description Già registrata: stesso `id`, nessun effetto. */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["ScanRef"];
                };
            };
            /** @description Successful Response */
            readonly 201: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["ScanRef"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Stesso report con `sarif`, `sbom` o `graph` diversi. */
            readonly 409: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Una parte o la richiesta supera i limiti di dimensione. */
            readonly 413: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Troppe ingestioni per il repository o in corso per il tenant (`Retry-After`). */
            readonly 429: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getScan: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["ScanDetail"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getScanSarif: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path: {
                /** @description Identificativo opaco. */
                readonly id: string;
            };
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description SARIF 2.1.0 (`ADR-0011`). */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/sarif+json": unknown;
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    readonly getServiceContext: {
        readonly parameters: {
            readonly query?: never;
            readonly header?: never;
            readonly path?: never;
            readonly cookie?: never;
        };
        readonly requestBody?: never;
        readonly responses: {
            /** @description Successful Response */
            readonly 200: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/json": components["schemas"]["ServiceContextFile"];
                };
            };
            /** @description Token mancante o non valido. */
            readonly 401: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Azione non permessa dal ruolo o dall'identità. */
            readonly 403: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela). */
            readonly 404: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Richiesta non valida. */
            readonly 422: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description Errore interno, senza traccia né messaggio interno. */
            readonly 500: {
                headers: {
                    readonly [name: string]: unknown;
                };
                content: {
                    readonly "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
}
