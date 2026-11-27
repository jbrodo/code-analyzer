# Code Analyzer

Code Analyzer è un progetto in fase di sviluppo per analizzare repository e presentare i problemi in un elenco unico, ordinato per impatto e accompagnato da indicazioni per la correzione.

## Cosa prevede

- Analisi di qualità, architettura, test, sicurezza, dipendenze, licenze e configurazioni IaC.
- Orchestrazione di scanner open source e normalizzazione dei risultati in formati standard, tra cui SARIF e CycloneDX.
- MVP rivolto a repository Python e JavaScript/TypeScript.
- Integrazione prevista con CLI, API, GitHub Actions e GitLab CI.
- Agenti AI per spiegare e proporre correzioni: i finding restano basati su rilevamenti deterministici e ogni modifica richiede revisione umana.

## Architettura prevista

Monorepo con componenti Python (FastAPI, Temporal e PostgreSQL), interfaccia React/TypeScript e scanner eseguiti in sandbox. Il progetto è pensato per supportare sia installazioni self-hosted sia SaaS.

## Stato

Il progetto è in Fase 1 (MVP per Python e JavaScript/TypeScript) e non ha ancora un rilascio. Sono implementati il nucleo, il runner dei plugin in sandbox, i sette scanner e i comandi `scan`, `sbom`, `gate` e `config validate`. API, dashboard, agenti AI e integrazioni CI sono previsti nelle fasi successive.

Le immagini dei plugin non sono ancora pubblicate. Per provare il prodotto, `deploy/docker/package-cli.sh` costruisce e firma le immagini su un registry locale e produce il pacchetto installabile; `tests/e2e/scan_local.py` fa lo stesso per una singola scansione. Servono Docker, `cosign`, `syft` e, senza rete, uno snapshot dei feed.

Comandi, configurazione e limiti sono nella [guida della CLI](doc/utente/README.md); l'avanzamento è in [`doc/PROJECT.md` §13](doc/PROJECT.md).

## Hook pre-commit

Per abilitare i controlli automatici prima di ogni commit:

```bash
uv run pre-commit install
```

Gli hook validano JSON, YAML e TOML, rilevano chiavi private e marker di conflitto,
controllano spazi finali, formattazione, Ruff, ty e la coerenza dei lock `uv` e Bun.
Ruff e ty usano le versioni bloccate in `uv.lock`. Per eseguire i controlli su tutto
il repository:

```bash
uv run pre-commit run --all-files
```

La dashboard in `web/` usa Node 24 e Bun 1.4.4:

```bash
bun install --cwd web --frozen-lockfile
bun run --cwd web lint
bun run --cwd web test
```

## Licenza

Il codice del progetto è distribuito con la licenza di Apache, versione 2.0, **con la condizione aggiuntiva Commons Clause** ([LICENSE](LICENSE), ADR-0032). Il sorgente è disponibile, ma **non è software open source** nel senso comune del termine, perché la vendita è limitata.

In breve (fa fede il testo di [LICENSE](LICENSE)):

- chiunque, aziende comprese, può usare, modificare e ridistribuire gratuitamente il programma;
- chi lo riceve con questa licenza non può **venderlo**: nel senso della clausola, fornire a terzi dietro compenso un prodotto o un servizio il cui valore deriva del tutto o in gran parte dal programma, compresi hosting, consulenza e supporto a pagamento;
- il titolare dei diritti, Riccardo Roveda, può venderlo e concedere licenze commerciali.

Le versioni pubblicate prima di questo cambio restano disponibili, a chi le ha ottenute, con la licenza con cui erano pubblicate. I componenti di terze parti, comprese le immagini dei plugin e le cartelle di strumenti e schemi di terzi nel repository, restano sotto le proprie licenze.

## Documentazione

Per architettura, stack, modelli dati, pipeline e roadmap, consulta la [guida di implementazione](doc/PROJECT.md).

## Sviluppo guidato dalle specifiche (Spec Kit)

Il repository integra [GitHub Spec Kit](https://speckit.org/) per definire e verificare le
funzionalità prima dell'implementazione. Per installare la CLI in un ambiente isolato:

```bash
uv tool install specify-cli==1.3.2
```

In GitHub Copilot, esegui le skill nella chat, una alla volta:

1. `/speckit-specify` — crea la specifica della funzionalità.
2. `/speckit-clarify` — chiarisce i requisiti ambigui, se necessario.
3. `/speckit-plan` — definisce l'approccio tecnico.
4. `/speckit-checklist` — verifica la qualità dei requisiti, se utile.
5. `/speckit-tasks` — genera i task ordinati.
6. `/speckit-analyze` — controlla coerenza e lacune prima di implementare.
7. `/speckit-implement` — realizza i task dopo aver revisionato gli artefatti.
8. `/speckit-converge` — confronta il risultato con specifica, piano e task.

La costituzione del progetto è in `.specify/memory/constitution.md`; template, script e
skill Copilot sono in `.specify/` e `.github/skills/`. Gli artefatti delle singole
funzionalità vengono creati in `specs/`. Spec Kit è uno strumento di sviluppo e non una
dipendenza runtime di `ca-cli`.
