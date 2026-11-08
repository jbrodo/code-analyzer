# Code Analyzer

Code Analyzer è un progetto in fase di progettazione per analizzare repository e presentare i problemi in un elenco unico, ordinato per impatto e accompagnato da indicazioni per la correzione.

## Cosa prevede

- Analisi di qualità, architettura, test, sicurezza, dipendenze, licenze e configurazioni IaC.
- Orchestrazione di scanner open source e normalizzazione dei risultati in formati standard, tra cui SARIF e CycloneDX.
- MVP rivolto a repository Python e JavaScript/TypeScript.
- Integrazione prevista con CLI, API, GitHub Actions e GitLab CI.
- Agenti AI per spiegare e proporre correzioni: i finding restano basati su rilevamenti deterministici e ogni modifica richiede revisione umana.

## Architettura prevista

Monorepo con componenti Python (FastAPI, Temporal e PostgreSQL), interfaccia React/TypeScript e scanner eseguiti in sandbox. Il progetto è pensato per supportare sia installazioni self-hosted sia SaaS.

## Stato

Il repository contiene attualmente la specifica e il piano di implementazione; il software e i comandi descritti non sono ancora disponibili.

## Documentazione

Per architettura, stack, modelli dati, pipeline e roadmap, consulta la [guida di implementazione](doc/PROJECT.md).
