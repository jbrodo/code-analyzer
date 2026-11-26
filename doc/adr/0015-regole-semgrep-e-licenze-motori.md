# ADR-0015: Regole Semgrep e licenze dei motori distribuiti

- Stato: Accettato il 2026-11-10 dall'utente: opzione 2, licenza del prodotto GPL-3.0-only, D-0015 approvata con i punti aperti di `doc/verifiche/gate-1.md` accettati come rischio residuo
- Data: 2026-11-08
- Decisione umana richiesta: sì (valutazione legale, licenza del prodotto)
- Riferimenti: §7.3, §8, §13, §16 regola 2

## Contesto

§7.3 impone di verificare la licenza di ogni motore prima di includerlo nell'immagine distribuita. Con `network: none` Semgrep non può scaricare regole dal registry e la specifica cita solo "regole custom YAML in `rules/`", che non esistono. Senza un set di regole, per JS/TS non c'è SAST: bandit copre solo Python.

Le informazioni seguenti sono quelle note all'autore e **vanno confermate sul testo della versione fissata**:

| Elemento | Licenza attesa | Nota |
| --- | --- | --- |
| syft, osv-scanner, trivy, bandit | Apache-2.0 | |
| gitleaks | MIT | |
| scancode | Apache-2.0, dati CC-BY-4.0 | Attribuzione |
| Semgrep (motore community) | LGPL-2.1 | Aggregazione in immagine da valutare |
| Regole del registry Semgrep | Licenza propria e restrittiva | Possibile limite per redistribuzione e SaaS |
| trufflehog | AGPL-3.0 | Non in Fase 1 (ADR-0012) |

Il repository non dichiara ancora una licenza del prodotto, che incide sulla distribuzione.

## Opzioni

1. Includere le regole del registry nell'immagine: copertura ampia, rischio di licenza per distribuzione e SaaS.
2. Solo regole nostre incluse, più quelle indicate dal repository in `plugins.semgrep.rules`.
3. Adottare un altro set di regole con licenza compatibile, previa valutazione.

## Raccomandazione

Opzione 2 per la Fase 1. L'opzione 3 si valuta dopo il parere legale.

- Regole in `ca_plugins/builtin/semgrep/rules/`, sotto la licenza del prodotto, mirate alle classi di problemi nelle fixture Python e JS/TS.
- Il manifest non usa mai `--config auto` né il registry.
- Per ogni immagine: file di licenze e SBOM (§15), con esito della verifica registrato nel task del plugin.

## Conseguenze

- Copertura SAST iniziale limitata: si ottiene "i problemi noti delle fixture" del Gate 1, non un'analisi ampia sui repository pilota.
- Un task del piano deve produrre un primo set di regole e uno deve registrare la verifica legale; la pubblicazione delle immagini dipende da quest'ultimo.
- Il proprietario della verifica è una persona, non un agente.

## Emendamento per A-16 (2026-11-18): i motori e i componenti di Fase 2 (D2-14)

Motivo: la Fase 2 aggiunge motori e componenti alle immagini; la regola di §16 e di questo ADR (verificare licenza e manutenzione prima di includerli, con file di licenza e SBOM per immagine) vale per ognuno.

- **Decisioni prese.** hadolint è approvato il 2026-11-17 per uso interno e per il registry locale. Non è un'approvazione alla distribuzione: la sua licenza copyleft forte obbliga, a chi distribuisce l'immagine, ad accompagnarla con il testo della licenza e l'offerta della sorgente. Quella decisione resta di I-07 e non è un parere legale. Gli altri motori e componenti nuovi (checkov, il parser tree-sitter di `ca-graph`, eslint e i suoi plugin, il client S3, OpenTelemetry, le dipendenze del server e della SPA) si valutano sugli SBOM di rilascio.
- **Dove sta la verifica.** Ogni immagine ha i suoi file di licenza e il suo SBOM, controllati da `deploy/docker/image-gate.sh` (convenzione in `deploy/docker/LICENSES-SBOM.md`); ogni dipendenza Python o JavaScript nuova ha la sua nota di verifica nel task e nell'ADR che la introduce (per esempio ADR-0030).
- **Nessuna pubblicazione.** Finché D2-16 e la decisione del 2026-11-10 lo vietano, nessuna immagine con componenti nuovi lascia il registry locale (I-04, I-07).
