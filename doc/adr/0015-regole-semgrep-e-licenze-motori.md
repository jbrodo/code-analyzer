# ADR-0015: Regole Semgrep e licenze dei motori distribuiti

- Stato: Proposto
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
