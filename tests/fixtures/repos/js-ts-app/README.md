# js-ts-app (fixture F-03)

Repository di prova con problemi noti. **Non va installato, eseguito né compilato**: ogni
dipendenza in `package-lock.json` ha CVE pubbliche (il lockfile non e' mai stato risolto da `npm`)
e il codice in `src/` e' insicuro di proposito.

I problemi attesi sono in `expected-findings.yaml` (formato: `../../expected-findings.schema.json`).
Ogni voce e' stata osservata eseguendo lo scanner indicato direttamente sulla fixture.

| Percorso | Per quale scanner |
| --- | --- |
| `package-lock.json` | osv-scanner, trivy (CVE note) e syft (licenza dichiarata) |
| `Dockerfile`, `k8s/deployment.yaml` | trivy (misconfiguration) |
| `src/server.ts` | semgrep (regole del progetto) |
| `third_party/copyleft-helper.js` | scancode (licenza per file) |

## Problemi SAST (regole Semgrep del progetto)

I problemi in `src/server.ts` sono rilevati **solo** dalle regole Semgrep del progetto (ADR-0015,
task P-09, `packages/ca-plugins/src/ca_plugins/builtin/semgrep/rules/javascript.yaml`); bandit non
legge JS/TS. Ogni riga e' una voce attesa in `expected-findings.yaml`, osservata con semgrep 1.184.0.
Semgrep ignora le directory `tests/`: per rieseguirlo copiare la fixture fuori da `tests/`.

| Riga | Problema | Regola |
| --- | --- | --- |
| 11-13 | `child_process.exec` con parametro della richiesta (CWE-78) | `ca-js-command-injection` |
| 17 | `eval` su dato della richiesta (CWE-95) | `ca-js-eval-dynamic` |
| 22 | query SQL costruita per concatenazione (CWE-89) | `ca-js-sql-injection` |
| 28 | parametro della richiesta restituito senza escape, XSS riflesso (CWE-79) | `ca-js-reflected-xss` |
| 32 | `crypto.createHash("md5")` (CWE-328) | `ca-js-weak-hash` |

La policy di licenze di prova e' `../license-policy.yml` (fuori dalla fixture, vedi il commento). Nessun segreto qui.
