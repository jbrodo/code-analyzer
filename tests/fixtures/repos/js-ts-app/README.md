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
| `third_party/copyleft-helper.js` | scancode (licenza per file) |

## Problemi SAST non ancora attesi

I problemi in `src/server.ts` sono reali, ma il piano li assegna **solo** alle regole Semgrep del
progetto (ADR-0015, task P-09), che non esistono ancora; bandit non legge JS/TS. Finche' le regole
non ci sono, nessun scanner reale li rileva, quindi `expected-findings.yaml` non li elenca.
Quando P-09 produce le regole, ogni riga qui sotto diventa una voce attesa con il suo `rule_id`.

| Riga | Problema | Classe |
| --- | --- | --- |
| 11-13 | `child_process.exec` con parametro della richiesta | iniezione di comandi (CWE-78) |
| 17 | `eval` su dato della richiesta | esecuzione di codice (CWE-95) |
| 22 | query SQL costruita per concatenazione | iniezione SQL (CWE-89) |
| 28 | parametro della richiesta restituito senza escape | XSS riflesso (CWE-79) |
| 32 | `crypto.createHash("md5")` | hash debole (CWE-328) |

La policy di licenze di prova e' `../license-policy.yml` (fuori dalla fixture, vedi il commento). Nessun segreto qui.
