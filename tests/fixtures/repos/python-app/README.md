# python-app (fixture F-02)

Repository di prova con problemi noti. **Non va installato, eseguito né importato**: ogni
dipendenza in `poetry.lock` ha CVE pubbliche, il codice in `app/` e' insicuro di proposito.

I problemi attesi sono in `expected-findings.yaml` (formato: `../../expected-findings.schema.json`).
Ogni voce e' stata osservata eseguendo lo scanner indicato direttamente sulla fixture; le versioni
e i comandi usati sono nel campo `note` o nel report del task F-02.

| Percorso | Per quale scanner |
| --- | --- |
| `poetry.lock` | osv-scanner, trivy (CVE note) |
| `app/*.py` | bandit (regole diverse da B105, B106, B107) e semgrep (regole del progetto, P-09) |
| `Dockerfile`, `infra/main.tf` | trivy (misconfiguration) |
| `third_party/copyleft_helper.py` | scancode (licenza per file) |
| `vendor/legacycopyleft-1.0.0.dist-info/` | syft (licenza dichiarata di una dipendenza) |

La policy di licenze di prova e' `../license-policy.yml` (nessun elenco predefinito nel codice,
ADR-0013). Nessun segreto qui: la storia con segreti finti e' la fixture `secrets-history`.
