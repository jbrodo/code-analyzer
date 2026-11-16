# quality-python (fixture F-02 della Fase 2)

Repository di prova con problemi di qualita' noti per ruff. **Non va eseguito ne' importato.**
Il codice non ha problemi di sicurezza di proposito: serve solo ai finding `quality`.

I problemi attesi sono in `expected-findings.yaml`; il comando e la versione con cui sono stati
osservati sono in testa a quel file.

| Percorso | Cosa contiene |
| --- | --- |
| `app/report.py` | Import e variabile non usati, nome non definito, valore predefinito mutabile, e una funzione che supera con margine le soglie di complessita', argomenti, return e rami |
| `app/clean.py` | Nessun problema: caso negativo |

La cartella e' esclusa da `ruff` in `pyproject.toml`: i problemi sono voluti.
