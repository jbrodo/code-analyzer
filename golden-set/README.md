# Golden set del triage

Giudizi umani su finding SAST di repository pubblici in Python, per addestrare, calibrare e valutare il motore decisionale (Fase 3). Regole e Gate 3: `doc/adr/0034-golden-set-e-gate-3.md`.

**Qui non c'è codice.** Ci sono solo riferimenti (repository, commit, percorso, riga, fingerprint) e risposte. Messaggi dei tool, note, avanzamento e copie del codice stanno in `~/golden-material/`, fuori dal repository.

| File | Contenuto |
| --- | --- |
| `corpus.json` | I 30 repository pubblici con tag e commit |
| `sampling.json` | Tetto, regole escluse, percorsi di terzi |
| `eval/baselines.py` | Le basi di confronto di G3.c, costruite con le sole etichette di addestramento (ADR-0036) |
| `eval/metrics.py`, `eval/gate3.json` | Le misure del Gate 3 e le sue soglie. Sono funzioni: il comando che le applica a un motore vero arriva con DE-04 |
| `<insieme>.sample.json` | Le voci da annotare, nell'ordine in cui si annotano (`schemas/golden-sample.schema.json`) |
| `<insieme>.labels.<annotatore>.g<giro>.json` | Le risposte consegnate (`schemas/golden-labels.schema.json`) |

## Annotare

Le definizioni delle tre risposte sono quelle di ADR-0034. Si decide da soli: non si chiede a un modello o a un assistente, nemmeno per capire un finding.

```
uv run python scripts/golden/annotate.py --set pilota --fetch
```

Si apre l'indirizzo stampato, che contiene il segreto di accesso. `--fetch` scarica da GitHub le copie che mancano, senza storia; il codice scaricato si legge soltanto, non va eseguito. L'avanzamento si salva da sé e si riprende rilanciando il comando. «Consegna» scrive il file delle risposte in questa cartella, una volta sola.

Per la riannotazione di controllo si usa `--round 2`: non mostra le risposte del primo giro. Non vanno aperte in altro modo prima di aver finito.

## Estrarre un insieme

Servono i report delle scansioni dei repository di `corpus.json`, ai commit indicati:

```
uv run python scripts/golden/sample.py --reports CARTELLA --set calibrazione --size 100 \
    --seed calibrazione-1 --exclude golden-set/pilota.sample.json
```

Il comando non sovrascrive un campione esistente.
Il secondo pilota (`pilota-2`, ADR-0034) è stato estratto con lo stesso seme del suo nome, escluso il primo; si annota con `--set pilota-2`. A parità di report, filtri, seme ed esclusioni il risultato è identico. Il pilota è stato estratto con `--set pilota --size 30 --seed pilota-1`.
