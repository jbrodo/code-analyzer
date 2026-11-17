# Inviare i risultati al server (facoltativo)

Il server raccoglie le scansioni di più repository e le mostra con la loro storia. La CLI funziona
da sola anche senza: `upload` è un passo in più, da aggiungere dopo `scan`.

```
code-analyzer scan . --output-dir out
code-analyzer sbom --output out/code-analyzer.sbom.json   # facoltativo
code-analyzer upload --server https://analyzer.example.org --report out/code-analyzer.report.json
```

Insieme al report partono, se stanno nella stessa cartella, `code-analyzer.sarif`,
`code-analyzer.sbom.json` e `code-analyzer.graph.json`.

## Identità

Non serve nessun segreto a lunga durata: il server si fida del token OIDC che il provider della CI
rilascia alla singola esecuzione.

- **GitHub Actions:** abilita il permesso `id-token: write`. `upload` chiede il token da solo; con
  `--audience` si indica l'audience che il server si aspetta.
- **GitLab:** dichiara un `id_tokens` e passalo nella variabile `CA_OIDC_TOKEN`.

Il token non è mai un'opzione della riga di comando e non compare nei messaggi.

## Esito

- `0`: inviata, oppure già presente (un secondo invio dello stesso report non cambia nulla).
- `2`: errore. Se il server rifiuta, si stampa lo stato e il codice del problema (per esempio
  `repository-mismatch`), mai il testo ricevuto.

Il server accetta solo scansioni del repository a cui appartiene il token: il nome della cartella
analizzata deve coincidere con quello del repository, quindi si lancia la scansione dalla radice.
