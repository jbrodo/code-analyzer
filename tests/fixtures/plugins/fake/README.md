# Plugin finto (T-02)

Prova il runner reale (R-02, R-03) senza scanner. Non e' un plugin distribuito: il manifest
`plugin.yaml` (JSON, sottoinsieme di YAML come i manifest di `ca_plugins`) sta fuori dai dati di
`ca_plugins` e l'immagine e' solo locale (`localhost/ca-fake-plugin:1.0.0`), senza registry
(D-0005 aperta) e senza digest.

Costruzione: `docker build -t localhost/ca-fake-plugin:1.0.0 tests/fixtures/plugins/fake`
(base I-01 con digest fissato, utente `65534:65534`).

## Scelta del comportamento

Solo da `/inputs/config.json`, montato dal runner (`inputs.config: optional`):
`{"behavior": "<nome>"}`. Senza file: `success`. Nome sconosciuto: exit 64. Nessun segreto, nessuna
rete, nessuna variabile d'ambiente. A fine esecuzione stampa su stdout una riga JSON (uid, gid,
`HOME`, nomi delle variabili d'ambiente, esiti dei tentativi). `env_keys` include quelle
dell'immagine (`PATH`, `GPG_KEY`, ...): la prova "nessuna variabile dell'host" deve confrontarle
con quelle dell'immagine.

| Comportamento | Cosa fa | Exit atteso con il profilo |
|---|---|---|
| `success` | SARIF valido in `/out/results.sarif` | 0 |
| `exit-nonzero` | nessun output | 3 |
| `invalid-sarif` | SARIF troncato | 0 |
| `oversize` | SARIF valido di oltre 2 MiB (limite del manifest: 1 MiB) | 0 |
| `write-tmp` | scrive e cancella un file in `/tmp`; SARIF valido | 0 |
| `write-out` | scrive anche `/out/extra.txt` (regolare); SARIF valido | 0 |
| `symlink-out` | `/out/results.sarif` e' un symlink a `/etc/passwd` | 0 |
| `network` | connessione a 192.0.2.1:9 (RFC 5737); `ok` = violazione | 0 bloccata, 4 violazione |
| `write-workspace` | scrive in `/workspace` | 0 bloccata, 4 violazione |
| `write-rootfs` | scrive nel root file system | 0 bloccata, 4 violazione |
| `exec-tmp` | esegue un binario copiato in `/tmp` (noexec) | 0 bloccata, 4 violazione |
| `timeout` | dorme un'ora: il runner deve uccidere il container | (ucciso) |
| `report` | SARIF valido e `/out/report.json` con quanto il processo vede (uid, gruppi, ambiente, capability, seccomp, montaggi, limiti cgroup, lettura di un file del workspace) | 0 |
| `fill-out` | scrive `mib` MiB (tetto 512) in `/out/fill.bin`; con `hold` poi dorme (T-03, riempimento) | 0 (ucciso con `hold`) |
| `subdir-out` | crea `/out/<name>/f` e imposta `mode` (default 0) sulla sottodirectory (T-03) | 0 |
| `fifo-out` | `/out/results.sarif` e' una FIFO | 0 |

Parametri opzionali in `/inputs/config.json`, oltre a `behavior`: `report` (bool: scrive anche
`/out/report.json`, cambia l'elenco dei file di `/out`), `read` (nome di un file al primo livello
di `/workspace` da leggere nel rapporto), `mib` e `hold` (`fill-out`), `name` e `mode` (`subdir-out`).

## Test

`pytest tests/fixtures/plugins/fake` esegue le prove senza Docker. Le prove sull'immagine si
attivano con `CA_TEST_DOCKER=1` (costruiscono `localhost/ca-fake-plugin:test` e la rimuovono).
