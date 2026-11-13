# Immagine CLI (I-01)

La CLI in un container, per le pipeline che non installano Python. Progetto e motivazioni: ADR-0004, "Emendamento per I-03: modalità immagine CLI (M-11)". Il caso di riferimento resta la CLI installata sull'host.

L'immagine contiene la CLI, `cosign` v3.1.4 e il client Docker 28.5.2. Non contiene plugin: la CLI li avvia come container fratelli attraverso il socket del daemon dell'host.

## Privilegio del socket

Montare `/var/run/docker.sock` dà al container della CLI lo stesso potere di `root` sull'host: chi controlla il socket può avviare un container privilegiato. Vale per qualunque strumento usato in questo modo.

- Il socket arriva solo alla CLI. Nessun plugin lo riceve, e la CLI non passa mai `--privileged`, `--volumes-from`, `--pid` o `--ipc` (lo controllano i test).
- La scansione si annulla se una delle directory montate contiene un socket.
- Usa l'immagine solo su runner effimeri o su macchine di cui ti fidi. I runner persistenti condivisi senza gVisor non sono ammessi (ADR-0004).
- `DOCKER_HOST` remoto non è supportato: la prova di identità fallisce e la scansione si annulla. Podman, Docker Desktop, daemon rootless o con `userns-remap` e gVisor non sono verificati.

## Build

```
docker compose -f deploy/compose/registry.yaml up -d --wait
deploy/docker/package-cli.sh <pacchetto>
deploy/docker/cli/build-cli-image.sh <pacchetto> <nome:tag> <cartella-sbom>
```

`package-cli.sh` firma le immagini dei plugin e scrive i loro digest nei manifest dei wheel; `build-cli-image.sh` installa quei wheel nell'immagine e ne controlla licenze e SBOM (`image-gate.sh`). L'immagine è quindi legata ai digest e alla chiave di quel pacchetto. Nessun push: D2-16.

## Uso

Quattro directory dell'host, distinte e non annidate. `work` e `cache` devono essere dell'utente che lancia, con permessi `0700`.

```
docker run --rm \
  --user "$(id -u):$(id -g)" --group-add "$(stat -c %g /var/run/docker.sock)" \
  --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$WORKSPACE":/ca/workspace:ro \
  -v "$WORK":/ca/work \
  -v "$CACHE":/ca/cache \
  -v "$OUTPUT":/ca/output \
  -v /percorso/fidato/cosign.pub:/ca/keys/cosign.pub:ro \
  -e CA_COSIGN_PUBLIC_KEY=/ca/keys/cosign.pub \
  -e CA_HOST_WORKSPACE="$WORKSPACE" -e CA_HOST_WORK="$WORK" -e CA_HOST_CACHE="$CACHE" \
  <nome:tag> scan
```

| Montaggio | Contenuto | Variabile con il percorso host |
| --- | --- | --- |
| `/ca/workspace` (sola lettura) | Repository da analizzare; è la directory corrente | `CA_HOST_WORKSPACE` |
| `/ca/work` | File di ingresso dei plugin, per la durata della scansione | `CA_HOST_WORK` |
| `/ca/cache` | Snapshot dei feed di vulnerabilità | `CA_HOST_CACHE` |
| `/ca/output` | Report, SARIF e SBOM | Nessuna: la scrive solo la CLI |

Regole:

- Le tre variabili sono obbligatorie per `scan` e `sbom` e valgono solo dall'ambiente. Devono indicare, sull'host, le stesse directory montate nel container: la CLI lo prova prima di avviare i plugin e, se non coincidono, esce con 2.
- Un percorso host non può essere `/`, `/run`, `/var/run`, `/proc`, `/sys` né un loro antenato, e non può contenere la directory dei dati del daemon.
- `--user` è obbligatorio: senza, l'immagine parte con l'uid dei plugin (65534) e la CLI esce con 2.
- `--output-dir`, `--output` e `--report` valgono solo sotto `/ca/output`; un percorso relativo si legge rispetto a quella directory. `gate` senza opzioni legge `/ca/output/code-analyzer.report.json`.
- La chiave pubblica viene da un percorso fidato dell'host, mai dal repository analizzato. Sostituirla cambia la radice di fiducia.
- Con un registry su loopback (quello di prova) serve `--network host`.
- `gate` e `config validate` non usano il socket: bastano i montaggi che leggono.
