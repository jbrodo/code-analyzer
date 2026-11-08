# Build e firma locali con chiave di test (I-02)

ADR-0005 (emendamento dopo V-09), V-06. D-0005 e' aperta: registry e custodia
della chiave non sono decisi. Questo flusso usa **solo** un registry su
`127.0.0.1` e una chiave generata al momento, **che non protegge nulla**
(password vuota, mai nel repository, cancellata a fine prova).

## Strumenti
- `deploy/compose/registry.yaml`: `registry:2` per digest, solo loopback
  (`CA_REGISTRY_PORT`, default 5055), senza volume.
- `deploy/docker/sign-local.sh <contesto> <nome> [tag]`: build, push, digest
  letto dal registry, firma, verifica. Stampa il riferimento `...@sha256:...`.
- `deploy/docker/test-sign-local.sh`: prova i quattro casi di V-06 e pulisce.

`cosign` non viene installato: serve la v3.1.4 con SHA-256
`424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa`
(asset `cosign-linux-amd64`, `doc/verifiche/scanner-fase-1.md`). Lo script
controlla hash e versione e, se mancano, esce con 2 e un messaggio. Percorso
con `COSIGN=/percorso/cosign`.

## Comandi definitivi
```
cosign sign --yes --key k.key --tlog-upload=false --use-signing-config=false \
  [--allow-http-registry] <immagine@digest>
cosign verify --key k.pub --insecure-ignore-tlog=true \
  [--allow-http-registry] <immagine@digest>
```
`--allow-http-registry` solo per il registry locale. La verifica richiede
accesso al registry.

## `--use-signing-config=false` e' indispensabile
Provato con cosign 3.1.4 (firma con chiave):
- solo `--tlog-upload=false`: errore ("not supported with --signing-config or
  --use-signing-config"; cosign 3 usa la signing config per default).
- nessuno dei due flag, oppure solo `--use-signing-config=false`: la firma
  riesce ma cosign chiede l'accettazione dei termini del log pubblico, cioe'
  carica la firma sul log di trasparenza pubblico.
Servono quindi entrambi i flag per firmare senza log e senza servizi esterni.
Entrambi sono segnalati come deprecati da cosign 3.1.4: alla prossima serie
servira' una signing config senza `rekorTlogUrls` (`--signing-config`).

## Uso
```
docker compose -f deploy/compose/registry.yaml up -d --wait
COSIGN=/percorso/cosign deploy/docker/sign-local.sh deploy/docker/plugin-base ca-plugin-base
docker compose -f deploy/compose/registry.yaml down --volumes
```
La chiave sta in una cartella temporanea; per riusarla fra piu' firme
(`CA_KEY_DIR`) deve essere fuori dal repository (lo script rifiuta il resto).
