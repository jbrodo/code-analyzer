# ADR-0005: Firma e verifica delle immagini dei plugin

- Stato: Proposto
- Data: 2026-11-08
- Decisione umana richiesta: sì (registry definitivo e custodia della chiave)
- Riferimenti: §7.1, §7.2, §15

## Contesto

§7.2 richiede la verifica cosign prima dell'esecuzione, ma non dice chi firma, con quale identità, né come verificare senza rete. Il registry in §7.1 e §12.1 è un segnaposto (`registry.example.com`). Il repository è su GitHub, ma la specifica non fissa la CI del progetto.

## Opzioni

1. **Solo digest fissato:** garantisce l'integrità, non l'origine, e §7.2 chiede la firma.
2. **Cosign keyless (OIDC):** nessuna chiave da custodire, ma la verifica dipende dalla radice di fiducia e dal log pubblici; scomodo per self-hosted e air-gapped.
3. **Cosign con chiave, pubblica distribuita con la CLI, più digest fissato.**

## Raccomandazione

Opzione 3.

- Firmiamo noi tutte le immagini built-in, costruite in CI da scanner a versione fissata.
- La chiave pubblica è inclusa nel pacchetto CLI; la privata sta in un KMS o nei segreti CI protetti.
- I manifest built-in sono dati del pacchetto CLI e contengono il digest. Il rilascio costruisce e firma le immagini, poi inserisce i digest nei manifest e infine impacchetta la CLI. Lo schema richiede `@sha256:` sul manifest impacchettato.
- Si verifica il digest e si esegue quello stesso digest, mai un tag.
- La verifica deve funzionare senza accesso al log di trasparenza. Il comando esatto si fissa sulla versione di cosign adottata.
- Firma assente o non valida: nessun container parte e la scansione termina con exit 2. Non è un fallimento parziale di plugin, perché un `health` finding nasconderebbe una manomissione.
- Sviluppo: variabile `CA_INSECURE_ALLOW_UNSIGNED=1`, mai da `.code-analyzer.yml`. Il report segna `signature: skipped` e il gate esce con 2 senza `--allow-partial`.
- La CI del progetto firma con la stessa procedura, così i test E2E coprono il percorso reale.

## Conseguenze

- `cosign` a versione fissata è un prerequisito: incluso nell'immagine CLI, da installare per l'uso sull'host.
- La rotazione della chiave richiede una nuova release della CLI; accettabile in Fase 1, da rivedere con il registry firmato di Fase 4.
- Decisioni da prendere prima del primo rilascio: host del registry, spazio dei nomi, custodia della chiave. Fino ad allora la CI può usare il registry del repository con una chiave di test.
