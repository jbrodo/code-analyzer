# ADR-0012: Rilevamento dei segreti in Fase 1

- Stato: Proposto
- Data: 2026-11-08
- Decisione umana richiesta: sì (livello dei segreti non verificati; verifica online futura)
- Riferimenti: §3, §6.3, §7.2, §7.3, §13, §15; lacuna 7

## Contesto

§6.3 rende Critico un "segreto valido esposto", ma stabilire la validità significa provare il segreto contro il servizio emittente, e i plugin hanno `network: none`. `trufflehog` è in §3 ma non in §7.3 né in Fase 1. A quanto noto all'autore è AGPL-3.0, condizione da confermare (ADR-0015).

## Opzioni

1. Solo gitleaks, nessuna verifica, nessun segreto dichiarato "valido".
2. trufflehog con verifica online in Fase 1: mette insieme sorgenti, segreto e rete, viola §7.2 e l'invariante di ADR-0006 e contatta servizi terzi con credenziali reali.
3. gitleaks più un plugin di verifica separato con uscita limitata: la strada corretta se la verifica servirà, ma è prematura.

## Raccomandazione

Opzione 1.

- `evidence.validity = "unverified"` su ogni segreto. L'override "segreto valido" di §6.3 non si applica in Fase 1.
- Livello `alto` per tutti i segreti: blocca con il gate predefinito, ma non afferma una validità non provata. In alternativa `critico`, più prudente ma più rumoroso.
- Il valore non lascia mai il container: l'adattatore lavora sull'output grezzo in un percorso interno, calcola l'hash per il fingerprint (ADR-0008) e scrive in `/out` un SARIF oscurato. La CLI rifiuta un SARIF gitleaks che contenga il valore in `snippet` o `message`.
- Storia git: in Fase 1 tutte le scansioni sono complete, quindi si analizza tutta la storia disponibile. Con clone superficiale il report segnala la copertura ridotta.

Se in seguito servirà la verifica: plugin con capability `enrich`, esplicitamente abilitato, che riceve solo il segreto e il tipo di servizio, senza workspace. Va deciso con un nuovo ADR in Fase 2 o oltre.

## Conseguenze

- Nessun finding viene classificato per validità: anche i token già revocati bloccano, finché non c'è un'eccezione o una pulizia.
- Le fixture devono usare segreti finti riconoscibili, per non attivare la protezione dei push né creare rischi reali.
- Una sentinella di test deve risultare assente da report, SARIF, stdout e log.
