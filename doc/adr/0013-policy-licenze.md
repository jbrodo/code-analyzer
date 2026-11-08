# ADR-0013: Valutazione della policy di licenze

- Stato: Proposto
- Data: 2026-11-08
- Decisione umana richiesta: sì (elenco licenze, §18; livelli)
- Riferimenti: §4.2, §6.1, §6.3, §7.3, §8, §13, §18

## Contesto

§8 definisce `forbidden`, `require_approval` e `distributed_product`, ma non come si valutano. Sono aperti: confronto con espressioni SPDX, varianti `-or-later` (l'esempio vieta `AGPL-3.0-only`, e `AGPL-3.0-or-later` passerebbe), licenza dichiarata contro rilevata, licenze ignote, caso `forbidden` con `distributed_product: false`. L'elenco delle licenze è una decisione aperta di §18.

## Opzioni

Per le licenze composte:

1. Corrispondenza esatta di stringa: semplice ma elusa da qualsiasi espressione composta.
2. Valutazione dell'espressione SPDX secondo la semantica di `AND` e `OR`.

Per `require_approval`:

1. `alto`: blocca finché non esiste un'eccezione approvata.
2. `medio`: solo avviso con il gate predefinito.

## Raccomandazione

Opzione 2 per le espressioni, e `alto` per `require_approval`.

- Motore puro in `ca_core/policy/licenses.py`, eseguito dopo la normalizzazione; `tool = "ca-core"`, `rule_id = "ca.license"`.
- `AND`: viola se almeno un termine viola. `OR`: viola solo se tutti i termini violano.
- Le voci della policy sono identificatori SPDX esatti, senza equivalenze implicite: `-or-later` va elencata esplicitamente. `config validate` avvisa quando è elencata la sola variante `-only`.
- Entrambe le fonti si valutano: dichiarata da SBOM e rilevata da scancode. Finding su pacchetto se c'è il purl, altrimenti su file.
- Licenza mancante, `NOASSERTION` o `LicenseRef-*`: finding `medio` "da verificare", senza dichiarare una violazione.
- `licenses` assente: la policy non viene valutata e il report lo dichiara. Nessun elenco predefinito nel codice (§18).
- L'approvazione passa per `exceptions` (ADR-0014).

| Caso | Livello |
| --- | --- |
| `forbidden` e `distributed_product: true` | critico (override §6.3) |
| `forbidden` e `distributed_product: false` | alto |
| `require_approval` | alto (`medio` in alternativa) |
| Licenza ignota | medio |

"Obbligo di attribuzione mancante" (§6.1) non è rilevabile in Fase 1 ed è rinviato.

## Conseguenze

- Fino alla decisione su §18 le fixture usano una policy di test e nessun progetto reale ha valori predefiniti.
- La scelta `alto` per l'approvazione rende la policy vincolante e richiede un'eccezione per ogni dipendenza approvata; G = 0,6 in §6.1 è coerente con un tetto di 60, cioè Alto.
