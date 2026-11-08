# ADR-0013: Valutazione della policy di licenze

- Stato: Accettato
- Data: 2026-11-08
- Decisione umana richiesta: no (D-0013 decisa il 2026-11-08)
- Riferimenti: §4.2, §6.1, §6.3, §7.3, §8, §13, §18

## Contesto

§8 definisce `forbidden`, `require_approval` e `distributed_product`, ma non come si valutano. Restavano da definire il confronto con espressioni SPDX, le varianti `-or-later`, la valutazione delle licenze dichiarate e rilevate, le licenze ignote e il caso `forbidden` con `distributed_product: false`. D-0013 ha fissato gli elenchi, `distributed_product: true` e il livello alto per l'approvazione; questo ADR documenta anche le regole operative adottate.

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

### Decisione D-0013 (2026-11-08)

Per la policy prudenziale del prodotto:

```yaml
licenses:
  forbidden:
    - AGPL-3.0-only
    - AGPL-3.0-or-later
    - SSPL-1.0
  require_approval:
    - GPL-2.0-only
    - GPL-2.0-or-later
    - GPL-3.0-only
    - GPL-3.0-or-later
    - LGPL-2.1-only
    - LGPL-2.1-or-later
    - LGPL-3.0-only
    - LGPL-3.0-or-later
  distributed_product: true
```

Le voci sono identificatori SPDX esatti. Licenze non elencate, incluse MIT, Apache-2.0 e BSD, non richiedono approvazione in questa policy. È una regola operativa di triage, non un parere legale: il referente legale deve verificarla prima della distribuzione (D-0015).

| Caso | Livello |
| --- | --- |
| `forbidden` e `distributed_product: true` | critico (override §6.3) |
| `forbidden` e `distributed_product: false` | alto |
| `require_approval` | alto (`medio` in alternativa) |
| Licenza ignota | medio |

"Obbligo di attribuzione mancante" (§6.1) non è rilevabile in Fase 1 ed è rinviato.

## Conseguenze

- Le fixture usano una policy di test separata; gli elenchi approvati non sono predefiniti nel codice e vanno applicati nella configurazione del progetto.
- La scelta `alto` per l'approvazione rende la policy vincolante e richiede un'eccezione per ogni dipendenza approvata; G = 0,6 in §6.1 è coerente con un tetto di 60, cioè Alto.
