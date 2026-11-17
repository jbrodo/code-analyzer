# graph-python (fixture F-01 della Fase 2)

Pacchetto Python `shop` con smell architetturali noti e un caso negativo per ciascuno. **Non va
eseguito né importato**: i moduli si importano a vicenda di proposito e senza altro contenuto.

Gli attesi sono in `expected-graph.yaml` (formato: `../../expected-graph.schema.json`). Sono scritti
dal progetto qui sotto, non copiati dall'output dell'estrattore: provano gli archi di G-02, le
metriche di G-04 e gli smell di G-05, G-06 e G-07. Il file `tests/checks.py` è un modulo di test
(non si chiama `test_*.py` perché pytest non lo raccolga): importa due moduli ma non deve entrare
in metriche né smell (ADR-0020).

| Caso | Dove | Atteso |
| --- | --- | --- |
| Ciclo di moduli | `shop/billing/a.py` → `b` → `c` → `a` | un ciclo di 3 moduli |
| Ciclo di pacchetti | `shop/billing` ↔ `shop/ledger` (`a` → `ledger/x`, `ledger/y` → `b`) | un ciclo di 2 pacchetti; `ledger/y.py` non è nel ciclo di moduli |
| Negativo dei cicli | `shop/catalog/item.py` → `price` → `tax` | nessun ciclo |
| Hub | `shop/core/hub.py`: 4 moduli lo importano (`hubusers/u*`), lui ne importa 4 (`hubdeps/d*`) | hub, con soglia minima di grado 6 |
| Negativi dell'hub | `shop/util/helpers.py` (5 entranti, 0 uscenti), `shop/main.py` (0 entranti, 4 uscenti), `shop/billing/c.py` (grado 2 bilanciato) | non sono hub |
| Dipendenza instabile | `shop/stable` (Ca 4, Ce 1, I 0,2) → `shop/volatile` (Ca 1, Ce 4, I 0,8) | una dipendenza instabile, grado 1,0 |
| Negativi | `shop/svc*` → `shop/stable` (verso un pacchetto più stabile), `shop/volatile` → `shop/ext*` | nessuna dipendenza instabile |

Il progetto: moduli logici `pacchetto.modulo`, archi `(origine, destinazione)`, e per ogni arco una
riga `from shop.<pacchetto> import <modulo>`. Gli archi interni sono 33.
