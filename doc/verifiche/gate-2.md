# Gate 2 — Verifica

Condizioni e task in `doc/plan/fase-2.md` sezione 2. Questo file raccoglie protocollo, misure ed esito. Il materiale di valutazione (finding, campioni, ordinamenti) resta fuori dal repository: qui entrano solo conteggi e misure.

## Protocollo (X-01)

Registrato il 2026-11-13 su indicazione dell'utente (D2-03, decisa il 2026-11-10).

### Scostamento rispetto a §13

§13 chiede un ordinamento "validato dai team". Non ci sono team da coinvolgere: il validatore è uno solo, l'utente (Riccardo Roveda), sui propri repository. Ne segue che:

- la variante predefinita che esce dal gate è provvisoria e va rivalidata con utenti reali;
- l'accordo misurato è quello di una persona, che è anche l'autore del prodotto e conosce le due varianti. L'ordinamento alla cieca riduce questo effetto ma non lo elimina;
- il Gate 2 si chiude dichiarando questo scostamento in X-08.

Il metodo di Martini et al. (ECSA 2018) citato da §13 non è ancora trascritto in un ADR: lo fanno A-06 e A-08, e l'utente conferma che la trascrizione è fedele. Fino ad allora questo protocollo vale come proposta operativa e non come applicazione verificata di quel metodo.

### Repository

| Repository | Commit | Data del commit | File versionati | Python | JS/TS |
| --- | --- | --- | --- | --- | --- |
| `orario-scuola` | `8b9cee9cc54d456f987f2aaf080d031e6fc62c20` | 2026-11-09 | 1.103 | 170 | 241 |
| `birds-cataloger` | `cb9227f2813b0843a5c0d4d2829c4da7a2d6ae53` | 2025-11-22 | 165 | 36 | 25 |

Entrambi sono dell'utente e si trattano come riservati. D2-03 ne ammette 2 o 3: il terzo è facoltativo e ancora da indicare. Se si aggiunge, entra in questa tabella con il commit fissato prima di X-02.

Le scansioni si eseguono su un clone pulito del commit indicato, sulla macchina di riferimento, con le immagini del registry locale (D2-16). I 3 pilota pubblici della Fase 1 servono a G2.a e G2.d, non a G2.b.

### Campione

- 30 finding per repository. Se i finding ammissibili sono meno di 30 si prendono tutti e si registra il numero.
- Ammissibili: un finding per fingerprint, stato aperto. Sono esclusi quelli coperti da un'eccezione e i finding di tipo `health`.
- Stratificato per categoria e livello provvisorio (ADR-0009): quote proporzionali, con almeno un finding per ogni strato non vuoto.
- Estrazione con seme registrato in X-03.

### Valutazione

- L'utente riceve il campione in ordine casuale, senza punteggio, fattori, livello, severità dello strumento né variante. Vede regola, messaggio, categoria, file e riga, e può aprire il codice.
- Ordina i finding dal più urgente da correggere al meno urgente. Sono ammessi i pari merito.
- L'ordinamento si consegna prima di vedere qualunque punteggio e non si modifica dopo.

### Metrica e soglia

Per ogni repository e per ciascuna variante, A e B:

- tau-b di Kendall tra l'ordinamento dell'utente e quello per punteggio decrescente della variante. Il tau-b tiene conto dei pari merito su entrambi i lati;
- sovrapposizione sui primi 10: quanti dei primi 10 dell'utente sono nei primi 10 della variante. I pari merito al confine si risolvono con l'ordine del fingerprint, su entrambi i lati.

Soglia per repository: la variante migliore ha tau-b ≥ 0,5 e almeno 6 dei primi 10 in comune. G2.b è superata se la soglia è raggiunta su tutti i repository della tabella; con campioni sotto i 30 finding la sovrapposizione si valuta sul terzo superiore del campione, arrotondato per eccesso, con la stessa proporzione (60%).

Si registra anche il risultato dei livelli provvisori, come termine di confronto: una variante che non li supera non giustifica il cambio di livelli.

### Riservatezza

In questo file: numero di finding per categoria e livello, dimensione dei campioni, seme, valori di tau-b e di sovrapposizione, durate. Non entrano percorsi, messaggi, regole per singolo finding né frammenti di codice dei due repository.
