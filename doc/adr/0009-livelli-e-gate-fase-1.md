# ADR-0009: Livelli e gate in Fase 1 senza scoring né baseline

- Stato: Accettato: il 2026-11-08 la parte sul Gate 1 (scansione completa < 10 minuti, PR incrementale al Gate 2), il 2026-11-09 i livelli provvisori. La Variante A resta in Fase 2
- Data: 2026-11-08
- Decisione umana richiesta: sì (ambito di Fase 1, severità, significato del Gate 1)
- Riferimenti: §5, §6, §8, §9.1, §13

## Contesto

Incoerenza non elencata. §13 mette il comando `gate` in Fase 1, ma scoring, livelli, baseline e finding nuovi in Fase 2. Il gate di §8 lavora proprio su livelli (`block_on: [critico, alto]`) e su `new-findings-only`. Inoltre §5 lega la "scansione PR incrementale < 10 minuti" al Gate 1, mentre §13 parla di "scansione < 10 minuti" e la modalità PR richiede la baseline di Fase 2.

## Opzioni

1. Anticipare la Variante A: richiede EPSS, KEV e raggiungibilità di Fase 2.
2. **Livelli provvisori** dalla severità dei tool e dalle policy, senza `score`.
3. Gate solo su licenze e segreti: lascia fuori CVE e SAST.
4. Spostare `gate` in Fase 2: contraddice §13.

## Raccomandazione

Opzione 2. `impact` e `score` restano `null`; si aggiunge a `Finding` il campo `level_source` (`tool_severity | policy | default`, in Fase 2 anche `score | override`).

| Categoria | Regola |
| --- | --- |
| `dependency` | CVSS più recente disponibile: `[9,10]` critico, `[7,9)` alto, `[4,7)` medio, `[0,4)` basso. Senza CVSS: alto (`default`) |
| `sast`, `iac` | Severità del tool: `critical` critico; `high` o SARIF `error` alto; `medium` o `warning` medio; `low` o `note` basso. Senza severità: medio |
| `license` | ADR-0013 |
| `secret` | ADR-0012: alto |
| `health` | Medio |

Ordinamento dell'elenco in Fase 1: livello, categoria, fingerprint, in modo deterministico.

Gate:

- Il mode accetta `all | new-findings-only`, predefinito `all`. In Fase 1 `new-findings-only` viene valutato come `all`, con avviso e `effective_mode: all` nel report: la scelta è più severa, quindi sicura. Niente `--pr` né `--base`.
- Precedenza: `--fail-on` CLI, poi `gate.block_on` registrato nel report, poi `critico,alto`.
- Le eccezioni attive (ADR-0014) escono dal gate.
- Scansione parziale: `gate` esce con 2, perché uno scanner mancante non è un esito verde. `--allow-partial` valuta ciò che c'è e lo segnala.

Significato del Gate 1 (§13): scansione completa su 3 repository pilota sotto i 10 minuti; il requisito sulla PR incrementale di §5 passa al Gate 2.

## Conseguenze

- Il gate è utile da subito, ma i livelli non riflettono l'impatto: un CVSS alto irraggiungibile blocca. In Fase 2 molti finding cambieranno livello e la documentazione deve dirlo.
- La scala CVSS non risolve la lacuna 5, che resta per Fase 2.
- Se si anticipasse la Variante A, questo ADR decade e le lacune 5 e 6 tornano bloccanti.
- scancode è il candidato più lento per i 10 minuti: va misurato presto sui repository pilota, che la specifica non indica.

## Emendamento per A-16 (2026-11-18): superata dai livelli da punteggio, per scelta

Motivo: D2-10 (2026-11-10) e ADR-0021. Questo ADR non decade: le sue regole restano in vigore finché la configurazione di scoring ha `levels.source: provisional`, che è il valore predefinito.

- Con `provisional` il livello dei finding, l'ordinamento e il gate sono quelli di questo ADR e il report è identico a quello della Fase 1; A e B stanno solo in `variant_scores`.
- Con `score` (l'atto del Gate 2, di chi controlla la configurazione di scoring e non del repository) il livello viene dalla variante attiva, con gli override, e la tabella sopra non si applica più ai finding che hanno un punteggio. `level_source` assume `score` o `override`.
- Il significato del Gate 1 non cambia. La scansione PR incrementale sotto i 10 minuti è il G2.d del Gate 2; `new-findings-only` esiste dal 2026-11-17 (ADR-0025) e non si ripiega più su `all` quando c'è una baseline valida.
- La scala CVSS e la regola «senza CVSS» informano il fattore G delle dipendenze, con i valori in configurazione (ADR-0021).
