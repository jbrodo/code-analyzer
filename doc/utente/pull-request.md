# Modalità pull request: finding nuovi e baseline

Una scansione di PR dice quali finding la PR introduce, confrontandoli con una **baseline**. Il gate può bloccare solo su quelli nuovi, così un repository con debito pregresso non blocca ogni PR. Decisioni: ADR-0025.

## Uso

```bash
# 1. scansione completa del commit base, con la sua configurazione (la baseline)
code-analyzer scan . --output-dir base-out        # nel checkout del commit base

# 2. scansione della PR, confrontata con quella
code-analyzer scan . --output-dir out \
  --pr --base <commit-base> --baseline base-out/code-analyzer.report.json \
  --baseline-source ci-artifact --pull-request 42
code-analyzer gate --report out/code-analyzer.report.json --fail-on critico,alto
```

| Opzione | Significato |
| --- | --- |
| `--pr` | Scansione di PR. Richiede `--base`. |
| `--base COMMIT` | Commit base, completo (da 40 a 64 cifre esadecimali minuscole). Richiede `--pr`. |
| `--baseline FILE` | Report della scansione completa del commit base. |
| `--baseline-source` | `ci-artifact`, `base-scan` o `server`: dichiara la fonte nel report. La CLI non la verifica. |
| `--pull-request N` | Numero della PR, per il report e per `notify`. |

Un'opzione usata senza `--pr`, o `--pr` senza `--base`, è un errore di sintassi (exit 2) prima di qualunque lavoro. L'exit di `scan` non cambia: 0 se il report è prodotto, 2 altrimenti; decide solo `gate`.

## Quando la baseline vale

La baseline è un file che arriva **da fuori dal repository**: una PR non può fornirne una propria. `scan` la accetta solo se:

- sta fuori dalla directory analizzata (il percorso è risolto, quindi un collegamento simbolico non lo aggira);
- è un report valido di una scansione **completa** del repository (`scan.kind` `full`, non di una PR);
- è del commit indicato da `--base`.

Altrimenti la scansione procede senza baseline e il report registra `baseline.status` `missing` o `rejected` con il motivo (`baseline-inside-workspace`, `baseline-unreadable`, `baseline-invalid`, `baseline-not-full` o `baseline-commit-mismatch`). In quel caso il gate valuta **tutti** i finding, come in modo `all`, e l'avviso `new-findings-only-as-all` lo dice. Una baseline di una scansione parziale è accettata con l'avviso `baseline-partial`: i finding degli strumenti che erano falliti risultano nuovi. Una baseline mancante non fa mai passare un gate che altrimenti fallirebbe.

## Configurazione: quella del base

Con una baseline valida la scansione usa la configurazione **registrata nella baseline** (`effective_config`), non quella del file della PR: una PR non può indebolire il gate modificando `.code-analyzer.yml`. Se la configurazione della PR è diversa, il report avvisa con `config-changed-in-pr` (solo i nomi delle sezioni). Se la baseline non ha configurazione (un report della Fase 1) vale quella della PR, con l'avviso `baseline-without-config`; senza baseline, `pr-config-from-head`.

## Stato dei finding

Con una baseline valida ogni finding ha `baseline_state`:

- `new`: non c'era nella baseline;
- `existing`: c'era, anche se la riga è cambiata (il fingerprint non dipende dai numeri di riga);
- un finding della baseline che non c'è più è **risolto**: non è nel report, ma `baseline.resolved` li elenca e il SARIF li riporta come assenti.

Un file spostato o rinominato dalla PR non fa diventare «nuovi» i suoi finding: un secondo passaggio li accoppia al finding vecchio per regola e contesto, ma solo se l'accoppiamento è senza ambiguità (uno contro uno). Il vecchio percorso è in `previous_path`. Nel dubbio il finding resta `new`: si preferisce un falso nuovo a un nuovo nascosto.

Gli strumenti falliti o non eseguiti nella scansione della PR, o nella baseline, non hanno un confronto affidabile: i finding della baseline che non si possono valutare sono contati in `baseline.not_evaluated` e **non** diventano «risolti».

## Gate

Con `gate.mode: new-findings-only` e una baseline valida il gate blocca solo sui finding `new`, secondo `block_on`. Il modo effettivo è nel report (`gate.effective_mode`) e `gate` lo stampa. Con `gate.mode: all`, o senza baseline valida, valgono tutti i finding. Il gate sui nuovi non cancella i controlli di integrità: una scansione parziale o un plugin non firmato continuano a dare exit 2.

## Limiti

- **Provato con container reali solo in un E2E locale** (una PR simulata con un finding nuovo); non ancora in CI su un repository vero.
- Un finding nuovo che coincide con uno vecchio spostato **tra file diversi con più finding uguali** resta `new`.
- Il confronto è sulla scansione del commit base. Se il commit base cambia (rebase), la baseline va rifatta: l'Action e il componente GitLab lo fanno a ogni esecuzione.
- Il numero della PR e la fonte della baseline sono dichiarati da chi lancia `scan`: il report non può provarli.
