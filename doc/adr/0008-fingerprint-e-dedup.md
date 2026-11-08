# ADR-0008: Algoritmo di fingerprint e deduplicazione

- Stato: Proposto
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §1, §4.1, §4.2, §8

## Contesto

Il fingerprint è la chiave delle eccezioni (§8) e, da Fase 2, della baseline: cambiarlo dopo il rilascio invalida entrambe. §4.2 lascia aperti diversi punti:

- `tool_family` e `component` non sono definiti.
- `rule_id` e `tool_family` entrano nell'hash, quindi osv-scanner (`GHSA-…`) e trivy (`CVE-…`) non si fondono mai sullo stesso problema, contro la promessa di §4.2 e §1.
- "2 righe attorno" è ambiguo.
- Mancano i casi: segreti nella storia git (la riga non esiste in HEAD) e licenze rilevate su file (nessun purl).
- `Finding.tool` è un solo valore, ma la dedup deve conservare "tutti i tool di origine".
- `id`, `first_seen`, `last_seen` e `Location.commit` sono obbligatori senza un database né, in alcuni casi, un repository git.

## Opzioni

1. Hash per regola e posizione, come scritto in §4.2: niente fusione fra scanner.
2. Dedup separata dal fingerprint, con unione degli alias a ogni scansione: il fingerprint resta legato allo scanner e un cambio di scanner invalida le eccezioni.
3. Fingerprint definito per tipo di finding, con identità canonica della vulnerabilità e versione dell'algoritmo.

## Raccomandazione

Opzione 3.

```text
fingerprint = "sha256:" + sha256("fp1" NUL kind NUL rule_id NUL tool_family NUL normalized_location NUL component)
```

| `kind` | `rule_id` | `tool_family` | `normalized_location` | `component` |
| --- | --- | --- | --- | --- |
| `code` (sast, iac) | id della regola | nome dello scanner | percorso + hash del contesto + occorrenza | vuoto |
| `dependency` | id canonico della vulnerabilità | `vuln` | vuoto | purl senza versione |
| `license-package` | `ca.license` | `license` | licenza SPDX | purl senza versione |
| `license-file` | `ca.license` | `license` | percorso + licenza SPDX | vuoto |
| `secret` | id della regola | `secret` | percorso + `sha256` del valore | vuoto |
| `health` | `ca.scanner-not-run` | `ca` | nome del plugin | vuoto |

- **Contesto del codice:** riga iniziale, una riga prima e una dopo (lettura letterale di "2 righe attorno"). Normalizzazione: fine riga LF, spazi compressi. Percorso POSIX relativo alla radice.
- **Occorrenza:** indice progressivo tra finding con stessa regola e stesso hash nel file, per non fondere codice duplicato.
- **Id canonico:** primo CVE in ordine lessicografico tra gli alias; altrimenti primo GHSA; altrimenti l'id dello scanner. Se in seguito a un GHSA viene assegnato un CVE, il fingerprint cambia: rischio accettato.
- **Segreti:** l'adattatore calcola l'hash nel container e dal container esce solo l'hash, mai il valore (ADR-0012). Lo stesso segreto in più commit dello stesso file è un solo finding.
- **Confine:** il `SourceReader` legge solo file regolari dentro il workspace; URI assoluti, `..` e symlink che escono vengono rifiutati. Un URI non valido fa fallire il plugin.

Regola di fusione: stesso fingerprint nella scansione. SAST di scanner diversi sulla stessa riga non si fondono in Fase 1.

Modifiche proposte al modello §4.1:

- `tools: list[str]` affianca `tool`, che diventa il primo in ordine lessicografico.
- `evidence` è raggruppata per tool; ulteriori percorsi e versioni in `evidence.occurrences`.
- `Location.commit` diventa opzionale (cartella non git).
- Senza database: `id` uguale al fingerprint, opaco per i consumatori; `first_seen` e `last_seen` uguali all'ora della scansione.

## Conseguenze

- Una futura `fp2` richiede una migrazione delle eccezioni; il prefisso `fp1` la rende rilevabile.
- L'SARIF espone il valore come `partialFingerprints["codeAnalyzer/v1"]` (ADR-0011).
- Una tabella di casi attesi con hypothesis copre rinomine di righe, CRLF, duplicati e alias (§14).
- Un hash di un segreto a bassa entropia è attaccabile a forza bruta; i report vanno trattati come riservati. Da rivedere con `security`.
