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

## Precisazioni per K-04

Data: 2026-11-08. Regole normative: dove il testo sopra è più generico vale questa sezione. L'opzione 3 non cambia. Qualunque variazione futura di queste regole richiede `fp2`, perché cambia l'identità dei finding. Le regole sono state provate con un'implementazione usa e getta contro `tests/unit/core/test_fingerprint.py`, e i casi reali sono ricavati da `tests/fixtures/plugin-output/`.

### 1. Formato di `normalized_location` e hash del contesto

I sotto-campi si separano con il byte NUL, come i campi della formula.

| `kind` | `normalized_location` |
| --- | --- |
| `code` | `path` NUL `context_hash` NUL `occurrence` |
| `dependency` | vuoto |
| `license-package` | `spdx` |
| `license-file` | `path` NUL `spdx` |
| `secret` | `path` NUL `value_sha256` |
| `health` | `plugin` |

- `context_hash`: SHA-256 del contesto normalizzato (§2 e §3), 64 cifre esadecimali minuscole, senza prefisso.
- `occurrence`: intero decimale ASCII senza zeri iniziali; la prima occorrenza è `0`.
- `value_sha256`: SHA-256 del valore del segreto in UTF-8, così come lo emette lo scanner, 64 cifre esadecimali minuscole, senza prefisso.

Il numero di sotto-campi è fisso per `kind` e `kind` è nell'hash, quindi la codifica è iniettiva. Non si usa `:`, che compare nei percorsi e nelle espressioni SPDX (`DocumentRef-x:LicenseRef-y`). Ogni campo e sotto-campo elementare che contiene NUL viene rifiutato con `ValueError`: i percorsi POSIX reali non lo contengono, una stringa di un plugin ostile sì.

`spdx` e `plugin` si usano così come arrivano, senza canonicalizzazione: `MIT OR Apache-2.0` e `Apache-2.0 OR MIT` danno fingerprint diversi. Con un'unica fonte per ciascuna forma di licenza il costo è nullo.

### 2. Contesto ai bordi del file

1. Se `source` comincia con U+FEFF, il carattere si toglie.
2. CRLF e CR isolato diventano LF. Si divide **solo** su LF: `str.splitlines()` non va usata, perché spezza anche su VT, FF, NEL, U+2028 e altri, e sposterebbe le righe rispetto agli scanner.
3. Con `n` righe, la riga `i` è il suo testo se `1 <= i <= n`, altrimenti la stringa vuota. La finestra ha sempre tre elementi: `start_line - 1`, `start_line`, `start_line + 1`. `end_line` non partecipa.
4. Il contesto è la concatenazione delle tre righe normalizzate (§3), separate da LF.

Conseguenze: un file con o senza LF finale dà lo stesso risultato sull'ultima riga; `start_line` oltre la fine del file è valido e produce righe vuote; `start_line < 1` è un `ValueError`.

**Finding senza contesto.** Se il `result` non ha `region`, o il file supera il limite di lettura (`SourceTooLarge`, ADR-0004), K-05 chiama `fingerprint_code` con `source=""` e `start_line=1`. Il contesto vale `sha256("\n\n")`; le occorrenze distinguono i finding nello stesso file. Le altre `SourceError` fanno fallire il plugin (vedi **Confine** nella Raccomandazione).

K-05 decodifica il file con `data.decode("utf-8", errors="surrogateescape")`: un file non UTF-8 non fa fallire la scansione e ha un risultato deterministico.

### 3. Spazi

Per ogni riga: ogni sequenza di caratteri SPACE (0x20), TAB (0x09), VT (0x0B) o FF (0x0C) diventa un solo SPACE; poi si tolgono gli SPACE iniziali e finali. Una riga di soli spazi diventa vuota. Gli spazi Unicode (es. U+00A0) non si toccano: `re.sub(r"\s+")` e `str.strip()` senza argomenti non sono conformi. La rimozione ai bordi rende stabile il fingerprint quando il codice viene reindentato.

### 4. Assegnazione di `occurrence`

`fingerprint_code` è pura e riceve `occurrence`. La calcola K-05, una volta per ogni SARIF di plugin e prima di costruire i `Finding`, con la funzione `assign_occurrences` di K-04, così l'algoritmo resta in un solo modulo.

- Gruppo: stessi `rule_id`, `tool`, `path`, `context_hash`.
- Ordine crescente per `(start_line, start_column, end_line, end_column)`. Colonne assenti valgono 0, `end_line` assente vale `start_line`.
- L'indice si assegna alle **posizioni distinte**: due `result` nella stessa posizione hanno la stessa occorrenza, quindi lo stesso fingerprint, e li fonde la deduplica. L'ordine dei `result` nel SARIF non conta.

Esempio: le posizioni `(20,1,20,5)`, `(2,9,2,12)`, `(2,1,2,5)`, `(20,1,20,5)` della stessa chiave danno `[2, 1, 0, 2]`.

### 5. `purl` senza versione

Ingresso conforme allo schema di `purl` (`^pkg:[a-z][a-z0-9.+-]*/\S+$`), altrimenti `ValueError`.

1. Si tolgono subpath (dal primo `#`) e qualifier (dal primo `?`): gli scanner emettono qualifier diversi (`arch`, `distro`) sullo stesso pacchetto, e l'identità è quella del pacchetto.
2. Nell'ultimo segmento dopo l'ultimo `/` si toglie la versione, dal primo `@` in poi. Così `pkg:npm/@a/b` conserva lo scope, che non è una versione.
3. `npm`: namespace e nome in minuscolo; un `@` iniziale del namespace diventa `%40`. `pypi`: nome normalizzato PEP 503 (minuscolo, sequenze di `-`, `_`, `.` sostituite da `-`). Gli altri tipi restano invariati.

Forma risultante: `pkg:<tipo>/<namespace>/<nome>`, senza `/` finale e senza namespace se assente. La forma è usata solo per l'hash: `Location.purl` conserva il valore originale.

### 6. Alias e id canonico

- `vuln_ids` è l'unione di `ruleId` e di `properties.aliases`. Ammette duplicati: in osv-scanner `deprecatedIds` contiene anche l'id primario. Lista vuota: `ValueError`.
- L'ordine non conta. Si sceglie il minimo lessicografico tra gli id con prefisso `CVE-`; altrimenti tra quelli con prefisso `GHSA-`; altrimenti tra tutti gli id. Il riconoscimento è per prefisso esatto.
- La frase "altrimenti l'id dello scanner" è superata: con più id senza CVE o GHSA (`PYSEC-…`, `BIT-…`) l'id dello scanner dipenderebbe da quale scanner lo emette. Con un solo id il risultato è lo stesso.
- Riconoscere un id significa accettarne la forma pubblicata dalla fonte: gli adattatori non alterano maiuscole e minuscole.

### 7. Deduplica

L'idempotenza è una proprietà di K-07, `ca_core.dedup.deduplicate(findings: Sequence[Finding]) -> list[Finding]`. K-04 ne fornisce la chiave ma non la implementa.

Definizione, per ogni lista `xs`: `deduplicate(deduplicate(xs)) == deduplicate(xs)` e, per ogni permutazione, `deduplicate(perm(xs)) == deduplicate(xs)`. L'uguaglianza è campo per campo.

Implementazione:

- Si raggruppa per `fingerprint`; il risultato è ordinato per `fingerprint`. Un gruppo di uno ritorna invariato: dato che dopo la fusione i fingerprint sono unici, questo basta per l'idempotenza.
- Precondizioni da K-05: `tools = [tool]`, `evidence` con chiave `<tool>` (più `occurrences` riservata, che nessun plugin può usare come nome), `level`, `score` e `impact` nulli. I livelli si calcolano dopo (K-11) sull'evidenza fusa.
- Rappresentante del gruppo per `title`, `message`, `location`, `license_spdx`: il finding con la serializzazione canonica minima (`json.dumps(f.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))`).
- `tools`, `cve`, `cwe`: unione ordinata senza duplicati. `tool`: il primo di `tools`.
- `evidence["<tool>"]`: quella del rappresentante tra i finding dello stesso tool. `evidence["occurrences"]`: unione delle posizioni di tutti i finding del gruppo (`path`, `start_line`, `end_line`, `purl`), senza duplicati, ordinata per serializzazione canonica.
- `first_seen` è il minimo, `last_seen` il massimo.

### 8. Codifica

`fingerprint = "sha256:" + sha256(payload).hexdigest()`, con payload uguale a `"fp1"`, `kind`, `rule_id`, `tool_family`, `normalized_location`, `component` uniti da un singolo byte `0x00`, senza NUL finale aggiunto: un `component` vuoto lascia l'ultimo separatore in coda al payload. La stringa si codifica con `str.encode("utf-8", "surrogateescape")`, così un percorso non UTF-8 mantiene i suoi byte. Vale lo stesso per il contesto. Digest in esadecimale minuscolo.

### Percorsi e campi in ingresso

- `path` è POSIX, relativo alla radice, senza `/` iniziale e senza segmenti vuoti, `.` o `..`: altrimenti `ValueError`. Nessuna normalizzazione Unicode né di maiuscole.
- K-05 lo ricava dall'`uri` con `urllib.parse.unquote(uri, encoding="utf-8", errors="surrogateescape")`, dopo averlo validato. Per i segreti il controllo è solo sintattico: il file può esistere solo nella storia.
- `tool` è il `name` del manifest del plugin, mai `tool.driver.name`, che è dato non fidato e può variare tra versioni.
- `rule_id`, `tool`, `path`, `spdx`, `plugin` vuoti sono `ValueError`.

Requisiti verso gli adattatori (ADR-0007, emendamento dopo A-01): gli `uri` in `/out` sono relativi alla radice del workspace; `ruleId` non dipende dal percorso delle regole, dato che semgrep prefissa l'id con il percorso della directory di configurazione (nel campione `tmp.claude-….scratchpad.rules.py-shell-true`).

### Firma di `ca_core.fingerprint`

Solo libreria standard, nessun I/O. Tutte le funzioni di fingerprint restituiscono `"sha256:" + <64 hex minuscoli>`; ingressi non validi sollevano `ValueError`.

```python
def compute_fingerprint(kind: str, rule_id: str, tool_family: str,
                        normalized_location: str, component: str) -> str: ...
def context_hash(source: str, start_line: int) -> str: ...          # 64 hex, senza prefisso
def normalize_purl(purl: str) -> str: ...
def canonical_vuln_id(ids: Sequence[str]) -> str: ...

class CodeSite(NamedTuple):
    rule_id: str
    tool: str
    path: str
    context_hash: str
    start_line: int
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

def assign_occurrences(sites: Sequence[CodeSite]) -> list[int]: ...  # stesso ordine di `sites`

def fingerprint_code(*, rule_id: str, tool: str, path: str, source: str,
                     start_line: int, occurrence: int = 0) -> str: ...
def fingerprint_dependency(*, vuln_ids: Sequence[str], purl: str) -> str: ...
def fingerprint_license_package(*, spdx: str, purl: str) -> str: ...
def fingerprint_license_file(*, path: str, spdx: str) -> str: ...
def fingerprint_secret(*, rule_id: str, path: str, value_sha256: str) -> str: ...
def fingerprint_health(*, plugin: str) -> str: ...
```

`compute_fingerprint` rifiuta NUL in `kind`, `rule_id`, `tool_family` e `component`; in `normalized_location` no, perché i sotto-campi sono già separati da NUL. Il controllo dei sotto-campi spetta alle funzioni `fingerprint_*`.

### Vettori di prova

Con `SOURCE` e `CODE` di `test_fingerprint.py` (`B605`, `bandit`, `app/run.py`, riga 4):

| Caso | Valore |
| --- | --- |
| `context_hash(SOURCE, 4)` | `d47f4091a596c49743162cdd10baf905a2daad5b9b517314147244f25c4f69f4` |
| `context_hash(SOURCE, 1)` | `d6f34ecc0e2af7242bf9d77a21f32dcb32be709e96f7088e74978eb0671c0eb2` |
| `context_hash(SOURCE, 7)`, con e senza LF finale | `a31c6181c7365adfa4b7a3dae5bc3b028126f1a973e89a9cffc2698f79322d3a` |
| `context_hash("", 1)` | `75a11da44c802486bc6f65640aa48a730f0f684c5c07a42ba3cd1735eb3fb070` |
| `fingerprint_code` con `occurrence=0` | `sha256:187c77673925b2ef1adb137c936008f2234866b63ff8b84725553f7def7c0ed0` |
| `fingerprint_code` con `occurrence=1` | `sha256:74a89bf93e4398895f7ad8826dabc244a2a78fef6cd46a359e60da1a5abf54bb` |
| `fingerprint_secret("generic-api-key", "config/settings.py", H1)` | `sha256:8f72eb4d0df8835149ac43ef26fd85bd4f4b3a0f2111ebf7bffd7cf51d315af0` |
| `fingerprint_license_file("vendor/LICENSE", "AGPL-3.0-only")` | `sha256:5afd24e0e77943f5191a42cf963b79809a63d97b88db65ea042905de805e3ebf` |

`H1` è `sha256(b"FAKE-SECRET-NOT-REAL-1")`, cioè `aa9d997ccd858516b21e6eddf65825e622e807a34586cc3cd25074cb6bbd657b`.

Casi di `normalize_purl`:

| Ingresso | Risultato |
| --- | --- |
| `pkg:pypi/Django_Foo.bar@1` | `pkg:pypi/django-foo-bar` |
| `pkg:npm/%40angular/core@1.0` | `pkg:npm/%40angular/core` |
| `pkg:npm/@Angular/Core` | `pkg:npm/%40angular/core` |
| `pkg:npm/left-pad@1.3.0?foo=bar#sub/x` | `pkg:npm/left-pad` |
| `pkg:deb/debian/libc6@2.31?arch=amd64&distro=debian-11` | `pkg:deb/debian/libc6` |
| `pkg:golang/google.golang.org/genproto@v0.0.1#googleapis/api` | `pkg:golang/google.golang.org/genproto` |
| `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0` | invariato tranne la versione |

### Adattamento di `tests/unit/core/test_fingerprint.py`

Con una implementazione conforme, l'intero file passa tranne un caso.

Da modificare:

1. `test_license_file_differs_from_license_package`: `purl="a"` non è un purl valido; sostituirlo con `purl="pkg:npm/a"`.
2. Docstring del modulo: `canonical_vuln_id` usa il minimo lessicografico al posto di `ids[0]`; togliere la nota su `occurrence` come punto aperto; aggiungere `context_hash`, `normalize_purl`, `CodeSite`, `assign_occurrences`.
3. `test_code_signature_matches_declared_one`: togliere il commento sul formato non definito.

Da aggiungere, con `needs_k04`:

- `test_code_golden_vector` e i vettori `context_hash`, `fingerprint_secret`, `fingerprint_license_file` della tabella.
- Bordi: `start_line=1` e ultima riga non sollevano; LF finale indifferente; `start_line=0` è `ValueError`; `start_line` oltre la fine è valido.
- Spazi: indentazione e TAB indifferenti; U+00A0 non equivale a SPACE; VT e FF non separano le righe.
- CR isolato equivale a LF; il BOM iniziale è ignorato.
- `assign_occurrences` con l'esempio di §4 e con una permutazione degli stessi siti.
- `normalize_purl` con la tabella sopra; `ValueError` su `a`.
- `test_canonical_vuln_id`: `(["PYSEC-2022-190", "BIT-django-2022-28346"], "BIT-django-2022-28346")` e `(["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9", "CVE-2020-28500"], "CVE-2020-28500")`; lista vuota `ValueError`.
- Valori non validi: NUL in `rule_id`, `path` assoluto o con `..`, `value_sha256` in maiuscolo.
