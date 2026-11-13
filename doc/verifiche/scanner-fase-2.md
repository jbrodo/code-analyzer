# Fase 2 — Verifica iniziale dei fatti

Esiti dei task V di `doc/plan/fase-2.md`. Ogni dato indica se è misurato qui o letto alla fonte, con la data. Non è un parere legale: le valutazioni di licenza restano di D2-14.

## V-01 — Versioni candidate

Raccolte il 2026-11-13 dai registri (API JSON di PyPI, registro npm, API dei rilasci di GitHub). Versione: l'ultima stabile pubblicata. Licenza: quella **dichiarata nei metadati** del pacchetto; la lettura dal file di licenza al tag è di V-02. Nulla è stato installato né eseguito: compatibilità e comportamento sono di V-03, V-04 e V-07.

### Motori dei plugin e `ca-graph`

| Componente | Versione | Data | Artefatto e SHA-256 | Licenza dichiarata | Note |
| --- | --- | --- | --- | --- | --- |
| ruff | 0.17.5 | 2026-11-12 | `ruff-0.17.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` `40ca8afaac309b41a5b2e09e4e7beb1f824826b93c25697c4d74f573324fba4e` | MIT | Rilasci settimanali |
| checkov | 3.4.5 | 2026-11-12 | `checkov-3.4.5-py3-none-any.whl` `64210c48a957ecb85dfb38057e00faa150b5e46e76b08e710d29beb687b7ced2` | Apache License 2.0 | Rilasci quasi quotidiani: la versione fissata invecchia in fretta |
| hadolint | 2.15.1 | 2026-07-31 | `hadolint-linux-x86_64` `c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507` | GPL-3.0 (dal repository) | **GPL-3.0: in `require_approval` di D-0013**, da portare a D2-14. Binario statico dai rilasci di GitHub. Rilasci rari: 2.13.1 e 2.14.0 a settembre 2025, 2.15.0 e 2.15.1 a luglio 2026; ultimo push al repository 2026-10-19 |
| eslint | 10.14.0 | 2026-10-30 | `eslint-10.14.0.tgz` `sha512-T0pNsxkb9IKmtQjhpK3d7nWOpFv+YHuMbTJnSVMoQblF0onvXfErrtp4V1jHtsQPan7dKaGVD0q1WCXnzMF31A==` | MIT | Rilasci ogni due settimane. Richiede Node 20.19, 22.13 o 24 |
| typescript-eslint | 8.72.2 | 2026-11-09 | `typescript-eslint-8.72.2.tgz` `sha512-c/+AKMW1KB81r28Sp0AAdcyXj5dzNmAsZFcsrxKbZTKmcBK2xIwBR31dcSYSDu3bKmzXe8GKrSxO+eDQ401Uzg==` | MIT | Compatibilità con TypeScript 7 da provare in V-03 |
| @microsoft/eslint-formatter-sarif | 3.1.0 | 2024-04-12 | `eslint-formatter-sarif-3.1.0.tgz` `sha512-/mn4UXziHzGXnKCg+r8HGgPy+w4RzpgdoqFuqaKOqUVBT5x2CygGefIrO4SusaY7t0C4gyIWMNu6YQT6Jw64Cw==` | MIT | **Fermo da aprile 2024**, 9 versioni in tutto: compatibilità con eslint 10 da provare in V-03; in alternativa SARIF prodotto dall'adattatore a partire dal JSON di eslint |
| tree-sitter | 0.26.1 | 2026-11-09 | `tree_sitter-0.26.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` `7b14ac81a2afdcf75610f714f1d2eeaac40da93965c104cabb5c4c2b536a488a` | MIT License | Wheel per cp310..cp314. Checksum della wheel cp312; cp314: `0c1b48e17b26cf555060c1285b35f49eeb345222e62c2a35d70c393a7c61c65b` |
| tree-sitter-python | 0.25.0 | 2025-09-11 | `tree_sitter_python-0.25.0-cp310-abi3-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl` `86f118e5eecad616ecdb81d171a36dde9bef5a0b21ed71ea9c3e390813c3baf5` | MIT | Wheel abi3. Ultimo rilascio a settembre 2025 |
| tree-sitter-javascript | 0.25.0 | 2025-09-01 | `tree_sitter_javascript-0.25.0-cp310-abi3-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl` `9dc04ba91fc8583344e57c1f1ed5b2c97ecaaf47480011b92fbeab8dda96db75` | MIT | Wheel abi3. Ultimo rilascio a settembre 2025 |
| tree-sitter-typescript | 0.23.2 | 2024-11-11 | `tree_sitter_typescript-0.23.2-cp39-abi3-manylinux_2_5_x86_64.manylinux1_x86_64.manylinux_2_17_x86_64.manylinux2014_x86_64.whl` `e96d36b85bcacdeb8ff5c2618d75593ef12ebaf1b4eace3477e2bdb2abb1752c` | MIT | Contiene TypeScript e TSX. **Fermo da novembre 2024**: compatibilità con tree-sitter 0.26 da provare in V-07 |

Per npm la colonna riporta il campo `integrity` del registro (SHA-512 in base64), che è ciò che `pnpm` verifica.

### Server

| Componente | Versione | Data | Artefatto e SHA-256 | Licenza dichiarata | Note |
| --- | --- | --- | --- | --- | --- |
| fastapi | 0.162.6 | 2026-11-13 | `fastapi-0.162.6-py3-none-any.whl` `df12575573c26a49083f690c43496b6dafa483dca72ca66de4b50d1db5940787` | MIT | Rilasci frequenti |
| uvicorn | 0.54.0 | 2026-09-25 | `uvicorn-0.54.0-py3-none-any.whl` `505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf` | BSD-3-Clause | Server ASGI per FastAPI |
| sqlalchemy | 2.1.8 | 2026-11-04 | `sqlalchemy-2.1.8-py3-none-any.whl` `69aea77b5d8a64e95d01fd7ec54985c84b4a8ef3cac3108e9271145441400c1b` | MIT | Serie 2.1 |
| alembic | 1.20.1 | 2026-10-22 | `alembic-1.20.1-py3-none-any.whl` `9970712cfb81ea26c8658d378aaa5b8f6ff9146e5bb111d70497c164016cf598` | MIT |  |
| psycopg | 3.3.9 | 2026-11-12 | `psycopg-3.3.9-py3-none-any.whl` `d2d7d04a1ce6dab4f5b27316bea3b52585cafa2f2d631e5b09dd69823f5c26f6` | LGPL-3.0-only | **LGPL-3.0-only: in `require_approval` di D-0013.** Da portare a D2-07 e D2-14 |
| psycopg-binary | 3.3.9 | 2026-11-12 | `psycopg_binary-3.3.9-cp310-cp310-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` `b36b1f1488843301af90a25b135dd4373a9835c4df185e564f14e6565220c353` | LGPL-3.0-only | Come psycopg; wheel cp314 disponibile. Include libpq e le sue dipendenze |
| asyncpg | 0.32.0 | 2026-10-06 | `asyncpg-0.32.0-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` `63417b8f7369c54f6754c1fbd5a2968fbe632ff55bfbedd56a0177b6a96bd251` | Apache-2.0 | Alternativa a psycopg senza copyleft; solo asincrono. Un rilascio all'anno |
| pg8000 | 1.31.6 | 2026-10-26 | `pg8000-1.31.6-py3-none-any.whl` `1ffe27af94fa5b37ce6885b98d591dc75562ff076859bf50ca7729af59345a80` | BSD-3-Clause | Alternativa in Python puro, sincrona |
| pyjwt | 2.15.1 | 2026-09-28 | `pyjwt-2.15.1-py3-none-any.whl` `42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193` | MIT | Candidata per la verifica dei token OIDC |
| authlib | 1.9.5 | 2026-11-05 | `authlib-1.9.5-py2.py3-none-any.whl` `e32a63e3d869196b61816b2602231862179a2ffc29358c009d1f022c8b86a8b2` | BSD-3-Clause | Alternativa a pyjwt, più ampia. Sulla serie 1.9 esiste un rilascio più recente (2026-11-12) non marcato come ultimo |
| opentelemetry-api | 1.45.2 | 2026-10-29 | `opentelemetry_api-1.45.2-py3-none-any.whl` `2cbd737377e710ee740d261c94e93fa0f08e6d037c18f17513cc0a2d94479a34` | Apache-2.0 | ADR-0016 |
| opentelemetry-sdk | 1.45.2 | 2026-10-29 | `opentelemetry_sdk-1.45.2-py3-none-any.whl` `ff974ea70ee4f1d51e2ec152db37c2b626c7bf82bb3f7d86114fd8704e7199c6` | Apache-2.0 | ADR-0016 |
| testcontainers | 4.15.0 | 2026-07-24 | `testcontainers-4.15.0-py3-none-any.whl` `8796c14e76604031ad39cf0ed3b8e9806283a1fbf5270965c2b1c594caa31b74` | Apache-2.0 |  |

### Frontend

| Componente | Versione | Data | Artefatto e integrità | Licenza dichiarata | Note |
| --- | --- | --- | --- | --- | --- |
| react | 19.3.1 | 2026-10-14 | `react-19.3.1.tgz` `sha512-QNhWdt7nrgVWWQG58QuGsAR3jv3Hbe4mb4vz7w2csnHavciZJgda1CPNaldF6eVxv90ud3jUXpKlHL69gO38yw==` | MIT |  |
| react-dom | 19.3.1 | 2026-10-14 | `react-dom-19.3.1.tgz` `sha512-Y0bARz53lhEC1NMCASs0/j+faB/zqt3R8hpvg1e8+61ZVJ4UL0UdC4cBbXfZMcIuhrfgeILTLe+ZeBCavQPtKQ==` | MIT |  |
| vite | 8.3.8 | 2026-11-11 | `vite-8.3.8.tgz` `sha512-LzOn3h9rG/0vhLdXrV4yJ4QFA9eEoqCl+Yx+kGJd7aB9w6nfNgVHKSYwLPZUHrz4ZGa+t+kXjV9itvcHDLQouA==` | MIT | Richiede Node 20.19 o 22.12 |
| typescript | 7.0.2 | 2026-07-08 | `typescript-7.0.2.tgz` `sha512-8FYau96o3NKOhbjKi/qNvG/W5jhzxkbdm5sj9AbZ/5T5sWqn3hJgLfGx27sRKZWTvyzCP8dLRBTf5tBTSRVUNA==` | Apache-2.0 | Serie 7, la prima con il compilatore nativo: da provare con typescript-eslint e openapi-typescript |
| pnpm | 12.18.0 | 2026-11-05 | `pnpm-12.18.0.tgz` `sha512-nXiC1dyCFH7PxOBiqjSDTgrQKWcQoYN6ERWuASEn02txCeMhrBWYod0KZVl2gbHpmRfhLtDXSerpEYeUM2O+sw==` | MIT |  |
| openapi-typescript | 7.13.0 | 2026-02-11 | `openapi-typescript-7.13.0.tgz` `sha512-EFP392gcqXS7ntPvbhBzbF8TyBA+baIYEm791Hy5YkjDYKTnk/Tn5OQeKm5BIZvJihpp8Zzr4hzx0Irde1LNGQ==` | MIT | Generatore dei tipi dall'OpenAPI (ADR-0017). Ultimo rilascio a febbraio 2026 |
| vitest | 5.1.0 | 2026-11-02 | `vitest-5.1.0.tgz` `sha512-MzmNFnrwa8v8lF1bLxw3UJ4EREwVOVb75VqJZmUDRjJ6EluK/x9th7qTbaeDk41WxE1GxWqmTXcdsfobfH5sOA==` | MIT | Richiede Node 22.12, 24 o 26 |
| @testing-library/react | 16.3.3 | 2026-08-27 | `react-16.3.3.tgz` `sha512-Uo193NgQbPMz6lrrhtRQQFcMC6Re/ELLFbbuVL30WDlZxlpZf9/lMHTAVxPRLw1q1iu9OJmR1c2BLiENRstdBg==` | MIT |  |

Il Temporal SDK non è nell'elenco: D2-01 lo esclude dalla Fase 2.

### Punti da decidere o provare

- **Driver PostgreSQL (D2-07, D2-14).** psycopg è LGPL-3.0-only, una licenza che la policy D-0013 mette tra quelle da approvare. Il server lo userebbe come libreria importata, non modificata. Le alternative senza copyleft sono asyncpg (Apache-2.0, solo asincrono) e pg8000 (BSD-3-Clause, Python puro). La scelta è di ADR-0030 (A-15).
- **hadolint (D2-14).** GPL-3.0, eseguito come binario separato nella propria immagine. Il progetto è GPL-3.0-only, quindi la combinazione non introduce una licenza più restrittiva di quella del prodotto; resta la valutazione di D2-14 sulla distribuzione dell'immagine.
- **Componenti fermi.** tree-sitter-typescript (novembre 2024) e `@microsoft/eslint-formatter-sarif` (aprile 2024) non hanno rilasci recenti, mentre i loro compagni sono avanzati di una o più serie. Vanno provati prima di fissarli: V-07 per la grammatica, V-03 per il formattatore.
- **TypeScript 7.** È la serie corrente e cambia compilatore. typescript-eslint, openapi-typescript e vite vanno provati con questa serie in V-03 e W-01; se uno non la regge, si fissa l'ultima 6.x.
- **Node.** gli intervalli dichiarati da eslint 10, vite 8 e vitest 5 hanno in comune Node 22 dalla 22.13 e Node 24. Node 24 li soddisfa tutti: è il candidato per l'immagine del plugin eslint e per la CI di `web/`.
- **Python.** I motori dei plugin girano nelle immagini con Python 3.12 (base dei plugin), il server con Python 3.14. Nessun pacchetto del server dichiara un limite superiore di versione di Python; psycopg-binary, asyncpg e tree-sitter hanno una wheel cp314. L'installazione su 3.14 non è stata provata.
- **Frequenza dei rilasci.** checkov, fastapi, ruff e typescript-eslint pubblicano più volte al mese: le versioni di questa tabella sono un punto di partenza, e ogni task che aggiunge la dipendenza fissa quella corrente con il proprio checksum.

## V-02 — Licenze sul testo della versione fissata

Verificato il 2026-11-13. Per ogni voce di V-01 ho scaricato l'artefatto della versione fissata, ne ho confrontato il checksum con quello del registro (tutti coincidono) e ho letto il file di licenza contenuto nell'artefatto. Per hadolint, MinIO e gli schemi di GitLab il file è stato letto dal repository. Il riconoscimento è sul testo del file, per frasi caratteristiche: dice quale licenza è, non se è stata modificata. Non è un parere legale.

Confronto con D-0013: **ammessa** se non è né vietata né da approvare; le altre due classi sono quelle della policy.

| Componente | File letto | Licenza dal testo | D-0013 |
| --- | --- | --- | --- |
| ruff 0.17.5 | `LICENSE` nella wheel | MIT | Ammessa |
| checkov 3.4.5 | `LICENSE` nella wheel | Apache-2.0 | Ammessa |
| hadolint 2.15.1 | `LICENSE` al tag `v2.15.1` | GPL versione 3 | **Da approvare** |
| eslint 10.14.0 | `LICENSE` nel pacchetto | MIT | Ammessa |
| typescript-eslint 8.72.2 | `LICENSE` nel pacchetto | MIT | Ammessa |
| @microsoft/eslint-formatter-sarif 3.1.0 | **Nessun file di licenza nel pacchetto.** I metadati dichiarano MIT; il sorgente è nel repository `Microsoft/sarif-js-sdk` | Non verificabile dal pacchetto | Da chiarire |
| tree-sitter 0.26.1 | `LICENSE` nella wheel | MIT | Ammessa |
| tree-sitter-python 0.25.0, tree-sitter-javascript 0.25.0 | `LICENSE` nella wheel | MIT | Ammessa |
| tree-sitter-typescript 0.23.2 | `LICENSE` nella wheel e al tag `v0.23.2` | MIT | Ammessa |
| fastapi 0.162.6, sqlalchemy 2.1.8, alembic 1.20.1, pyjwt 2.15.1 | `LICENSE` nella wheel | MIT | Ammessa |
| uvicorn 0.54.0, authlib 1.9.5 | `LICENSE` nella wheel | BSD a 3 clausole | Ammessa |
| psycopg 3.3.9, psycopg-binary 3.3.9 | `LICENSE.txt` nella wheel | LGPL versione 3 | **Da approvare** |
| asyncpg 0.32.0 | `LICENSE` nella wheel | Apache-2.0 | Ammessa |
| pg8000 1.31.6 | `LICENSE` nella wheel | BSD a 3 clausole | Ammessa |
| opentelemetry-api e opentelemetry-sdk 1.45.2, testcontainers 4.15.0 | `LICENSE` nella wheel | Apache-2.0 | Ammessa |
| react e react-dom 19.3.1, openapi-typescript 7.13.0, @testing-library/react 16.3.3 | `LICENSE` nel pacchetto | MIT | Ammessa |
| vite 8.3.8, vitest 5.1.0 | `LICENSE.md` nel pacchetto | MIT, seguita dalle licenze delle dipendenze incluse nel pacchetto | Ammessa per il testo principale; le dipendenze incluse non sono state lette una per una |
| typescript 7.0.2 | `LICENSE` e `NOTICE.txt` nel pacchetto | Apache-2.0; il `NOTICE` riporta testi MIT di terzi | Ammessa |
| pnpm 12.18.0 | Nessun file di licenza al primo livello; i metadati dichiarano MIT. Il pacchetto include dipendenze con i propri file di licenza | Non verificabile dal primo livello | Strumento di build, non distribuito con il prodotto |
| MinIO (server) | `LICENSE` del repository, ramo `master` | AGPL versione 3 | **Vietata** in un prodotto distribuito |
| Schemi dei report di sicurezza GitLab | `LICENSE.md` del repository `gitlab-org/security-products/security-report-schemas` | MIT | Ammessa |

### Da portare a D2-14 e D2-07

- **hadolint:** licenza da approvare. È un binario separato nella propria immagine; la licenza del progetto è della stessa famiglia e versione.
- **psycopg:** licenza da approvare, usata come libreria importata dal server. `psycopg-binary` include anche libpq e le sue dipendenze, non lette qui. Alternative con licenze ammesse: asyncpg e pg8000.
- **MinIO:** conferma l'ipotesi di D2-07: il server non può far parte di un prodotto distribuito senza un'eccezione alla policy. La raccomandazione di D2-07 (porta `ArtifactStore` con adattatore su file system, nessun server di object storage incluso) evita il problema.
- **Formattatore SARIF di eslint:** il pacchetto non porta il testo della licenza. Con il fatto che è fermo dal 2024 (V-01), pesa a favore del SARIF prodotto dall'adattatore.
- **Grammatiche tree-sitter:** nessun problema di licenza sul testo. Le wheel contengono codice C generato; la sua provenienza non è stata esaminata.
- **Dipendenze transitive:** questa verifica copre i componenti nominati, non l'albero delle loro dipendenze. Quello lo copre l'SBOM della build, come in D-0015.

### Requisiti di pubblicazione

Letti alla fonte il 2026-11-13. Servono a D2-12 e D2-13; nulla viene pubblicato (D2-16).

**GitHub Marketplace** (<https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace>):

- "The action must be in a public repository."
- "Each repository must contain a single action metadata file (`action.yml` or `action.yaml`) at the root." Altri file di metadati in sottocartelle sono ammessi, ma non vengono elencati nel Marketplace.
- Il `name` dell'action deve essere unico nel Marketplace.
- Servono l'accettazione dei termini del Marketplace e l'autenticazione a due fattori.

Quindi un'action in `integrations/github-action/` del monorepo si può usare con `uses:` e il percorso, ma non si può elencare nel Marketplace: per quello serve un repository dedicato e pubblico con `action.yml` alla radice. Conferma la raccomandazione di D2-13.

**Catalogo CI/CD di GitLab** (<https://docs.gitlab.com/ci/components/>):

- Il componente vive in un progetto GitLab, in una cartella `templates/` alla radice, con un `README.md`.
- Per il catalogo: descrizione del progetto, progetto marcato come progetto di catalogo (serve il ruolo Owner), rilascio creato da un job con la parola chiave `release` su una pipeline di tag, tag in versione semantica.
- "You can only reference components in the same GitLab instance as your project": un'istanza self-managed deve avere una copia del progetto.

Quindi il componente non può essere usato dal repository GitHub: serve un progetto su ciascuna istanza GitLab che lo usa. Conferma l'incoerenza 13 e D2-12.

## V-05 — Feed EPSS e KEV

Verificato il 2026-11-13, scaricando i file e leggendo le pagine indicate.

### EPSS

| Voce | Valore | Origine |
| --- | --- | --- |
| Distribuzione | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, che risponde 302 verso il file del giorno (`epss_scores-2026-11-13.csv.gz`). Il vecchio host `epss.cyentia.com` risponde 301 verso quello nuovo | Misurato |
| Storico | Archivio `github.com/empiricalsec/epss_scores`, dal 2021-04-14. La pagina non dà un URL per data | Letto: <https://www.first.org/epss/data> |
| Formato | CSV compresso con gzip. Prima riga di commento `#model_version:v2026.06.15,score_date:2026-11-13T12:03:22Z`, poi intestazione `cve,epss,percentile` | Misurato |
| Dimensione | 2,85 MB compresso, 12,4 MB decompresso, 406.184 CVE | Misurato |
| Frequenza | Giornaliera. La FAQ indica la pubblicazione poco dopo le 13:30 UTC; il file scaricato ha `Last-Modified` 13:30:36 UTC | Letto: <https://www.first.org/epss/faq>; misurato |
| Integrità | Nessun checksum né firma pubblicati. L'`ETag` è l'MD5 del file (verificato): prova il trasferimento, non l'origine | Misurato |
| API | Esiste un'API oltre al CSV. Non verificata: il piano usa il file giornaliero | Letto |
| Termini d'uso | Nessuna licenza dei dati dichiarata. "free of charge, with no registration required"; "Attribution is requested when EPSS data is used in publications or products". Il sito porta la nota generale "Copyright © 2015—2026 by Forum of Incident Response and Security Teams, Inc. All Rights Reserved" | Letto: <https://www.first.org/epss/data>, <https://www.first.org/epss/faq> |

I punteggi sono generati da Empirical Security e pubblicati da FIRST (EPSS SIG).

### KEV

| Voce | Valore | Origine |
| --- | --- | --- |
| Distribuzione | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; esiste anche il CSV in `/sites/default/files/csv/` | Misurato |
| Formato | JSON con `title`, `catalogVersion` (`2026.11.10`), `dateReleased`, `count` e `vulnerabilities[]`. Campi di ogni voce: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `cwes`, `forensicTriage` | Misurato |
| Dimensione | JSON 1,85 MB, 1.779 voci; CSV 1,11 MB. Il server non invia `Content-Length` | Misurato |
| Frequenza | Senza cadenza fissa: il catalogo cambia quando CISA aggiunge una voce. Da agosto 2026 le date di aggiunta distinte sono 51, cioè circa un aggiornamento ogni due giorni | Misurato su `dateAdded` |
| Integrità | Nessun checksum né firma. `ETag` e `Last-Modified` soltanto | Misurato |
| Termini d'uso | CC0 1.0. Le informazioni dei collegamenti a terzi restano sotto le condizioni dei rispettivi siti; l'uso non autorizza il logo CISA o il sigillo DHS né implica approvazione | Letto: <https://www.cisa.gov/sites/default/files/licenses/kev/license.txt> |

### Ridistribuzione di OSV e trivy-db

Serve a D2-05 (mirror) e a D2-14.

| Fonte | Termini | Origine |
| --- | --- | --- |
| OSV | Licenza per sorgente. Per gli ecosistemi della Fase 2: PyPI Advisory Database CC-BY 4.0, GitHub Advisory Database CC-BY 4.0. La pagina non ha una dichiarazione generale sulla ridistribuzione degli archivi aggregati e non dice quale sorgente alimenta npm. Altre sorgenti hanno licenze diverse, tra cui CC-BY-SA 4.0 (Ubuntu, Alpine) e CC-BY-NC-ND 4.0 (Chainguard): non sono negli ecosistemi sincronizzati oggi | Letto: <https://google.github.io/osv.dev/data/> |
| trivy-db | Il repository è Apache-2.0 (dal badge del README; il file `LICENSE` non è stato letto). Il README non dichiara le licenze dei dati aggregati (NVD, Red Hat, Debian e altri) né parla di ridistribuzione. Database pubblicato in `ghcr.io/aquasecurity/trivy-db:2`, costruito ogni 6 ore | Letto: README di `aquasecurity/trivy-db` |
| trivy, sorgenti per linguaggio | La documentazione indica l'uso commerciale ammesso per le sorgenti di Python e Node.js (GitHub Advisory Database), senza nominare le licenze. Per le sorgenti dei sistemi operativi non c'è alcuna indicazione | Letto: <https://trivy.dev/latest/docs/scanner/vulnerability/> |

### Conseguenze per il piano

- **E-02, E-03 (adattatori):** nessun ostacolo. I due file insieme sono meno di 5 MB compressi: la sincronizzazione è trascurabile rispetto a trivy-db e OSV. EPSS va scaricato seguendo il redirect; il vecchio host non va usato.
- **Finestra di aggiornamento:** EPSS esce una volta al giorno dopo le 13:30 UTC, KEV senza orario. Una sincronizzazione giornaliera come quella di ADR-0006 è sufficiente; lo snapshot registra `score_date` e `catalogVersion`, che identificano il contenuto meglio della data di scaricamento.
- **Integrità (ADR-0024):** nessuna delle due fonti pubblica checksum o firme. Il rischio dello snapshot avvelenato non si chiude verificando la fonte: restano TLS, i controlli di forma e di dimensione sul contenuto e, per il mirror, la firma apposta da noi.
- **Attribuzione di EPSS:** FIRST la chiede nei prodotti. Va in documentazione e, quando esiste, nella UI dove compare il punteggio (U-04, W-05).
- **Mirror (D2-05, E-05), da portare a D2-14:**
  - KEV: CC0, ridistribuibile.
  - EPSS: nessuna licenza dichiarata e nota "All Rights Reserved" sul sito. La ridistribuzione in un mirror non è concessa in modo esplicito: serve una valutazione, o si lascia EPSS fuori dal mirror.
  - OSV per PyPI e GitHub Advisory: CC-BY 4.0, ridistribuibile con attribuzione. Va chiarito quale sorgente copre npm.
  - trivy-db: le licenze dei dati aggregati non sono dichiarate nel README. Valutazione necessaria prima di ridistribuire il database.
- **Non verificato:** l'API di EPSS; i termini generali del sito FIRST (`/about/policies/terms`); il file `LICENSE` di trivy-db; le licenze delle singole sorgenti di trivy-db.

## V-06 — Misura preliminare di una scansione PR

Misurato il 2026-11-13 sulla macchina di sviluppo, con la CLI impacchettata da `package-cli.sh` al commit `2790159` (include P-07), immagini firmate sul registry locale, `--offline` con gli snapshot dei feed già in cache. Una sola esecuzione per caso: i valori indicano l'ordine di grandezza, non una media.

Differenze rispetto alla misura del Gate 1 (`gate-1.md`): i pilota sono clonati con 80 commit di storia anziché per intero, quindi gitleaks vede meno storia; bandit non riporta più B101 nei test.

### Scansione completa, per plugin

Durate in secondi, dal report. I plugin girano in parallelo dopo syft, quindi il totale è vicino a syft più il plugin più lento.

| Pilota | Totale | Finding | syft | osv-scanner | trivy | scancode | semgrep | bandit | gitleaks |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` (`aabb901`) | 15,9 | 474 | 1,2 | 13,2 | 1,3 | 12,9 | 2,8 | 1,0 | 1,0 |
| `excalidraw` (`701b901`) | 141,7 | 1.515 | 1,5 | 16,6 | 1,8 | 135,8 | 11,5 | saltato | 4,8 |
| `saleor` (`1d707dc`) | 220,8 | 436 | 1,4 | 13,2 | 2,0 | 217,8 | 5,5 | 66,9 | 12,9 |

Tutte `complete`. Rispetto al Gate 1 saleor passa da 47.718 a 436 finding e da 247,7 a 220,8 s. scancode determina il totale su due pilota su tre.

### Scansione limitata ai file di una PR

Simulata a mano: una cartella con i soli file toccati dalla PR, nella versione del commit del pilota, scansionata con la stessa CLI. La cartella non ha storia git, quindi gitleaks analizza i file e non i commit.

| Pilota | PR di riferimento | File | Totale | scancode | semgrep | bandit | gitleaks |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | #2460, commit `f8dd304`: 11 file, di cui 7 ancora presenti | 7 | 7,2 | 5,2 | 2,5 | 0,7 | 0,7 |
| `excalidraw` | #12516, commit `dd2f8fc` | 16 | 23,9 | 22,0 | 3,9 | saltato | 0,8 |
| `saleor` | #19969, commit `0e3fa1b` | 7 | 7,2 | 5,4 | 2,5 | 0,8 | 0,7 |

In questa simulazione anche syft, osv-scanner e trivy hanno visto solo i file della PR: i loro valori non servono e non sono riportati.

### Quali plugin si possono restringere

| Plugin | Si restringe ai file cambiati? | Motivo |
| --- | --- | --- |
| bandit, semgrep | Sì | Regole su un file alla volta. Un file cambiato può però spostare un finding in un file non cambiato solo con regole tra file, che i motori usati non hanno |
| scancode, licenze dei file | Sì | La licenza rilevata in un file dipende solo dal file |
| scancode, licenze dei componenti | No | Legge l'SBOM dell'intero repository |
| syft | No | L'SBOM descrive tutto il repository; un manifest cambiato può essere ovunque |
| osv-scanner, trivy | No | Leggono manifest e lockfile dell'intero repository. Costano poco: da 1,3 a 2,0 s trivy, da 13 a 17 s osv-scanner, quasi tutti di caricamento del database |
| gitleaks | Non per file: per intervallo di commit | In una PR vanno analizzati i commit della PR, non i file nello stato finale: un segreto aggiunto e tolto nella stessa PR resta nella storia |

### Stima della scansione PR e margine

Stima: syft completo, poi in parallelo osv-scanner e trivy completi e gli altri ristretti; si aggiunge lo scarto tra totale e plugin misurato nella scansione completa (da 1,5 a 4,4 s).

| Pilota | Plugin più lento | Stima | Scansione completa | Margine sotto 600 s |
| --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | osv-scanner, 13,2 s | circa 16 s | 15,9 s | circa 584 s |
| `excalidraw` | scancode sui file della PR, 22,0 s | circa 28 s | 141,7 s | circa 572 s |
| `saleor` | osv-scanner, 13,2 s | circa 16 s | 220,8 s | circa 584 s |

### Cosa ne segue per ADR-0025

- **G2.d è già soddisfatta senza restringere nulla:** la scansione completa più lenta dura 221 s. La restrizione ai file cambiati riduce saleor da 221 a circa 16 s, ma non serve a rispettare i 10 minuti.
- **Scansionare anche il branch base nello stesso job è sostenibile:** costa una scansione completa in più, al massimo 221 s sui pilota. Base completo più PR ristretta: circa 240 s su saleor. Base e PR entrambi completi: circa 440 s, ancora sotto i 600 s ma con poco margine.
- **Il collo di bottiglia è scancode,** non gli scanner di sicurezza: 136 e 218 s sui due pilota grandi. È anche il plugin che guadagna di più dalla restrizione.
- **osv-scanner ha un costo fisso di circa 13 s** indipendente dal repository: è il pavimento di ogni scansione PR finché gira per intero.
- **Limiti di questa misura:** mancano i plugin della Fase 2 (ruff, eslint, checkov, hadolint, coverage) e `ca-graph`, che deve vedere tutto il repository; la restrizione è simulata copiando i file, non con la modalità `--pr`; una sola esecuzione; storia git ridotta. X-05 rimisura con la modalità reale e la regola del Gate 1.

## V-07 — tree-sitter sui pilota

Misurato il 2026-11-13 con codice usa e getta fuori dal repository. tree-sitter 0.26.1, tree-sitter-python 0.25.0, tree-sitter-javascript 0.25.0, tree-sitter-typescript 0.23.2, installati dalle wheel per Python 3.14 ed eseguiti nell'immagine `python:3.14-slim-trixie` con `--network none`, file system in sola lettura, utente 65534, 1 CPU, workspace montato in sola lettura. Esclusi `.git`, `node_modules`, `.venv`, `dist`, `build`.

Risponde anche a due dubbi di V-01: le wheel si installano e funzionano su Python 3.14, e la grammatica TypeScript del 2024 (ABI 14) si carica con tree-sitter 0.26.1 (le altre due sono ABI 15).

### Tempo, memoria, errori

Il tempo comprende il parsing e una visita completa dell'albero in Python, che è la parte più lenta; il solo parsing del file più costoso è indicato a parte.

| Pilota | Linguaggio | File | Dimensione | Tempo | Nodi | File con errori | Parsing più lento |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | Python | 43 | 91 KB | 0,02 s | 25 mila | 0 | 2 ms |
| | TypeScript | 39 | 133 KB | 0,03 s | 37 mila | 0 | 1 ms |
| | TSX | 70 | 185 KB | 0,04 s | 44 mila | 0 | 2 ms |
| `excalidraw` | JavaScript | 28 | 128 KB | 0,03 s | 31 mila | 0 | 3 ms |
| | TypeScript | 372 | 5,3 MB | 0,75 s | 846 mila | 2 | 11 ms |
| | TSX | 323 | 3,4 MB | 0,82 s | 949 mila | 3 | 30 ms (`App.tsx`, 371 KB) |
| `saleor` | Python | 4.384 | 28,3 MB | 5,54 s | 6,05 milioni | 0 | 19 ms |

Memoria massima del processo: 26 MB su fastapi, 42 MB su excalidraw, 36 MB su saleor. Il file più grande è `woff2-wasm.ts` di excalidraw, 972 KB di dati incorporati: si analizza senza problemi.

### Errori di parsing

5 file su 5.259, tutti in excalidraw, tutti file di test e tutti per lo stesso costrutto: un argomento di tipo `typeof import("...")` in una chiamata, per esempio `importOriginal<typeof import("../src/binding")>()`. La grammatica 0.23.2 non lo riconosce. L'errore resta locale: il resto del file viene analizzato e gli `import` in cima al file sono letti.

Per il grafo delle dipendenze la conseguenza è piccola, perché quel costrutto è un riferimento di tipo dentro un test. Ma mostra il rischio di una grammatica ferma dal 2024: la sintassi nuova di TypeScript produce errori. `ca-graph` deve trattare un file con errori come analizzato in parte e contarlo nel report, non scartarlo né fallire.

### Import non risolvibili staticamente

Conteggi delle forme di import trovate. "Calcolato" significa che l'argomento non è una stringa letterale.

| Caso | fastapi | excalidraw | saleor | Trattamento proposto per ADR-0020 |
| --- | --- | --- | --- | --- |
| Import relativi | 93 (JS/TS) | 3.027 | 16.431 (Python) | Risolvibili dal percorso |
| Import assoluti di Python | 191 | — | 10.051 | Risolvibili se la radice del pacchetto è nota; altrimenti dipendenza esterna |
| Import "nudi" di JS/TS | 198 | 2.151 | — | Esterni, salvo gli alias sotto |
| Alias di `tsconfig` (`paths`) | 203 con prefisso `@/`, dichiarato in `frontend/tsconfig.json` | Alias `@excalidraw/*` in `tsconfig.json` e `packages/tsconfig.base.json`: sono tra gli import nudi | — | **Senza leggere `paths` più della metà degli import interni di fastapi e una parte di quelli di excalidraw risulta esterna.** Va letto `tsconfig.json`, che è un file del repository e quindi un dato non fidato |
| `require` con stringa | — | 52 | — | Come un import |
| `require` calcolato | — | 7, negli script di rilascio | — | Non risolvibile: arco mancante, contato |
| `import()` dinamico con stringa | — | 26 | — | Risolvibile; arco marcato come dinamico |
| `import()` dinamico calcolato | — | 2 (per esempio `` import(`./locales/${code}.json`) ``) | — | Non risolvibile: contato |
| `importlib.import_module` calcolato | 0 | — | 4 (caricamento di plugin e scheduler) | Non risolvibile: contato |
| Cartelle con file Python senza `__init__.py` | 4 | — | 10 | Pacchetti impliciti: la risoluzione non può richiedere `__init__.py` |

Il terzo `import()` "calcolato" contato dallo script su excalidraw è in realtà letterale, preceduto da un commento: errore dello script di misura, corretto a mano nella tabella.

### Cosa ne segue per ADR-0020

- **Prestazioni:** non sono un vincolo. Il pilota più grande si analizza in meno di 6 secondi con una visita completa in Python e 36 MB di memoria. Limiti di risorse stretti per l'estrazione sono realistici.
- **Isolamento:** l'estrazione ha funzionato con le stesse restrizioni dei plugin (senza rete, sola lettura, utente non privilegiato, nessuna capability). Eseguirla in un container come un plugin non costa in tempo più dell'avvio del container.
- **Alias di `tsconfig`:** vanno risolti, o il grafo dei progetti TypeScript perde gran parte degli archi interni. È il punto più importante emerso.
- **Archi mancanti:** import calcolati e caricamenti dinamici sono pochi (da 0 a 7 per pilota) ma esistono: il grafo dichiara quanti ne ha saltati.
- **Limiti di questa misura:** nessuna risoluzione degli import è stata implementata, solo il conteggio delle forme; `extends` tra file `tsconfig`, i workspace dei monorepo e le riesportazioni non sono stati esaminati.
