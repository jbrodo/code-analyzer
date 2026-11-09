# secrets-history

Fixture di F-04 per i segreti nella storia git (ADR-0012, ADR-0008). Qui non c'e' un `.git`: un
repository annidato non e' versionabile. La storia si genera a ogni test con
`tests/fixtures/builders/secrets_history.py`, a partire dai file di `template/`.

## Storia generata

Autore `Fixture Author <fixture@example.invalid>`, date fisse a gennaio 2026, nessuna firma, ambiente
git isolato: gli SHA sono stabili (il test li fissa).

| # | Commit | Effetto |
|---|--------|---------|
| 1 | `chore: initial import` | `app/settings.py` con il segreto `PAT` |
| 2 | `feat: deploy settings` | `deploy/.env` con il segreto `GITLAB` |
| 3 | `refactor: settings read the environment` | `PAT` di nuovo, su un'altra riga |
| 4 | `fix: drop the gitlab token from the tree` | `deploy/.env` rimosso, `PAT` resta in HEAD |

Casi coperti: stesso segreto in piu commit, segreto rimosso che resta nella storia, segreto in
HEAD, clone superficiale (solo `PAT`, con `git rev-parse --is-shallow-repository` vero) e repository
di altro proprietario (`dubious ownership`, con e senza `safe.directory`).

## Segreti finti

`PAT` (regola gitleaks `github-pat`) e `GITLAB` (`gitlab-pat`) non sono nel repository in forma
completa: il costruttore li compone a runtime da un seme fisso, con prefisso del servizio scritto a
pezzi, marcatore `FAKE` e corpo pseudo-casuale riproducibile. Nessun servizio li ha emessi. I
`template/` contengono solo segnaposto `@@SECRET_<NOME>@@`. Un test cerca nei file committabili la
forma completa, sia per pattern sia per valore generato.

## Verifica con gitleaks reale

`tests/fixtures/builders/test_secrets_history.py` usa il binario indicato da `CA_GITLEAKS_BIN` (o
`gitleaks` nel `PATH`); senza binario i test che lo richiedono vengono saltati. Su un repository di
altro proprietario gitleaks esce con 0 e zero risultati se manca `safe.directory`: il test distingue
quel caso da un repository pulito dal messaggio `dubious ownership` nel log. Senza privilegi il
proprietario diverso e' simulato con `GIT_TEST_ASSUME_DIFFERENT_OWNER`, variabile che git prevede per
i propri test.
