# Campioni reali dei motori della Fase 2 (V-03)

Output non modificato degli strumenti alle versioni di `doc/verifiche/scanner-fase-2.md` (V-01), prodotto il 2026-11-13 su un repository di esempio di poche righe, in container senza rete e con il workspace in sola lettura. Sono in una sottocartella perché i test della Fase 1 leggono `../*.sarif` come output già conformi al contratto dei plugin: questi sono output grezzi, da adattare. T-02 li collega all'harness di contratto.

| File | Strumento | Comando essenziale |
| --- | --- | --- |
| `ruff.sarif` | ruff 0.17.5 | `ruff check --isolated --no-cache --output-format sarif` |
| `eslint.json` | eslint 10.14.0, typescript-eslint 8.72.2, typescript 6.0.3 | `eslint --no-config-lookup -c <config dell'immagine> -f json` |
| `eslint.formatter.sarif` | come sopra, con `@microsoft/eslint-formatter-sarif` 3.1.0 | stesso comando con il formattatore |
| `checkov.sarif` | checkov 3.4.5 | `checkov -d /workspace --skip-download -o sarif` |
| `hadolint.sarif` | hadolint 2.15.1 | `hadolint -f sarif /workspace/Dockerfile` |
| `coveragepy.lcov`, `coveragepy.cobertura.xml` | coverage.py 7.17.3 con pytest 9.2.0 | `coverage lcov`, `coverage xml` |
| `vitest.lcov`, `vitest.cobertura.xml` | vitest 5.1.0 con `@vitest/coverage-v8` | `vitest run --coverage` |
| `nyc-empty.cobertura.xml` | nyc 18.0.0 su un modulo ES non strumentato | report vuoto, con `line-rate="NaN"` |
