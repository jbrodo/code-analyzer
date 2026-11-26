// Configurazione di eslint della modalità benchmark (ADR-0023, K-06). La sceglie l'adattatore solo
// con `{"benchmark": true}` in `/inputs/config.json`, che scrive l'host e mai il repository. Le sole
// regole con una metrica, con soglia zero: ogni funzione (o blocco, per `max-depth`) dà un risultato
// con il suo valore. Stesso parser e stessi file della configurazione normale.
import tseslint from "typescript-eslint";

const SOURCE = ["**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx}"];

export default tseslint.config(
  { ignores: ["**/node_modules/**", "**/.git/**"] },
  {
    files: SOURCE,
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    rules: {
      complexity: ["warn", { max: 0 }],
      "max-params": ["warn", { max: 0 }],
      "max-depth": ["warn", { max: 0 }],
      "max-lines-per-function": ["warn", { max: 0 }],
    },
  },
);
