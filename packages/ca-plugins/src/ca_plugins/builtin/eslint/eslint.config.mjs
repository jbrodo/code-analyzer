// Configurazione di eslint dell'immagine (P-02, ADR-0026). E' l'unica che si usa: quella del
// repository non si legge mai (`--no-config-lookup`). Regole che non richiedono informazioni di
// tipo: senza le dipendenze installate del progetto il controllo dei tipi non e' affidabile.
// Soglie: complessita' e parametri come ruff (10 e 5); annidamento e righe i valori predefiniti
// di eslint. Quando esistera' la configurazione di scoring (C-03) le passera' l'host.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

const SOURCE = ["**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx}"];

export default tseslint.config(
  { ignores: ["**/node_modules/**", "**/.git/**"] },
  {
    files: SOURCE,
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      parser: tseslint.parser,
      // Nessun `project` ne' `projectService`: il `tsconfig.json` del repository non si legge.
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    rules: {
      complexity: ["warn", { max: 10 }],
      "max-params": ["warn", { max: 5 }],
      "max-depth": ["warn", { max: 4 }],
      "max-lines-per-function": ["warn", { max: 50 }],
    },
  },
);
