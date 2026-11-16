# quality-js-ts (fixture F-02 della Fase 2)

Repository di prova con problemi di qualita' noti per eslint con typescript-eslint, su JS, TS e
TSX. **Non va installato ne' eseguito.** Nessuna dipendenza e nessun problema di sicurezza.

I problemi attesi sono in `expected-findings.yaml`; comando, versioni e configurazione di prova
sono in testa a quel file.

| Percorso | Cosa contiene |
| --- | --- |
| `src/plain.js` | Una funzione che supera con margine le soglie di complessita', parametri e annidamento |
| `src/model.ts` | `any` esplicito, variabile non usata, blocco `catch` vuoto |
| `src/view.tsx` | Variabile non usata in un componente |
| `src/clean.ts` | Nessun problema: caso negativo |
