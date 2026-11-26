import { useCallback, useState } from "react";

/** Una bozza di campo che sopravvive al giro dall'IdP quando la sessione scade (G11, SC 3.3.7).
 *
 * Sta in `sessionStorage` (per scheda, si cancella chiudendola), mai il token: solo il testo che
 * l'utente stava scrivendo. Si cancella quando il dialogo si conclude (invio riuscito o «Scarta»).
 * Se l'archivio non c'è, la bozza vive solo in memoria.
 */
const PREFIX = "ca.draft.";

function read(key: string): string {
  try {
    return window.sessionStorage.getItem(PREFIX + key) ?? "";
  } catch {
    return "";
  }
}

export function useDraft(key: string): [string, (value: string) => void, () => void] {
  const [value, setValue] = useState(() => read(key));
  const set = useCallback(
    (next: string) => {
      setValue(next);
      try {
        if (next === "") window.sessionStorage.removeItem(PREFIX + key);
        else window.sessionStorage.setItem(PREFIX + key, next);
      } catch {
        /* archivio non disponibile: la bozza resta in memoria */
      }
    },
    [key],
  );
  const clear = useCallback(() => {
    set("");
  }, [set]);
  return [value, set, clear];
}
