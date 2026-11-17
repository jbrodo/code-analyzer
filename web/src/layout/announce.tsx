import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

/** La regione di stato unica della pagina (U-02): i componenti vi scrivono gli annunci. */
const INVISIBLE = String.fromCharCode(0x200b);
const Announce = createContext<(message: string) => void>(() => undefined);

export const useAnnounce = () => useContext(Announce);

export function AnnounceProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState("");
  const announce = useCallback((text: string) => {
    // lo stesso testo due volte di fila deve essere riannunciato: si alterna un carattere invisibile
    setMessage((previous) => (previous === text ? text + INVISIBLE : text));
  }, []);
  const value = useMemo(() => announce, [announce]);
  return (
    <Announce.Provider value={value}>
      {children}
      <div role="status" className="visually-hidden">
        {message}
      </div>
    </Announce.Provider>
  );
}
