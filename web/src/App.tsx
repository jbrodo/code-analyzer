import { useEffect, useState } from "react";

import type { Schemas } from "@/api/client";
import { SessionProvider, useSession } from "@/auth/session";

/** Guscio della SPA: accesso e barra superiore. Le viste arrivano con W-04..W-07. */
export function App() {
  return (
    <SessionProvider>
      <Shell />
    </SessionProvider>
  );
}

function Shell() {
  const session = useSession();
  const [me, setMe] = useState<Schemas["Me"] | null>(null);
  const client = session.status === "signed-in" ? session.client : null;

  useEffect(() => {
    if (client === null) return;
    const controller = new AbortController();
    client
      .me(controller.signal)
      .then(setMe)
      .catch(() => undefined); // l'errore di sessione lo gestisce il provider; qui basta non mostrare l'utente
    return () => {
      controller.abort();
    };
  }, [client]);

  return (
    <>
      <header className="topbar">
        <h1>Code Analyzer</h1>
        {me !== null && (
          <p className="topbar-user muted">
            {me.name ?? me.subject} · {me.roles.join(", ") || "nessun ruolo"}
          </p>
        )}
      </header>
      <main>
        {session.status === "loading" && <p role="status">Accesso in corso…</p>}
        {session.status === "error" && (
          <section aria-labelledby="signin-error">
            <h2 id="signin-error">Accesso non riuscito</h2>
            <p>
              Codice: <code>{session.code}</code>
            </p>
            <button type="button" onClick={session.retry}>
              Riprova
            </button>
          </section>
        )}
        {session.status === "signed-in" && <p className="muted">Nessun repository selezionato.</p>}
        {session.status === "signed-out" && <p>Sessione terminata.</p>}
      </main>
    </>
  );
}
