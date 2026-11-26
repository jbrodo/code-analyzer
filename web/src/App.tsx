import { BrowserRouter } from "react-router";

import { SessionProvider, useSession } from "@/auth/session";
import { AnnounceProvider } from "@/layout/announce";
import { Shell } from "@/layout/Shell";

/** La SPA: accesso, poi le viste. Fuori da una sessione aperta si vede solo lo stato dell'accesso. */
export function App() {
  return (
    <SessionProvider>
      <AnnounceProvider>
        <Gate />
      </AnnounceProvider>
    </SessionProvider>
  );
}

function Gate() {
  const session = useSession();
  if (session.status === "signed-in") {
    return (
      <BrowserRouter>
        <Shell />
      </BrowserRouter>
    );
  }
  return (
    <>
      <header className="topbar">
        <span className="brand">Code Analyzer</span>
      </header>
      <main id="contenuto">
        <h1>Code Analyzer</h1>
        {session.status === "loading" && <p className="muted">Accesso in corso…</p>}
        {session.status === "error" && (
          <section aria-labelledby="signin-error" className="state-text" role="alert">
            <h2 id="signin-error">Accesso non riuscito</h2>
            <p>Codice: <code>{session.code}</code></p>
            <button type="button" className="button" onClick={session.retry}>Riprova</button>
          </section>
        )}
        {session.status === "signed-out" && <p>Sessione terminata.</p>}
      </main>
    </>
  );
}
