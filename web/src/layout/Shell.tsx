import { useEffect, useState } from "react";
import { Link, Route, Routes, useMatch, useNavigate } from "react-router";

import type { Schemas } from "@/api/client";
import { useClient } from "@/auth/session";
import { FindingPanel } from "@/features/finding/FindingPanel";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { RepositoriesPage } from "@/features/repositories/RepositoriesPage";
import { age } from "@/lib/format";
import { MeContext } from "./me";
import { useResource } from "@/lib/useResource";

function RepositorySelect({ current }: { current: string | null }) {
  const client = useClient();
  const navigate = useNavigate();
  const [list] = useResource((signal) => client.listRepositories({ limit: 100 }, signal), []);
  const items = list.status === "ready" ? list.data.items : [];
  return (
    <div className="field field-inline">
      <label htmlFor="repository-select">Repository</label>
      <select
        id="repository-select"
        value={current ?? ""}
        disabled={items.length === 0}
        onChange={(event) => {
          if (event.target.value !== "") void navigate(`/r/${event.target.value}`);
        }}
      >
        {current === null && <option value="">Scegli…</option>}
        {items.map((repo) => (
          <option key={repo.id} value={repo.id}>{repo.name}</option>
        ))}
      </select>
    </div>
  );
}

/** Lo stato dell'ultima scansione, sempre visibile nella barra (U-01): collegamento alla scansione. */
function ScanStatus({ repository }: { repository: string }) {
  const client = useClient();
  const [repo] = useResource((signal) => client.getRepository(repository, signal), [repository]);
  const [now] = useState(() => new Date());
  if (repo.status !== "ready") return null;
  const scan: Schemas["ScanSummary"] | null | undefined = repo.data.current_scan;
  if (scan === null || scan === undefined) return <p className="scan-status muted">Nessuna scansione</p>;
  return (
    <p className="scan-status">
      <Link to={`/r/${repository}/scans/${scan.id}`}>
        <span data-partial={scan.status === "partial"}>{scan.status === "partial" ? "Parziale" : "Completa"}</span>
        {" · "}
        <span className="mono">{scan.commit.slice(0, 7)}</span>
        {" · "}
        {age(scan.started_at, now)} fa
      </Link>
    </p>
  );
}

export function Shell() {
  const client = useClient();
  const match = useMatch("/r/:repository/*");
  const repository = match?.params.repository ?? null;
  const [me, setMe] = useState<Schemas["Me"] | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    client.me(controller.signal).then(setMe).catch(() => undefined);
    return () => {
      controller.abort();
    };
  }, [client]);

  return (
    <>
      <a className="skip-link" href="#contenuto">Vai al contenuto</a>
      <header className="topbar">
        <Link to="/" className="brand">Code Analyzer</Link>
        <RepositorySelect current={repository} />
        {repository !== null && <ScanStatus repository={repository} />}
        {me !== null && (
          <p className="topbar-user">
            {me.name ?? me.subject}
            <span className="muted"> · {me.roles.join(", ") || "nessun ruolo"}</span>
          </p>
        )}
      </header>
      <MeContext.Provider value={me}>
      <Routes>
        <Route path="/" element={<RepositoriesPage />} />
        <Route path="/r/:repository" element={<FindingsPage />}>
          <Route path="f/:finding" element={<FindingPanel />} />
        </Route>
        <Route
          path="*"
          element={
            <main id="contenuto">
              <h1>Pagina non trovata</h1>
              <p><Link to="/">Torna ai repository</Link></p>
            </main>
          }
        />
      </Routes>
      </MeContext.Provider>
    </>
  );
}
