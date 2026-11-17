import { useEffect } from "react";
import { Link, Navigate } from "react-router";

import { useClient } from "@/auth/session";
import { age } from "@/lib/format";
import { useResource } from "@/lib/useResource";

export function RepositoriesPage() {
  const client = useClient();
  const [list, reload] = useResource((signal) => client.listRepositories({ limit: 100 }, signal), []);
  const now = new Date();
  useEffect(() => {
    document.title = "Repository · Code Analyzer";
  }, []);

  if (list.status === "ready" && list.data.items.length === 1 && list.data.items[0]) {
    return <Navigate to={`/r/${list.data.items[0].id}`} replace />; // un solo repository: si va alla sua lista
  }
  return (
    <main id="contenuto">
      <h1>Repository</h1>
      {list.status === "loading" && <p className="muted">Carico i repository…</p>}
      {list.status === "error" && (
        <div role="alert" className="state-text">
          <p>Elenco dei repository: richiesta non riuscita.</p>
          <p className="muted">Codice: <code>{list.error.code}</code></p>
          <button type="button" className="button" onClick={reload}>Riprova</button>
        </div>
      )}
      {list.status === "ready" && list.data.items.length === 0 && (
        <div className="state-text">
          <p>Nessun repository.</p>
          <p className="muted">Le scansioni arrivano dalla CI con <code>code-analyzer upload</code>.</p>
        </div>
      )}
      {list.status === "ready" && list.data.items.length > 1 && (
        <ul className="repo-list">
          {list.data.items.map((repo) => (
            <li key={repo.id}>
              <Link to={`/r/${repo.id}`}>{repo.name}</Link>
              <span className="muted">
                {repo.current_scan
                  ? `${repo.current_scan.status === "partial" ? "Parziale" : "Completa"}, ${age(repo.current_scan.started_at, now)} fa`
                  : "Nessuna scansione"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
