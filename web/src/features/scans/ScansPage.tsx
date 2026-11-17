import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import type { Schemas } from "@/api/client";
import { useClient } from "@/auth/session";
import { age, dateTime } from "@/lib/format";
import { useResource } from "@/lib/useResource";

type Scan = Schemas["ScanSummary"];
const PAGE = 50;

export function scanKind(scan: Scan): string {
  return scan.kind === "pr" ? `PR${scan.pull_request ? ` #${String(scan.pull_request)}` : ""}` : "Completa";
}

export function scanStatus(scan: Scan): string {
  return scan.status === "partial" ? "Parziale" : "Completa";
}

/** Il tempo relativo con la data esatta nell'elemento `time` (S4). */
export function Ago({ value, now }: { value: string; now: Date }) {
  return (
    <time dateTime={value} title={dateTime(value)}>
      {age(value, now)} fa
      <span className="visually-hidden"> ({dateTime(value)})</span>
    </time>
  );
}

function seconds(value: number): string {
  return value >= 60 ? `${String(Math.floor(value / 60))} min ${String(Math.round(value % 60))} s` : `${value.toFixed(1).replace(".", ",")} s`;
}
export { seconds as durationText };

export function ScansPage() {
  const { repository = "" } = useParams();
  const client = useClient();
  const [now] = useState(() => new Date());
  const [repo] = useResource((signal) => client.getRepository(repository, signal), [repository]);
  const [first, reload] = useResource((signal) => client.listScans(repository, { limit: PAGE }, signal), [repository]);
  const [more, setMore] = useState<{ repository: string; items: Scan[]; cursor: string | null } | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const extra = more?.repository === repository ? more : null;
  const firstData = first.status === "ready" ? first.data : null;
  const items = firstData ? [...firstData.items, ...(extra?.items ?? [])] : [];
  const cursor = extra ? extra.cursor : (firstData?.next_cursor ?? null);
  const name = repo.status === "ready" ? repo.data.name : "repository";

  useEffect(() => {
    document.title = `Scansioni · ${name} · Code Analyzer`;
  }, [name]);

  const loadMore = () => {
    if (cursor === null) return;
    setLoadingMore(true);
    client
      .listScans(repository, { limit: PAGE, cursor })
      .then((page) => {
        setMore({ repository, items: [...(extra?.items ?? []), ...page.items], cursor: page.next_cursor ?? null });
      })
      .catch(() => undefined)
      .finally(() => {
        setLoadingMore(false);
      });
  };

  return (
    <main id="contenuto" className="page">
      <h1 className="page-title">
        {name}
        <span className="muted"> · Scansioni</span>
      </h1>
      <p><Link to={`/r/${repository}`}>Torna ai finding</Link></p>
      {first.status === "error" && (
        <div role="alert" className="state-text">
          <p>{first.error.status === 404 ? "Repository non trovato o non più presente." : "Elenco delle scansioni: richiesta non riuscita."}</p>
          <p className="muted">Codice: <code>{first.error.code}</code></p>
          {first.error.status !== 404 && first.error.status !== 403 && <button type="button" className="button" onClick={reload}>Riprova</button>}
        </div>
      )}
      {first.status !== "error" && (
        <div className="table-region plain" tabIndex={0} role="region" aria-label="Elenco delle scansioni">
          <table className="findings scans" aria-busy={first.status === "loading"}>
            <caption>Scansioni di {name}{firstData ? `, ${String(items.length)} mostrate` : ""}</caption>
            <thead>
              <tr>
                <th scope="col">Tipo</th>
                <th scope="col">Ref</th>
                <th scope="col">Commit</th>
                <th scope="col">Inizio</th>
                <th scope="col">Durata</th>
                <th scope="col">Stato</th>
              </tr>
            </thead>
            <tbody>
              {first.status === "loading" &&
                Array.from({ length: 5 }, (_, i) => (
                  <tr key={i} className="row-skeleton" aria-hidden="true"><td colSpan={6}><span className="skeleton-bar" /></td></tr>
                ))}
              {items.map((scan) => (
                <tr key={scan.id}>
                  <td><Link to={`/r/${repository}/scans/${scan.id}`}>{scanKind(scan)}</Link></td>
                  <td className="mono">{scan.ref ?? "—"}</td>
                  <td className="mono">{scan.commit.slice(0, 7)}</td>
                  <td><Ago value={scan.started_at} now={now} /></td>
                  <td>{seconds(scan.duration_seconds)}</td>
                  <td>{scanStatus(scan)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {firstData && items.length === 0 && (
            <div className="state-text">
              <p>Nessuna scansione ricevuta per questo repository.</p>
              <p className="muted">Le scansioni arrivano dalla CI con <code>code-analyzer upload</code>.</p>
            </div>
          )}
          {cursor !== null && (
            <div className="table-footer">
              <button type="button" className="button" onClick={loadMore} disabled={loadingMore}>{loadingMore ? "Carico…" : "Carica altri"}</button>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
