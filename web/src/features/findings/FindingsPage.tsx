import { useEffect, useMemo, useRef, useState } from "react";
import { Link, Outlet, useNavigate, useParams, useSearchParams } from "react-router";

import { ApiError } from "@/api/client";
import type { Schemas } from "@/api/client";
import { useClient } from "@/auth/session";
import { useAnnounce } from "@/layout/announce";
import { dateTime } from "@/lib/format";
import { useResource } from "@/lib/useResource";
import { FilterBar } from "./FilterBar";
import { FindingsTable } from "./FindingsTable";
import { activeFilterCount, parseFilters, toParams, toQuery } from "./filters";
import type { Filters } from "./filters";

type Item = Schemas["FindingListItem"];
const PAGE = 50;

function ErrorText({ error, retry, what }: { error: ApiError; retry: () => void; what: string }) {
  const text =
    error.status === 403
      ? "Non hai accesso a questo repository."
      : error.status === 404
        ? `${what} non trovato o non più presente.`
        : `${what}: richiesta non riuscita.`;
  return (
    <div role="alert" className="state-text">
      <p>{text}</p>
      <p className="muted">
        Codice: <code>{error.code}</code>
      </p>
      {error.status !== 403 && error.status !== 404 && (
        <button type="button" className="button" onClick={retry}>Riprova</button>
      )}
    </div>
  );
}

/** Fascia sopra la lista finché la scansione corrente è parziale (U-01 §4.4, L14). */
function PartialBanner({ repositoryId, scan }: { repositoryId: string; scan: Schemas["ScanSummary"] }) {
  const client = useClient();
  const [detail] = useResource((signal) => client.getScan(scan.id, signal), [scan.id]);
  const failed = detail.status === "ready" ? detail.data.plugins.filter((p) => p.outcome === "failed") : [];
  return (
    <p className="banner" data-tone="warn">
      <strong>Scansione parziale.</strong>{" "}
      {detail.status === "ready"
        ? `${String(failed.length)} ${failed.length === 1 ? "plugin non riuscito" : "plugin non riusciti"}${failed.length > 0 ? ` (${failed.map((p) => p.name).join(", ")})` : ""}. `
        : ""}
      I finding di questi strumenti non sono aggiornati. Nessun finding è stato segnato come risolto da questa scansione.{" "}
      <Link to={`/r/${repositoryId}/scans/${scan.id}`}>Vai alla scansione</Link>
    </p>
  );
}

export function FindingsPage() {
  const { repository = "", finding = null } = useParams();
  const client = useClient();
  const navigate = useNavigate();
  const announce = useAnnounce();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseFilters(params), [params]);
  const query = useMemo(() => toQuery(filters), [filters]);
  const searchRef = useRef<HTMLInputElement>(null);
  const [now] = useState(() => new Date());

  const [repo, reloadRepo] = useResource((signal) => client.getRepository(repository, signal), [repository]);
  const [first, reloadFirst] = useResource(
    (signal) => client.listFindings(repository, { ...query, limit: PAGE }, signal),
    [repository, query],
  );

  // pagine successive, legate alla richiesta della prima: cambiando filtri si ricomincia
  const key = JSON.stringify([repository, query]);
  const [more, setMore] = useState<{ key: string; items: Item[]; cursor: string | null; failed: boolean } | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const extra = more?.key === key ? more : null;

  const firstData = first.status === "ready" ? first.data : null;
  const items: readonly Item[] = firstData ? [...firstData.items, ...(extra?.items ?? [])] : [];
  const cursor = extra ? extra.cursor : (firstData?.next_cursor ?? null);

  useEffect(() => {
    document.title = `Finding · ${repo.status === "ready" ? repo.data.name : "repository"} · Code Analyzer`;
  }, [repo]);

  const announced = useRef("");
  useEffect(() => {
    if (firstData === null) return;
    const text = `${String(firstData.total)} finding con i filtri attivi`;
    if (announced.current !== text) {
      announced.current = text;
      announce(text);
    }
  }, [firstData, announce]);

  const change = (next: Filters) => {
    setParams(toParams(next), { replace: true });
  };

  const loadMore = () => {
    if (cursor === null) return;
    setLoadingMore(true);
    client
      .listFindings(repository, { ...query, limit: PAGE, cursor })
      .then((page) => {
        setMore({ key, items: [...(extra?.items ?? []), ...page.items], cursor: page.next_cursor ?? null, failed: false });
        announce(`${String(page.items.length)} finding aggiunti, ${String(items.length + page.items.length)} di ${String(firstData?.total ?? 0)}`);
      })
      .catch(() => {
        setMore({ key, items: extra?.items ?? [], cursor, failed: true });
      })
      .finally(() => {
        setLoadingMore(false);
      });
  };

  if (repo.status === "error") {
    return <main><ErrorText error={repo.error} retry={reloadRepo} what="Repository" /></main>;
  }

  const current = repo.status === "ready" ? repo.data.current_scan : undefined;
  const filtered = activeFilterCount(filters) > 0;
  const hrefFor = (id: string) => `/r/${repository}/f/${id}${params.size > 0 ? `?${params.toString()}` : ""}`;
  const loading = first.status === "loading";

  let empty: React.ReactNode = null;
  if (first.status === "error") {
    empty = <ErrorText error={first.error} retry={reloadFirst} what="Elenco dei finding" />;
  } else if (repo.status === "ready" && current === null) {
    empty = (
      <div className="state-text">
        <p>Nessuna scansione ricevuta per questo repository.</p>
        <p className="muted">Le scansioni arrivano dalla CI con <code>code-analyzer upload</code>.</p>
      </div>
    );
  } else if (firstData !== null && items.length === 0) {
    empty = filtered ? (
      <div className="state-text">
        <p>Nessun finding con questi filtri.</p>
        <p className="muted">Cambia i filtri o usa “Azzera filtri” qui sopra.</p>
      </div>
    ) : (
      <div className="state-text">
        <p>Nessun finding aperto.</p>
        {current ? (
          <p className="muted">
            Ultima scansione: {current.status === "partial" ? "parziale" : "completa"}, {dateTime(current.started_at)}.
            {current.status === "partial" ? " Zero finding da una scansione parziale non è una buona notizia." : ""}
          </p>
        ) : null}
      </div>
    );
  }

  const caption = `Finding di ${repo.status === "ready" ? repo.data.name : "…"}${firstData ? `, ${String(firstData.total)} con i filtri attivi` : ""}`;
  const footer =
    cursor !== null || (extra?.failed ?? false) ? (
      <div className="table-footer">
        <button type="button" className="button" onClick={loadMore} disabled={loadingMore}>
          {loadingMore ? "Carico…" : "Carica altri"}
        </button>
        <span className="muted">{String(items.length)} di {String(firstData?.total ?? 0)}</span>
        {extra?.failed === true && <span role="alert" className="error-text">Caricamento non riuscito. Riprova.</span>}
      </div>
    ) : firstData && items.length > 0 ? (
      <div className="table-footer"><span className="muted">{String(items.length)} di {String(firstData.total)}</span></div>
    ) : null;

  return (
    <div className="findings-page" data-panel={finding !== null ? "open" : "closed"}>
      <main className="list-column" id="contenuto">
        <h1 className="page-title">
          {repo.status === "ready" ? repo.data.name : "Repository"}
          <span className="muted"> · Finding</span>
        </h1>
        {current?.status === "partial" && <PartialBanner repositoryId={repository} scan={current} />}
        <FilterBar
          filters={filters}
          onChange={change}
          total={firstData?.total ?? null}
          totalNew={firstData?.total_new ?? null}
          searchRef={searchRef}
        />
        <FindingsTable
          caption={caption}
          items={items}
          loading={loading}
          selectedId={finding}
          sort={filters.sort}
          now={now}
          hrefFor={hrefFor}
          onSort={(sort) => { change({ ...filters, sort }); }}
          onFocusSearch={() => { searchRef.current?.focus(); }}
          empty={empty}
          footer={footer}
        />
      </main>
      <Outlet context={{ closeTo: () => { void navigate(`/r/${repository}${params.size > 0 ? `?${params.toString()}` : ""}`); } }} />
    </div>
  );
}
