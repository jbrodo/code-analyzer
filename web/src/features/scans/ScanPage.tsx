import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";

import type { Schemas } from "@/api/client";
import { useClient } from "@/auth/session";
import { dateTime } from "@/lib/format";
import { useResource } from "@/lib/useResource";
import { Ago, durationText, scanKind, scanStatus } from "./ScansPage";

type Detail = Schemas["ScanDetail"];

const OUTCOME: Record<Schemas["Outcome"], string> = { ok: "Riuscito", failed: "Fallito" };
const SIGNATURE: Record<Schemas["Signature"], string> = { verified: "Verificata", skipped: "Non verificata" };
const ISOLATION: Record<Schemas["Isolation"], string> = { gvisor: "gVisor", "hardened-container": "Contenitore rinforzato" };
const BASELINE_SOURCE: Record<Schemas["BaselineSourceKind"], string> = {
  "ci-artifact": "artefatto della CI",
  "base-scan": "scansione del branch base",
  server: "server",
};
const BASELINE_STATUS: Record<Schemas["BaselineStatus"], string> = {
  valid: "Valida",
  missing: "Assente",
  rejected: "Respinta",
};

function Plugins({ detail }: { detail: Detail }) {
  return (
    <div className="table-region plain" tabIndex={0} role="region" aria-label="Plugin della scansione">
      <table className="findings plugins">
        <caption>Plugin della scansione</caption>
        <thead>
          <tr>
            <th scope="col">Nome</th>
            <th scope="col">Versione</th>
            <th scope="col">Esito</th>
            <th scope="col">Motivo</th>
            <th scope="col">Durata</th>
            <th scope="col">Firma</th>
            <th scope="col">Isolamento</th>
            <th scope="col">Snapshot dei feed</th>
          </tr>
        </thead>
        <tbody>
          {detail.plugins.map((p) => (
            <tr key={`${p.name}-${p.version}`}>
              <th scope="row">{p.name}</th>
              <td className="mono">{p.version}</td>
              <td>{OUTCOME[p.outcome]}</td>
              <td className="wrap">{p.failure ?? "—"}</td>
              <td>{durationText(p.duration_seconds)}</td>
              <td>{SIGNATURE[p.signature]}</td>
              <td>{ISOLATION[p.isolation]}</td>
              <td className="wrap">
                {p.feed ? (
                  <>
                    {p.feed.origin}, <time dateTime={p.feed.synced_at}>{dateTime(p.feed.synced_at)}</time>
                    {p.feed.sync_failed ? ", sincronizzazione fallita: usato lo snapshot precedente" : ""}
                  </>
                ) : (
                  "—"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Baseline({ repository, scan, detail }: { repository: string; scan: Schemas["ScanSummary"]; detail: Detail }) {
  const b = detail.baseline;
  if (scan.kind !== "pr" || !b) return null;
  return (
    <section aria-labelledby="sec-baseline" className="scan-section">
      <h2 id="sec-baseline">Rispetto al branch base</h2>
      <dl className="defs">
        <dt>Baseline</dt>
        <dd>
          {BASELINE_STATUS[b.status]}
          {b.source ? `, da ${BASELINE_SOURCE[b.source]}` : ""}
          {b.reason ? ` (${b.reason})` : ""}
        </dd>
        {b.commit && (<><dt>Commit della baseline</dt><dd className="mono">{b.commit}</dd></>)}
        <dt>Nuovi</dt>
        <dd>{b.new}</dd>
        <dt>Esistenti</dt>
        <dd>{b.existing}</dd>
        <dt>Risolti</dt>
        <dd>{b.resolved?.length ?? 0}</dd>
        {b.not_evaluated > 0 && (<><dt>Non valutati</dt><dd>{b.not_evaluated} (il loro plugin è fallito: non sono né risolti né esistenti)</dd></>)}
      </dl>
      <p>
        {b.new === 0 ? (
          "Nessun finding nuovo in questa scansione."
        ) : (
          <Link to={`/r/${repository}?scan=${scan.id}&new=true&status=any`}>
            {b.new === 1 ? "Vedi il finding nuovo di questa scansione" : `Vedi i ${String(b.new)} finding nuovi di questa scansione`}
          </Link>
        )}
      </p>
      {b.resolved && b.resolved.length > 0 && (
        <>
          <h3>Finding risolti</h3>
          <ul>
            {b.resolved.map((r) => (
              <li key={r.fingerprint}>{r.title} <span className="mono muted">{r.rule_id}</span></li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

export function ScanPage() {
  const { repository = "", scan: scanId = "" } = useParams();
  const client = useClient();
  const [now] = useState(() => new Date());
  const [repo] = useResource((signal) => client.getRepository(repository, signal), [repository]);
  const [detail, reload] = useResource((signal) => client.getScan(scanId, signal), [scanId]);
  const name = repo.status === "ready" ? repo.data.name : "repository";

  useEffect(() => {
    document.title = `Scansione · ${name} · Code Analyzer`;
  }, [name]);

  if (detail.status === "error") {
    return (
      <main id="contenuto" className="page">
        <h1 className="page-title">{name}<span className="muted"> · Scansione</span></h1>
        <div role="alert" className="state-text">
          <p>{detail.error.status === 404 ? "Scansione non trovata." : "Scansione: richiesta non riuscita."}</p>
          <p className="muted">Codice: <code>{detail.error.code}</code></p>
          {detail.error.status !== 404 && detail.error.status !== 403 && <button type="button" className="button" onClick={reload}>Riprova</button>}
          <p><Link to={`/r/${repository}/scans`}>Torna alle scansioni</Link></p>
        </div>
      </main>
    );
  }
  if (detail.status === "loading") {
    return (
      <main id="contenuto" className="page" aria-busy="true">
        <h1 className="page-title">{name}<span className="muted"> · Scansione</span></h1>
        <span className="skeleton-bar" />
      </main>
    );
  }

  const data = detail.data;
  const scan = data.summary;
  const failed = data.plugins.filter((p) => p.outcome === "failed");
  return (
    <main id="contenuto" className="page">
      <h1 className="page-title">{name}<span className="muted"> · Scansione</span></h1>
      <p><Link to={`/r/${repository}/scans`}>Tutte le scansioni</Link> · <Link to={`/r/${repository}`}>Finding</Link></p>

      {scan.status === "partial" && (
        <p className="banner partial" data-tone="warn">
          <strong>Scansione parziale.</strong>{" "}
          {failed.length > 0 ? `Plugin non riusciti: ${failed.map((p) => p.name).join(", ")}. ` : ""}
          I finding di questi strumenti non sono aggiornati. Nessun finding è stato segnato come risolto da questa scansione.
        </p>
      )}

      <section aria-labelledby="sec-summary" className="scan-section">
        <h2 id="sec-summary">Riepilogo</h2>
        <dl className="defs">
          <dt>Tipo</dt><dd>{scanKind(scan)}</dd>
          <dt>Stato</dt><dd>{scanStatus(scan)}</dd>
          {scan.ref && (<><dt>Ref</dt><dd className="mono">{scan.ref}</dd></>)}
          <dt>Commit</dt><dd className="mono">{scan.commit}</dd>
          <dt>Inizio</dt><dd><Ago value={scan.started_at} now={now} /></dd>
          <dt>Durata</dt><dd>{durationText(scan.duration_seconds)}</dd>
          <dt>Gate</dt>
          <dd>{data.gate.effective_mode === "new-findings-only" ? "Solo i finding nuovi" : "Tutti i finding"}{data.gate.mode !== data.gate.effective_mode ? " (modo ripiegato)" : ""}</dd>
          {data.scoring && (
            <>
              <dt>Configurazione di scoring</dt>
              <dd className="mono">{data.scoring.config_version}</dd>
              <dt>Variante attiva</dt>
              <dd>{data.scoring.active_variant}{data.scoring.shadow ? " (A e B in ombra: la seconda non decide il livello)" : ""}</dd>
            </>
          )}
        </dl>
      </section>

      <Baseline repository={repository} scan={scan} detail={data} />

      <section aria-labelledby="sec-plugins" className="scan-section">
        <h2 id="sec-plugins">Plugin</h2>
        {data.plugins.length === 0 ? <p className="muted">Nessun plugin registrato.</p> : <Plugins detail={data} />}
      </section>

      <section aria-labelledby="sec-warnings" className="scan-section">
        <h2 id="sec-warnings">Avvisi</h2>
        {data.warnings.length === 0 ? (
          <p className="muted">Nessun avviso.</p>
        ) : (
          <ul className="warnings">
            {data.warnings.map((w, i) => (
              <li key={`${w.code}-${String(i)}`}>
                <code>{w.code}</code>: {w.message}
                {w.subject ? <span className="muted"> ({w.subject})</span> : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
