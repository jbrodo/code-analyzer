import { useEffect, useRef, useState } from "react";
import { useOutletContext, useParams } from "react-router";

import type { Schemas } from "@/api/client";
import { useClient } from "@/auth/session";
import { LevelBadge } from "@/components/LevelBadge";
import { CATEGORY_LABEL, STATUS_LABEL, dateTime, location } from "@/lib/format";
import { useResource } from "@/lib/useResource";
import type { Resource } from "@/lib/useResource";
import { ScoreSection } from "./ScoreSection";
import { TriageActions } from "./TriageActions";

type Detail = Schemas["FindingDetail"];

export interface PanelContext {
  /** Chiude il pannello e riporta il fuoco alla riga di partenza (D2). */
  close: (findingId: string) => void;
  /** Dopo un'azione di triage: la riga della lista segue il nuovo stato senza ricaricare. */
  changed: (detail: Schemas["FindingDetail"]) => void;
}

const REMEDIATION_SOURCE: Record<Schemas["RemediationSource"], string> = {
  tool: "Indicazione dello strumento",
  rule: "Indicazione della regola del prodotto",
  derived: "Indicazione ricavata dal prodotto",
};

function Time({ value }: { value: string }) {
  return <time dateTime={value}>{dateTime(value)}</time>;
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section aria-labelledby={id} className="panel-section">
      <h3 id={id}>{title}</h3>
      {children}
    </section>
  );
}

function Remediation({ finding }: { finding: Schemas["Finding"] }) {
  const fix = finding.remediation;
  if (!fix) {
    return (
      <>
        <p>Questo strumento non fornisce indicazioni di correzione.</p>
        <p className="muted">
          Regola: <span className="mono">{finding.rule_id}</span>
        </p>
      </>
    );
  }
  return (
    <>
      <p className="remediation">{fix.text}</p>
      <p className="muted">{REMEDIATION_SOURCE[fix.source]}</p>
      {fix.references && fix.references.length > 0 && (
        <ul className="references">
          {/* riferimenti mostrati per esteso e non attivi: il contenuto del report non genera collegamenti */}
          {fix.references.map((ref) => (
            <li key={ref} className="mono">{ref}</li>
          ))}
        </ul>
      )}
    </>
  );
}

function Where({ detail }: { detail: Detail }) {
  const { finding, occurrence } = detail;
  const loc = finding.location;
  const place = location(loc.path, loc.start_line);
  return (
    <dl className="defs">
      {place && (<><dt>Posizione</dt><dd className="mono">{loc.end_line && loc.end_line !== loc.start_line ? `${place}–${String(loc.end_line)}` : place}</dd></>)}
      {loc.purl && (<><dt>Pacchetto</dt><dd className="mono">{loc.purl}</dd></>)}
      {loc.dependency_path && loc.dependency_path.length > 0 && (
        <><dt>Catena di dipendenze</dt><dd className="mono">{loc.dependency_path.join(" → ")}</dd></>
      )}
      {finding.license_spdx && (<><dt>Licenza (SPDX)</dt><dd className="mono">{finding.license_spdx}</dd></>)}
      {occurrence?.commit && (<><dt>Commit della scansione</dt><dd className="mono">{occurrence.commit}</dd></>)}
      {finding.cve && finding.cve.length > 0 && (<><dt>CVE</dt><dd className="mono">{finding.cve.join(", ")}</dd></>)}
      {finding.cwe && finding.cwe.length > 0 && (<><dt>CWE</dt><dd className="mono">{finding.cwe.join(", ")}</dd></>)}
      <dt>Strumenti</dt>
      <dd>{finding.tools.join(", ")}</dd>
      <dt>Fingerprint</dt>
      <dd className="mono">{finding.fingerprint}</dd>
    </dl>
  );
}

function History({ detail }: { detail: Detail }) {
  const { finding, exceptions = [], events = [] } = detail;
  return (
    <>
      <dl className="defs">
        <dt>Stato</dt>
        <dd>{STATUS_LABEL[finding.status]}</dd>
        <dt>Assegnato a</dt>
        <dd>{finding.owner ?? "—"}</dd>
        {finding.due_date && (<><dt>Scadenza</dt><dd><Time value={finding.due_date} /></dd></>)}
        <dt>Prima rilevazione</dt>
        <dd><Time value={finding.first_seen} /></dd>
        <dt>Ultima rilevazione</dt>
        <dd><Time value={finding.last_seen} /></dd>
      </dl>
      {finding.status === "risolto" && (
        <p className="muted">«Risolto» lo assegna il server quando il finding non compare più in una scansione completa.</p>
      )}
      <h4>Eccezioni</h4>
      {exceptions.length === 0 ? (
        <p className="muted">Nessuna eccezione.</p>
      ) : (
        <ul className="exceptions">
          {exceptions.map((ex) => (
            <li key={ex.id}>
              {ex.origin === "server" ? (
                <p>Accettato da {ex.approved_by} fino al <Time value={ex.expires} />.</p>
              ) : (
                <p>
                  Accettato nel repository (<span className="mono">.code-analyzer.yml</span>) fino al <Time value={ex.expires} />.
                  Approvatore dichiarato: {ex.approved_by}, non verificato.
                </p>
              )}
              <p className="muted">Motivazione: {ex.reason}</p>
              {ex.revoked_at && <p className="muted">Revocata il <Time value={ex.revoked_at} />.</p>}
              {!ex.revoked_at && new Date(ex.expires) < new Date() && <p className="muted">Scaduta.</p>}
            </li>
          ))}
        </ul>
      )}
      <h4>Registro delle modifiche</h4>
      {events.length === 0 ? (
        <p className="muted">Nessuna modifica registrata.</p>
      ) : (
        <ol className="events">
          {events.map((ev, index) => (
            <li key={`${ev.at}-${String(index)}`}>
              <Time value={ev.at} /> · {ev.actor} · {ev.action}
              {ev.from_state && ev.to_state ? ` (${STATUS_LABEL[ev.from_state]} → ${STATUS_LABEL[ev.to_state]})` : ""}
              {ev.reason ? <span className="muted"> — {ev.reason}</span> : null}
            </li>
          ))}
        </ol>
      )}
    </>
  );
}

export function FindingPanel() {
  const { finding: id = "" } = useParams();
  const client = useClient();
  const { close, changed } = useOutletContext<PanelContext>();
  const title = useRef<HTMLHeadingElement>(null);
  const [loaded] = useResource((signal) => client.getFinding(id, signal), [id]);
  // dopo un'azione il pannello mostra la risposta del server, finché non cambia finding
  const [updated, setUpdated] = useState<Detail | null>(null);
  const detail: Resource<Detail> = updated?.finding.id === id ? { status: "ready", data: updated } : loaded;

  // D2: all'apertura il fuoco va al titolo del pannello
  useEffect(() => {
    if (detail.status === "ready") title.current?.focus();
  }, [detail.status, id]);

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape" && !event.defaultPrevented) {
      event.stopPropagation();
      close(id);
    }
  };

  if (detail.status === "loading") {
    return (
      <aside className="panel" aria-busy="true" aria-label="Dettaglio del finding">
        <div className="panel-body"><span className="skeleton-bar" /><span className="skeleton-bar" /></div>
      </aside>
    );
  }
  if (detail.status === "error") {
    return (
      <aside className="panel" aria-label="Dettaglio del finding" onKeyDown={onKeyDown}>
        <div className="panel-body" role="alert">
          <p>{detail.error.status === 404 ? "Finding non trovato o non più presente." : "Dettaglio del finding: richiesta non riuscita."}</p>
          <p className="muted">Codice: <code>{detail.error.code}</code></p>
          <button type="button" className="button" onClick={() => { close(id); }}>Torna alla lista</button>
        </div>
      </aside>
    );
  }

  const data = detail.data;
  const f = data.finding;
  const scores = data.occurrence?.variant_scores ?? [];
  return (
    <aside className="panel" aria-labelledby="panel-title" onKeyDown={onKeyDown}>
      <header className="panel-head">
        <button type="button" className="button back" onClick={() => { close(id); }}>
          <span className="back-narrow">Torna alla lista</span>
          <span className="back-wide">Chiudi</span>
        </button>
        <p className="panel-meta">
          <LevelBadge level={f.level} />
          <span>{CATEGORY_LABEL[f.category]}</span>
          <span>{STATUS_LABEL[f.status]}</span>
          {f.baseline_state === "new" && <strong className="new">Nuovo</strong>}
        </p>
        <h2 id="panel-title" tabIndex={-1} ref={title}>{f.title}</h2>
        <p className="mono muted">{f.rule_id}</p>
      </header>
      {/* regione scorrevole raggiungibile da tastiera: senza un punto di fuoco non si potrebbe scorrere */}
      <div className="panel-body" tabIndex={0} role="region" aria-label="Contenuto del finding">
        <Section id="sec-fix" title="Come risolvere"><Remediation finding={f} /></Section>
        <Section id="sec-where" title="Dove"><Where detail={data} /></Section>
        <Section id="sec-why" title="Perché questo livello">
          <ScoreSection level={f.level} source={f.level_source} scores={scores} />
        </Section>
        <Section id="sec-history" title="Stato e storia"><History detail={data} /></Section>
      </div>
      <TriageActions
        detail={data}
        onChanged={(next) => {
          setUpdated(next);
          changed(next);
        }}
      />
    </aside>
  );
}
