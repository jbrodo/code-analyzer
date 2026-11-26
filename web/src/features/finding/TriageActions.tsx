import { useId, useState } from "react";

import { ApiError } from "@/api/client";
import type { Schemas } from "@/api/client";
import { ActionDialog, Field } from "@/components/ActionDialog";
import type { FieldErrors } from "@/components/ActionDialog";
import { useClient } from "@/auth/session";
import { useAnnounce } from "@/layout/announce";
import { useMe } from "@/layout/me";
import { STATUS_LABEL } from "@/lib/format";
import { canApprove, canTriage } from "@/lib/roles";
import { useDraft } from "@/lib/useDraft";

type Detail = Schemas["FindingDetail"];

interface Props {
  detail: Detail;
  /** Dopo un'azione riuscita: il dettaglio aggiornato, per il pannello e per la riga della lista. */
  onChanged: (next: Detail) => void;
}

const TODAY = () => new Date().toISOString().slice(0, 10);

/** Il frammento di `.code-analyzer.yml` che fa valere l'eccezione anche nel gate della CI (U-01 §4.2). */
export function exceptionSnippet(fingerprint: string, reason: string, expires: string, approver: string): string {
  return [
    "exceptions:",
    `  - fingerprint: ${fingerprint}`,
    `    reason: ${JSON.stringify(reason)}`,
    `    expires: ${expires === "" ? "AAAA-MM-GG" : expires}`,
    `    approved_by: ${JSON.stringify(approver)}`,
  ].join("\n");
}

function DisabledAction({ label, reason }: { label: string; reason: string }) {
  const id = useId();
  return (
    <div className="action">
      <button type="button" className="button" aria-disabled="true" aria-describedby={id}>
        {label}
      </button>
      <p id={id} className="muted action-reason">{reason}</p>
    </div>
  );
}

export function TriageActions({ detail, onChanged }: Props) {
  const client = useClient();
  const me = useMe();
  const announce = useAnnounce();
  const roles = me?.roles ?? [];
  const f = detail.finding;
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ApiError | null>(null);

  if (!canTriage(roles)) return null; // un lettore non vede la sezione
  const approver = canApprove(roles);
  const who = me?.name ?? me?.subject ?? "";
  const activeServerExceptions = (detail.exceptions ?? []).filter(
    (e) => e.origin === "server" && !e.revoked_at && new Date(e.expires) >= new Date(TODAY()),
  );
  const repositoryException = (detail.exceptions ?? []).some(
    (e) => e.origin === "repository" && !e.revoked_at && new Date(e.expires) >= new Date(TODAY()),
  );

  if (f.status === "risolto") {
    return (
      <section className="panel-actions" aria-label="Azioni">
        <p className="muted">Il finding è risolto: non si modifica. «Risolto» lo assegna il server.</p>
      </section>
    );
  }

  const apply = async (body: Parameters<typeof client.patchFinding>[1]): Promise<Detail> => {
    const next = await client.patchFinding(f.id, body);
    onChanged(next);
    announce(`Stato aggiornato: ${STATUS_LABEL[next.finding.status]}`);
    return next;
  };

  /** Un'azione immediata, senza dialogo: l'esito si vede solo dopo la risposta del server. */
  const immediate = async (body: Parameters<typeof client.patchFinding>[1]) => {
    setBusy(true);
    setFailure(null);
    try {
      await apply(body);
    } catch (cause) {
      setFailure(cause instanceof ApiError ? cause : new ApiError(0, "network-error", null));
    } finally {
      setBusy(false);
    }
  };

  const needApprover = "Serve il ruolo approvatore.";

  return (
    <section className="panel-actions" aria-label="Azioni">
      <h3 className="visually-hidden">Azioni</h3>
      <div className="actions">
        {f.status !== "in_corso" && f.status !== "accettato" && <TakeDialog detail={detail} who={who} apply={apply} />}
        <OwnerDialog detail={detail} apply={apply} />
        {approver ? <FalsePositiveDialog findingId={f.id} apply={apply} /> : <DisabledAction label="Segna come falso positivo" reason={needApprover} />}
        {f.status !== "accettato" &&
          (approver ? <ExceptionDialog detail={detail} who={who} apply={apply} /> : <DisabledAction label="Accetta con eccezione" reason={needApprover} />)}
        {(f.status === "in_corso" || f.status === "falso_positivo") && (
          <div className="action">
            <button type="button" className="button" aria-disabled={busy} onClick={() => { if (!busy) void immediate({ action: "set-status", status: "aperto" }); }}>
              Riapri
            </button>
          </div>
        )}
        {f.status === "accettato" &&
          activeServerExceptions.map((ex) =>
            approver ? (
              <div className="action" key={ex.id}>
                <button type="button" className="button" aria-disabled={busy} onClick={() => { if (!busy) void immediate({ action: "revoke-exception", exception_id: ex.id }); }}>
                  Revoca l&apos;eccezione
                </button>
              </div>
            ) : (
              <DisabledAction key={ex.id} label="Revoca l'eccezione" reason={needApprover} />
            ),
          )}
      </div>
      {f.status === "accettato" && repositoryException && activeServerExceptions.length === 0 && (
        <p className="muted">L&apos;eccezione è dichiarata nel repository: si toglie da <span className="mono">.code-analyzer.yml</span>.</p>
      )}
      {failure && (
        <div role="alert" className="dialog-error">
          <p>{failure.problem?.title ?? "Richiesta non riuscita"}</p>
          <p className="muted">Codice: <code>{failure.code}</code></p>
        </div>
      )}
    </section>
  );
}

/** Gli errori senza quello di `field`: un campo corretto non resta segnato fino al nuovo invio. */
function without(errors: FieldErrors, field: string): FieldErrors {
  if (errors[field] === undefined) return errors;
  return Object.fromEntries(Object.entries(errors).filter(([name]) => name !== field));
}

type Apply = (body: Parameters<ReturnType<typeof useClient>["patchFinding"]>[1]) => Promise<Detail>;

function TakeDialog({ detail, who, apply }: { detail: Detail; who: string; apply: Apply }) {
  const [draft, setDraft, clearDraft] = useDraft(`${detail.finding.id}:take:owner`);
  const owner = draft === "" ? (detail.finding.owner ?? who) : draft;
  const setOwner = setDraft;
  const [errors, setErrors] = useState<FieldErrors>({});
  return (
    <div className="action">
      <ActionDialog
        onFinished={clearDraft}
        trigger={<button type="button" className="button" data-tone="accent">Prendi in carico</button>}
        title="Prendi in carico"
        description="Il finding passa a «In corso» e viene assegnato."
        submitLabel="Prendi in carico"
        dirty={draft !== ""}
        validate={() => { const e = owner.trim() === "" ? { owner: "Indica chi lo prende in carico." } : null; setErrors(e ?? {}); return e; }}
        onSubmit={async () => { await apply({ action: "set-owner", owner: owner.trim() }); await apply({ action: "set-status", status: "in_corso" }); }}
        onOpenChange={(open) => { if (open) setErrors({}); }}
      >
        <Field id="owner" label="Assegnato a" required error={errors.owner}>
          {(p) => <input {...p} type="text" value={owner} maxLength={200} onChange={(e) => { setOwner(e.target.value); setErrors((now) => without(now, "owner")); }} />}
        </Field>
      </ActionDialog>
    </div>
  );
}

function OwnerDialog({ detail, apply }: { detail: Detail; apply: Apply }) {
  const [draft, setDraft, clearDraft] = useDraft(`${detail.finding.id}:assign:owner`);
  const owner = draft === "" ? (detail.finding.owner ?? "") : draft;
  const setOwner = setDraft;
  return (
    <div className="action">
      <ActionDialog
        onFinished={clearDraft}
        trigger={<button type="button" className="button">Assegna</button>}
        title="Assegna"
        description="Cambia chi si occupa del finding. Un campo vuoto toglie l'assegnazione."
        submitLabel="Assegna"
        dirty={draft !== ""}
        validate={() => null}
        onSubmit={async () => { await apply({ action: "set-owner", owner: owner.trim() === "" ? null : owner.trim() }); }}
      >
        <Field id="owner" label="Assegnato a">
          {(p) => <input {...p} type="text" value={owner} maxLength={200} onChange={(e) => { setOwner(e.target.value); }} />}
        </Field>
      </ActionDialog>
    </div>
  );
}

function FalsePositiveDialog({ findingId, apply }: { findingId: string; apply: Apply }) {
  const [reason, setReason, clearReason] = useDraft(`${findingId}:false-positive:reason`);
  const [errors, setErrors] = useState<FieldErrors>({});
  return (
    <div className="action">
      <ActionDialog
        onFinished={clearReason}
        trigger={<button type="button" className="button">Segna come falso positivo</button>}
        title="Segna come falso positivo"
        description="Il finding non si presenta più tra gli aperti. La motivazione resta nel registro."
        submitLabel="Segna come falso positivo"
        dirty={reason !== ""}
        validate={() => { const e = reason.trim() === "" ? { reason: "Scrivi la motivazione." } : null; setErrors(e ?? {}); return e; }}
        onSubmit={async () => { await apply({ action: "set-status", status: "falso_positivo", reason: reason.trim() }); }}
        onOpenChange={(open) => { if (open) setErrors({}); }}
      >
        <Field id="reason" label="Motivazione" required error={errors.reason}>
          {(p) => <textarea {...p} rows={4} value={reason} maxLength={2000} onChange={(e) => { setReason(e.target.value); setErrors((now) => without(now, "reason")); }} />}
        </Field>
      </ActionDialog>
    </div>
  );
}

function ExceptionDialog({ detail, who, apply }: { detail: Detail; who: string; apply: Apply }) {
  const [reason, setReason, clearReason] = useDraft(`${detail.finding.id}:exception:reason`);
  const [expires, setExpires, clearExpires] = useDraft(`${detail.finding.id}:exception:expires`);
  const [errors, setErrors] = useState<FieldErrors>({});
  const [copied, setCopied] = useState<string | null>(null);
  const announce = useAnnounce();
  const snippet = exceptionSnippet(detail.finding.fingerprint, reason.trim(), expires.trim(), who);

  const validate = (): FieldErrors | null => {
    const found: FieldErrors = {};
    if (reason.trim() === "") found.reason = "Scrivi la motivazione.";
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expires.trim()) || Number.isNaN(Date.parse(expires.trim()))) {
      found.expires = "Scrivi la data nel formato AAAA-MM-GG, per esempio 2027-06-30.";
    } else if (expires.trim() <= TODAY()) {
      found.expires = "La scadenza deve essere una data futura.";
    }
    setErrors(found);
    return Object.keys(found).length > 0 ? found : null;
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied("Copiato negli appunti.");
    } catch {
      setCopied("Copia non riuscita: seleziona il testo e copialo a mano.");
    }
    announce("Frammento copiato");
  };

  return (
    <div className="action">
      <ActionDialog
        onFinished={() => { clearReason(); clearExpires(); }}
        trigger={<button type="button" className="button">Accetta con eccezione</button>}
        title="Accetta con eccezione"
        description="Il finding passa a «Accettato» fino alla scadenza. Poi torna aperto."
        submitLabel="Accetta con eccezione"
        dirty={reason !== "" || expires !== ""}
        validate={validate}
        onSubmit={async () => { await apply({ action: "create-exception", reason: reason.trim(), expires: expires.trim() }); }}
        onOpenChange={(open) => { if (open) { setErrors({}); setCopied(null); } }}
      >
        <Field id="reason" label="Motivazione" required error={errors.reason}>
          {(p) => <textarea {...p} rows={3} value={reason} maxLength={2000} onChange={(e) => { setReason(e.target.value); setErrors((now) => without(now, "reason")); }} />}
        </Field>
        <Field id="expires" label="Scadenza" required hint="Formato AAAA-MM-GG." error={errors.expires}>
          {(p) => <input {...p} type="text" inputMode="numeric" placeholder="2027-06-30" value={expires} maxLength={10} onChange={(e) => { setExpires(e.target.value); setErrors((now) => without(now, "expires")); }} />}
        </Field>
        <p>Approva: <strong>{who}</strong> (l&apos;utente autenticato; non si modifica).</p>
        <p className="notice">
          Il gate della CI non legge le eccezioni del server. Per farla valere anche lì, aggiungi questo
          frammento a <span className="mono">.code-analyzer.yml</span>:
        </p>
        <pre className="snippet" tabIndex={0} aria-label="Frammento di .code-analyzer.yml">{snippet}</pre>
        <button type="button" className="button" onClick={() => { void copy(); }}>Copia</button>
        {/* una regione di stato dentro il dialogo: fuori, la pagina è nascosta alle tecnologie assistive */}
        <span role="status" className="muted"> {copied}</span>
      </ActionDialog>
    </div>
  );
}
