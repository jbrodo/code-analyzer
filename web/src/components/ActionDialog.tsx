import { Dialog } from "radix-ui";
import { cloneElement, createContext, isValidElement, useContext, useId, useState } from "react";
import type { ReactElement, ReactNode } from "react";

import { ApiError } from "@/api/client";

const PrefixContext = createContext("dialog");

export interface FieldErrors {
  [field: string]: string | undefined;
}

interface Props {
  /** Il pulsante che apre il dialogo: a lui torna il fuoco alla chiusura (T1). */
  trigger: ReactElement;
  title: string;
  description: string;
  /** Il verbo dell'azione, mai «OK» (U-02). */
  submitLabel: string;
  tone?: "accent" | "danger";
  /** C'è testo inserito: chiudere senza salvare chiede conferma (T2). */
  dirty: boolean;
  /** Controlla i campi; restituisce gli errori per campo, o nulla se va bene. */
  validate: () => FieldErrors | null;
  /** Esegue l'azione. Un `ApiError` resta nel dialogo con i dati inseriti (T6). */
  onSubmit: () => Promise<void>;
  onOpenChange?: (open: boolean) => void;
  children: ReactNode;
}

/** Messaggio di un errore del server: titolo e codice, mai il corpo grezzo (ADR-0017). */
export function ServerError({ error }: { error: ApiError }) {
  const title = error.problem?.title ?? "Richiesta non riuscita";
  return (
    <div role="alert" className="dialog-error">
      <p>{title}</p>
      <p className="muted">
        Codice: <code>{error.code}</code>
      </p>
    </div>
  );
}

export function ActionDialog(props: Props) {
  const { trigger, title, description, submitLabel, tone = "accent", dirty, validate, onSubmit, onOpenChange, children } = props;
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const titleId = useId();
  const descId = useId();

  const change = (next: boolean) => {
    setOpen(next);
    setError(null);
    setConfirmDiscard(false);
    onOpenChange?.(next);
  };

  /** Esc, fuori dal dialogo o «Annulla»: con testo inserito si chiede prima (T2). */
  const requestClose = () => {
    if (dirty && !busy) setConfirmDiscard(true);
    else change(false);
  };

  const submit = async (event: React.SyntheticEvent) => {
    event.preventDefault();
    const problems = validate();
    if (problems && Object.values(problems).some(Boolean)) {
      // T5: il fuoco va al primo campo in errore, nell'ordine del modulo
      const first = Object.keys(problems).find((k) => problems[k]);
      if (first) document.getElementById(`${titleId}-${first}`)?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSubmit();
      change(false);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause : new ApiError(0, "network-error", null));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (next) change(true); else requestClose(); }}>
      <Dialog.Trigger asChild>
        {isValidElement(trigger) ? cloneElement(trigger as ReactElement<Record<string, unknown>>, { "data-dialog-trigger": titleId }) : trigger}
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content
          className="dialog"
          aria-labelledby={titleId}
          aria-describedby={descId}
          onCloseAutoFocus={(event) => {
            // T1: il fuoco torna al pulsante che ha aperto il dialogo; se l'azione lo ha tolto di mezzo
            // (lo stato è cambiato), va al titolo del pannello, mai al corpo della pagina
            event.preventDefault();
            const trigger = document.querySelector<HTMLElement>(`[data-dialog-trigger="${CSS.escape(titleId)}"]`);
            (trigger ?? document.getElementById("panel-title"))?.focus();
          }}
          onEscapeKeyDown={(event) => { event.preventDefault(); requestClose(); }}
          onPointerDownOutside={(event) => { event.preventDefault(); requestClose(); }}
          onInteractOutside={(event) => { event.preventDefault(); }}
        >
          <form onSubmit={(event) => { void submit(event); }} noValidate>
            <Dialog.Title id={titleId} className="dialog-title">{title}</Dialog.Title>
            <Dialog.Description id={descId} className="muted">{description}</Dialog.Description>
            <PrefixContext.Provider value={titleId}>
              <div className="dialog-fields">{children}</div>
            </PrefixContext.Provider>
            {error && <ServerError error={error} />}
            {confirmDiscard && (
              <div role="alert" className="dialog-error">
                <p>Hai scritto del testo che non è stato salvato. Chiudere comunque?</p>
                <button type="button" className="button" onClick={() => { setConfirmDiscard(false); }}>Continua a modificare</button>{" "}
                <button type="button" className="button" onClick={() => { change(false); }}>Scarta</button>
              </div>
            )}
            <div className="dialog-actions">
              <button type="button" className="button" onClick={requestClose}>Annulla</button>
              <button type="submit" className="button" data-tone={tone} aria-disabled={busy}>
                {busy ? "Attendi…" : submitLabel}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Un campo con etichetta visibile e associata, errore accanto con `aria-describedby` (T3, T5). */
export function Field({
  id, label, required, hint, error, children,
}: {
  /** Suffisso dell'identificativo del campo (usato per riportare il fuoco). */
  id: string;
  label: string;
  required?: boolean;
  hint?: string;
  error?: string | undefined;
  /** Riceve le proprietà da mettere sul controllo. */
  children: (props: { id: string; "aria-describedby": string | undefined; "aria-invalid": boolean }) => ReactNode;
}) {
  const prefix = useContext(PrefixContext);
  const controlId = `${prefix}-${id}`;
  const errorId = `${controlId}-error`;
  const hintId = `${controlId}-hint`;
  const described = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(" ") || undefined;
  return (
    <div className="field dialog-field">
      <label htmlFor={controlId}>
        {label}
        {required ? " (obbligatorio)" : ""}
      </label>
      {hint && <p id={hintId} className="muted hint">{hint}</p>}
      {children({ id: controlId, "aria-describedby": described, "aria-invalid": Boolean(error) })}
      {error && <p id={errorId} className="error-text">{error}</p>}
    </div>
  );
}
