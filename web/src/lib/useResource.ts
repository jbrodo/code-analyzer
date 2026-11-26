import { useEffect, useState } from "react";

import { ApiError } from "@/api/client";

export type Resource<T> =
  | { status: "loading" }
  | { status: "ready"; data: T }
  | { status: "error"; error: ApiError };

interface Settled<T> {
  /** La richiesta a cui appartiene l'esito: un esito di una richiesta superata non vale. */
  request: string;
  outcome: { data: T } | { error: ApiError };
}

/** Carica una risorsa e la ricarica quando cambiano le dipendenze; annulla la richiesta superata. */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
): [Resource<T>, () => void] {
  const [attempt, setAttempt] = useState(0);
  const [settled, setSettled] = useState<Settled<T> | null>(null);
  // Le dipendenze sono valori semplici (identificativi, filtri): la loro forma testuale è la
  // identità della richiesta, e da lì si deriva "in caricamento" senza impostare stato negli effetti.
  const request = JSON.stringify([deps, attempt]);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setSettled({ request, outcome: { data } });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        const known = error instanceof ApiError ? error : new ApiError(0, "network-error", null);
        setSettled({ request, outcome: { error: known } });
      });
    return () => {
      controller.abort();
    };
    // `load` è nuova a ogni render: conta solo `request`, che cambia con le dipendenze.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request]);

  const state: Resource<T> =
    settled?.request !== request
      ? { status: "loading" }
      : "data" in settled.outcome
        ? { status: "ready", data: settled.outcome.data }
        : { status: "error", error: settled.outcome.error };
  return [
    state,
    () => {
      setAttempt((n) => n + 1);
    },
  ];
}
