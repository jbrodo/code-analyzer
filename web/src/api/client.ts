/** Client dell'API v1 (W-02, ADR-0017). I tipi vengono da `schema.d.ts`, generato dal contratto.
 *
 * Nessun segreto in questo file: il token arriva da chi costruisce il client e va solo
 * nell'intestazione `Authorization`. Un errore del server è sempre un `ApiError` con il codice e lo
 * stato del problema+json (ADR-0017); il testo che il server può aver copiato dal report non esce
 * da qui se non come `detail`, che la UI mostra come testo semplice.
 */
import type { components, operations } from "./schema";

export type Schemas = components["schemas"];
export type Problem = Schemas["Problem"];

type Json<T> = T extends { content: { "application/json": infer B } } ? B : never;
type Ok<Op extends keyof operations> = operations[Op] extends { responses: infer R }
  ? R extends { 200: infer S }
    ? Json<S>
    : R extends { 201: infer S }
      ? Json<S>
      : never
  : never;
type Query<Op extends keyof operations> = operations[Op] extends {
  parameters: { query?: infer Q };
}
  ? NonNullable<Q>
  : Record<string, never>;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly problem: Problem | null,
  ) {
    super(`${String(status)} ${code}`);
    this.name = "ApiError";
  }
}

export interface ClientOptions {
  /** Indirizzo del server senza barra finale; vuoto per lo stesso host della SPA. */
  baseUrl?: string;
  /** Il token OIDC corrente, o `null` se manca o è scaduto: in quel caso nessuna richiesta parte. */
  getToken: () => string | null | Promise<string | null>;
  /** Chiamata una volta su un 401: la SPA riporta all'accesso e poi alla stessa vista. */
  onUnauthenticated?: () => void;
  fetch?: typeof fetch;
}

function queryString(query: Record<string, unknown> | undefined): string {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(query ?? {})) {
    for (const item of Array.isArray(value) ? (value as unknown[]) : [value]) {
      // solo valori semplici: un oggetto non diventa mai un parametro
      if (typeof item === "string" && item !== "") params.append(name, item);
      else if (typeof item === "number" || typeof item === "boolean") params.append(name, String(item));
    }
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

interface CallInit {
  query?: Record<string, unknown> | undefined;
  body?: unknown;
  signal?: AbortSignal | undefined;
  accept?: string | undefined;
}

function isProblem(value: unknown): value is Problem {
  return typeof value === "object" && value !== null && "code" in value && "status" in value;
}

export function createClient(options: ClientOptions) {
  const base = (options.baseUrl ?? "").replace(/\/$/, "");
  const doFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));

  async function call(
    method: "GET" | "PATCH",
    path: string,
    init: CallInit,
  ): Promise<Response> {
    const token = await options.getToken();
    if (!token) {
      // senza token valido la richiesta non parte: l'API risponderebbe 401 e il token non c'è da inviare
      options.onUnauthenticated?.();
      throw new ApiError(401, "unauthenticated", null);
    }
    const headers: Record<string, string> = { Accept: init.accept ?? "application/json" };
    headers.Authorization = `Bearer ${token}`;
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    let response: Response;
    try {
      response = await doFetch(`${base}${path}${queryString(init.query)}`, {
        method,
        headers,
        body: init.body === undefined ? null : JSON.stringify(init.body),
        signal: init.signal ?? null,
        credentials: "omit", // nessun cookie: l'identità è il token
        redirect: "error",
      });
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
      throw new ApiError(0, "network-error", null);
    }
    if (response.ok) return response;
    let problem: Problem | null = null;
    try {
      const parsed: unknown = await response.json();
      if (isProblem(parsed)) problem = parsed;
    } catch {
      /* corpo assente o non JSON: resta il solo stato */
    }
    if (response.status === 401) options.onUnauthenticated?.();
    throw new ApiError(response.status, problem?.code ?? "unknown-error", problem);
  }

  async function json<T>(
    method: "GET" | "PATCH",
    path: string,
    init: CallInit = {},
  ): Promise<T> {
    return (await (await call(method, path, init)).json()) as T;
  }

  const id = (value: string) => encodeURIComponent(value);

  return {
    me: (signal?: AbortSignal) => json<Ok<"getMe">>("GET", "/v1/me", { signal }),
    listRepositories: (query: Query<"listRepositories"> = {}, signal?: AbortSignal) =>
      json<Ok<"listRepositories">>("GET", "/v1/repositories", { query, signal }),
    getRepository: (repository: string, signal?: AbortSignal) =>
      json<Ok<"getRepository">>("GET", `/v1/repositories/${id(repository)}`, { signal }),
    patchRepository: (repository: string, body: Schemas["RepositoryPatch"]) =>
      json<Ok<"patchRepository">>("PATCH", `/v1/repositories/${id(repository)}`, { body }),
    listScans: (repository: string, query: Query<"listRepositoryScans"> = {}, signal?: AbortSignal) =>
      json<Ok<"listRepositoryScans">>("GET", `/v1/repositories/${id(repository)}/scans`, {
        query,
        signal,
      }),
    getScan: (scan: string, signal?: AbortSignal) =>
      json<Ok<"getScan">>("GET", `/v1/scans/${id(scan)}`, { signal }),
    listFindings: (repository: string, query: Query<"listFindings"> = {}, signal?: AbortSignal) =>
      json<Ok<"listFindings">>("GET", `/v1/repositories/${id(repository)}/findings`, {
        query,
        signal,
      }),
    getFinding: (finding: string, signal?: AbortSignal) =>
      json<Ok<"getFinding">>("GET", `/v1/findings/${id(finding)}`, { signal }),
    patchFinding: (finding: string, body: PatchBody) =>
      json<Ok<"patchFinding">>("PATCH", `/v1/findings/${id(finding)}`, { body }),
  };
}

type PatchBody =
  | Schemas["SetStatus"]
  | Schemas["SetOwner"]
  | Schemas["CreateException"]
  | Schemas["RevokeException"];

export type Client = ReturnType<typeof createClient>;
