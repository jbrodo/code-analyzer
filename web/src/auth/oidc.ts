/** Authorization code con PKCE per un client pubblico (W-03, ADR-0019).
 *
 * Il token di accesso vive solo in memoria (`session.ts`): mai in `localStorage`, `sessionStorage` o
 * cookie. In `sessionStorage` resta soltanto lo stato transitorio del flusso (`state`, `nonce`,
 * verificatore PKCE e la vista di ritorno) per il tempo del giro di andata e ritorno dall'IdP, e si
 * cancella al ritorno: non è un token e senza il codice non vale nulla.
 */
import type { AuthConfig } from "./config";
import { checkIdpUrl } from "./config";
import { challengeFor, randomToken } from "./pkce";

const FLOW_KEY = "ca.auth.flow";
export const CALLBACK_PATH = "/auth/callback";
const MAX_FLOW_AGE_MS = 10 * 60 * 1000;

export interface Endpoints {
  readonly authorization: string;
  readonly token: string;
}

export interface Tokens {
  readonly accessToken: string;
  /** Millisecondi epoch oltre i quali il token non vale. */
  readonly expiresAt: number;
}

export class AuthError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "AuthError";
  }
}

interface Flow {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  at: number;
}

/** Solo un percorso della stessa origine: mai `//host`, mai uno schema, mai un percorso con `\`. */
export function safeReturnTo(value: string | null | undefined): string {
  if (typeof value !== "string" || !/^\/(?![/\\])[^\s\\]*$/.test(value)) return "/";
  return value.startsWith(CALLBACK_PATH) ? "/" : value;
}

export async function discover(
  config: AuthConfig,
  doFetch: typeof fetch = (...a) => fetch(...a),
): Promise<Endpoints> {
  const response = await doFetch(`${config.issuer}/.well-known/openid-configuration`, {
    credentials: "omit",
    redirect: "error",
  });
  if (!response.ok) throw new AuthError("discovery-failed");
  const doc = (await response.json()) as Record<string, unknown>;
  if (doc.issuer !== config.issuer) throw new AuthError("issuer-mismatch");
  const pick = (name: string): string => {
    const value = doc[name];
    if (typeof value !== "string") throw new AuthError("discovery-invalid");
    return checkIdpUrl(value).href;
  };
  return { authorization: pick("authorization_endpoint"), token: pick("token_endpoint") };
}

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export async function startLogin(
  config: AuthConfig,
  endpoints: Endpoints,
  returnTo: string,
  redirect: (url: string) => void,
): Promise<void> {
  const flow: Flow = {
    state: randomToken(),
    nonce: randomToken(),
    verifier: randomToken(),
    returnTo: safeReturnTo(returnTo),
    at: Date.now(),
  };
  const store = storage();
  if (store === null) throw new AuthError("storage-unavailable");
  store.setItem(FLOW_KEY, JSON.stringify(flow));
  const url = new URL(endpoints.authorization);
  const params = {
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: `${window.location.origin}${CALLBACK_PATH}`,
    scope: config.scope,
    state: flow.state,
    nonce: flow.nonce,
    code_challenge: await challengeFor(flow.verifier),
    code_challenge_method: "S256",
  };
  for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
  if (config.audience !== null) url.searchParams.set("audience", config.audience);
  redirect(url.href);
}

function takeFlow(): Flow | null {
  const store = storage();
  const raw = store?.getItem(FLOW_KEY) ?? null;
  store?.removeItem(FLOW_KEY); // si usa una volta sola, anche se il ritorno fallisce
  if (raw === null) return null;
  try {
    const flow = JSON.parse(raw) as Flow;
    return Date.now() - flow.at <= MAX_FLOW_AGE_MS ? flow : null;
  } catch {
    return null;
  }
}

function idTokenNonce(idToken: string): string | null {
  try {
    const payload = idToken.split(".")[1] ?? "";
    const json = atob(payload.replaceAll("-", "+").replaceAll("_", "/"));
    const claims = JSON.parse(json) as { nonce?: unknown };
    return typeof claims.nonce === "string" ? claims.nonce : null;
  } catch {
    return null;
  }
}

/** Dal ritorno dell'IdP ai token. Ogni fallimento è un `AuthError` con un codice, mai un testo dell'IdP. */
export async function completeLogin(
  config: AuthConfig,
  endpoints: Endpoints,
  search: string,
  doFetch: typeof fetch = (...a) => fetch(...a),
  now: () => number = Date.now,
): Promise<{ tokens: Tokens; returnTo: string }> {
  const query = new URLSearchParams(search);
  const flow = takeFlow();
  if (flow === null) throw new AuthError("no-login-in-progress");
  if (query.get("state") !== flow.state) throw new AuthError("state-mismatch");
  if (query.has("error")) throw new AuthError("denied");
  const code = query.get("code");
  if (code === null || code === "" || code.length > 2000) throw new AuthError("no-code");

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: `${window.location.origin}${CALLBACK_PATH}`,
    client_id: config.clientId,
    code_verifier: flow.verifier,
  });
  let response: Response;
  try {
    response = await doFetch(endpoints.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
      credentials: "omit",
      redirect: "error",
    });
  } catch {
    throw new AuthError("token-request-failed");
  }
  if (!response.ok) throw new AuthError("token-request-failed");
  const data = (await response.json()) as Record<string, unknown>;
  const access = data.access_token;
  const lifetime = data.expires_in;
  if (typeof access !== "string" || access === "" || access.length > 16_000) {
    throw new AuthError("token-invalid");
  }
  if (data.token_type !== undefined && !(typeof data.token_type === "string" && data.token_type.toLowerCase() === "bearer")) {
    throw new AuthError("token-invalid");
  }
  if (typeof data.id_token === "string" && idTokenNonce(data.id_token) !== flow.nonce) {
    throw new AuthError("nonce-mismatch");
  }
  const seconds = typeof lifetime === "number" && lifetime > 0 ? Math.min(lifetime, 86_400) : 300;
  return {
    tokens: { accessToken: access, expiresAt: now() + seconds * 1000 },
    returnTo: flow.returnTo,
  };
}
