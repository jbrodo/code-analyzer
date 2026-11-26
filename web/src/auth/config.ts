/** Configurazione dell'accesso, letta a runtime da `/config.json` (W-03, ADR-0019).
 *
 * Un solo file per ambiente, nessun segreto: la SPA è un client pubblico. L'indirizzo dell'IdP deve
 * essere `https`, salvo `http` su loopback per lo sviluppo.
 */
export interface AuthConfig {
  /** Emittente dell'IdP: da qui si legge la scoperta OIDC. */
  readonly issuer: string;
  readonly clientId: string;
  readonly scope: string;
  /** `aud` richiesto all'IdP, se diverso dal client (parametro `audience`). */
  readonly audience: string | null;
  /** Indirizzo dell'API; vuoto per lo stesso host della SPA. */
  readonly apiBase: string;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function checkIdpUrl(value: string): URL {
  const url = new URL(value);
  const secure = url.protocol === "https:";
  const local = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (!(secure || local) || url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new Error("indirizzo dell'IdP non ammesso");
  }
  return url;
}

export function parseConfig(raw: unknown): AuthConfig {
  if (typeof raw !== "object" || raw === null) throw new Error("configurazione non valida");
  const data = raw as Record<string, unknown>;
  const text = (name: string, fallback?: string): string => {
    const value = data[name];
    if (value === undefined && fallback !== undefined) return fallback;
    if (typeof value !== "string" || value === "" || value.length > 500) {
      throw new Error(`configurazione non valida: ${name}`);
    }
    return value;
  };
  const issuer = checkIdpUrl(text("issuer")).href.replace(/\/$/, "");
  const apiBase = text("apiBase", "");
  if (apiBase !== "") checkIdpUrl(apiBase);
  const audience = data.audience === undefined ? null : text("audience");
  return {
    issuer,
    clientId: text("clientId"),
    scope: text("scope", "openid profile email groups"),
    audience,
    apiBase: apiBase.replace(/\/$/, ""),
  };
}

export async function loadConfig(doFetch: typeof fetch = (...a) => fetch(...a)): Promise<AuthConfig> {
  const response = await doFetch("/config.json", { credentials: "omit", cache: "no-store" });
  if (!response.ok) throw new Error("configurazione non disponibile");
  return parseConfig(await response.json());
}
