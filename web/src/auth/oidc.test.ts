import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { parseConfig } from "./config";
import { AuthError, completeLogin, discover, safeReturnTo, startLogin } from "./oidc";
import type { Endpoints } from "./oidc";
import { challengeFor } from "./pkce";

const config = parseConfig({ issuer: "https://idp.example.org/", clientId: "ca-spa" });
const endpoints: Endpoints = {
  authorization: "https://idp.example.org/authorize",
  token: "https://idp.example.org/token",
};

beforeEach(() => {
  window.sessionStorage.clear();
});
afterEach(() => {
  vi.useRealTimers();
});

async function begin(returnTo = "/r/1?level=critico") {
  let target = "";
  await startLogin(config, endpoints, returnTo, (url) => {
    target = url;
  });
  return new URL(target);
}

function tokenReply(body: Record<string, unknown>, status = 200) {
  return vi.fn<typeof fetch>(() => Promise.resolve(new Response(JSON.stringify(body), { status })));
}

test("il ritorno è sempre un percorso della stessa origine", () => {
  expect(safeReturnTo("/r/1?level=critico#x")).toBe("/r/1?level=critico#x");
  for (const bad of ["//evil.example", "https://evil.example", "/\\evil", "javascript:alert(1)", "r/1", "", null, undefined, "/a b"]) {
    expect(safeReturnTo(bad), String(bad)).toBe("/");
  }
  expect(safeReturnTo("/auth/callback?code=1")).toBe("/");
});

test("la richiesta di accesso usa PKCE S256, state e nonce e non mette il segreto nell'indirizzo", async () => {
  const url = await begin();
  const p = url.searchParams;
  expect(url.origin + url.pathname).toBe(endpoints.authorization);
  expect([p.get("response_type"), p.get("client_id"), p.get("code_challenge_method")]).toEqual(["code", "ca-spa", "S256"]);
  expect(p.get("redirect_uri")).toBe(`${window.location.origin}/auth/callback`);
  const flow = JSON.parse(window.sessionStorage.getItem("ca.auth.flow") ?? "{}") as Record<string, string>;
  expect(p.get("state")).toBe(flow.state);
  expect(p.get("nonce")).toBe(flow.nonce);
  expect(p.get("code_challenge")).toBe(await challengeFor(flow.verifier ?? ""));
  expect(url.href).not.toContain(flow.verifier ?? "x"); // il verificatore non parte mai verso l'IdP in chiaro
  expect(flow.verifier).toHaveLength(43);
});

test("il ritorno scambia il codice col verificatore e dà un token in memoria con la sua scadenza", async () => {
  const url = await begin();
  const fetchMock = tokenReply({ access_token: "AT.jwt.sig", token_type: "Bearer", expires_in: 600 });
  const done = await completeLogin(config, endpoints, `?code=abc&state=${url.searchParams.get("state") ?? ""}`, fetchMock, () => 1_000);
  expect(done.tokens).toEqual({ accessToken: "AT.jwt.sig", expiresAt: 601_000 });
  expect(done.returnTo).toBe("/r/1?level=critico");
  const [target, init] = fetchMock.mock.calls[0] ?? [];
  expect(target).toBe(endpoints.token);
  const sent = new URLSearchParams((init as RequestInit).body as URLSearchParams);
  expect([sent.get("grant_type"), sent.get("code"), sent.get("client_id")]).toEqual(["authorization_code", "abc", "ca-spa"]);
  expect(await challengeFor(sent.get("code_verifier") ?? "")).toBe(url.searchParams.get("code_challenge"));
  // né il token né il codice finiscono nell'archivio del browser
  for (const store of [window.localStorage, window.sessionStorage]) {
    const held = Object.keys(store).map((key) => store.getItem(key) ?? "");
    expect(held.join("|")).not.toContain("AT.jwt.sig");
  }
  expect(window.sessionStorage.getItem("ca.auth.flow")).toBeNull();
});

test("uno state diverso, mancante o già usato non scambia nulla", async () => {
  const url = await begin();
  const fetchMock = tokenReply({ access_token: "x" });
  const state = url.searchParams.get("state") ?? "";
  await expect(completeLogin(config, endpoints, "?code=abc&state=altro", fetchMock)).rejects.toMatchObject({ code: "state-mismatch" });
  // il flusso si consuma comunque: un secondo tentativo con lo state giusto non ha più nulla da completare
  await expect(completeLogin(config, endpoints, `?code=abc&state=${state}`, fetchMock)).rejects.toMatchObject({ code: "no-login-in-progress" });
  expect(fetchMock).not.toHaveBeenCalled();
  await expect(completeLogin(config, endpoints, "?code=abc", fetchMock)).rejects.toBeInstanceOf(AuthError);
});

test("un accesso rifiutato o senza codice è un errore con un codice, senza il testo dell'IdP", async () => {
  let url = await begin();
  const state = () => url.searchParams.get("state") ?? "";
  await expect(completeLogin(config, endpoints, `?error=access_denied&error_description=SEGRETO&state=${state()}`, tokenReply({}))).rejects.toMatchObject({ code: "denied", message: "denied" });
  url = await begin();
  await expect(completeLogin(config, endpoints, `?state=${state()}`, tokenReply({}))).rejects.toMatchObject({ code: "no-code" });
});

test("un flusso troppo vecchio non si completa", async () => {
  vi.useFakeTimers();
  const url = await begin();
  vi.advanceTimersByTime(11 * 60 * 1000);
  await expect(completeLogin(config, endpoints, `?code=a&state=${url.searchParams.get("state") ?? ""}`, tokenReply({ access_token: "x" }))).rejects.toMatchObject({ code: "no-login-in-progress" });
});

test("una risposta dell'IdP malformata o con un nonce sbagliato è respinta", async () => {
  const fail = async (body: Record<string, unknown>, status = 200) => {
    const url = await begin();
    return completeLogin(config, endpoints, `?code=a&state=${url.searchParams.get("state") ?? ""}`, tokenReply(body, status)).catch((e: unknown) => (e as AuthError).code);
  };
  expect(await fail({}, 400)).toBe("token-request-failed");
  expect(await fail({ expires_in: 60 })).toBe("token-invalid");
  expect(await fail({ access_token: "x", token_type: "mac" })).toBe("token-invalid");
  const idToken = `h.${btoa(JSON.stringify({ nonce: "altro" }))}.s`;
  expect(await fail({ access_token: "x", id_token: idToken })).toBe("nonce-mismatch");
});

test("senza expires_in valido la durata è breve, mai illimitata", async () => {
  const url = await begin();
  const done = await completeLogin(config, endpoints, `?code=a&state=${url.searchParams.get("state") ?? ""}`, tokenReply({ access_token: "x", expires_in: "per sempre" }), () => 0);
  expect(done.tokens.expiresAt).toBe(300_000);
});

test("la scoperta rifiuta un emittente diverso e indirizzi non sicuri", async () => {
  const reply = (doc: Record<string, unknown>) => vi.fn<typeof fetch>(() => Promise.resolve(new Response(JSON.stringify(doc))));
  const good = { issuer: "https://idp.example.org", authorization_endpoint: "https://idp.example.org/a", token_endpoint: "https://idp.example.org/t" };
  expect(await discover(config, reply(good))).toEqual({ authorization: "https://idp.example.org/a", token: "https://idp.example.org/t" });
  await expect(discover(config, reply({ ...good, issuer: "https://altro.example.org" }))).rejects.toMatchObject({ code: "issuer-mismatch" });
  await expect(discover(config, reply({ ...good, token_endpoint: "http://idp.example.org/t" }))).rejects.toThrow();
  await expect(discover(config, reply({ issuer: good.issuer }))).rejects.toMatchObject({ code: "discovery-invalid" });
});

test("la configurazione ammette https o loopback e nessuna credenziale", () => {
  expect(() => parseConfig({ issuer: "http://idp.example.org", clientId: "x" })).toThrow();
  expect(() => parseConfig({ issuer: "https://u:p@idp.example.org", clientId: "x" })).toThrow();
  expect(() => parseConfig({ issuer: "https://idp.example.org" })).toThrow();
  expect(parseConfig({ issuer: "http://127.0.0.1:9000/user", clientId: "x" }).issuer).toBe("http://127.0.0.1:9000/user");
  expect(parseConfig({ issuer: "https://idp.example.org", clientId: "x", audience: "code-analyzer", apiBase: "https://api.example.org/" })).toMatchObject({ audience: "code-analyzer", apiBase: "https://api.example.org" });
});
