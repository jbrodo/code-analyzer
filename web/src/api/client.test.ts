import { expect, test, vi } from "vitest";

import { ApiError, createClient } from "./client";
import { example, jsonResponse } from "./examples";

function setup(reply: () => Response | Promise<Response>, token: string | null = "tok-123") {
  const fetchMock = vi.fn<typeof fetch>(() => Promise.resolve(reply()));
  const onUnauthenticated = vi.fn();
  const client = createClient({
    baseUrl: "https://ca.example.org/",
    getToken: () => token,
    onUnauthenticated,
    fetch: fetchMock,
  });
  return { client, fetchMock, onUnauthenticated };
}

function lastCall(fetchMock: ReturnType<typeof setup>["fetchMock"]) {
  const [url, init] = fetchMock.mock.calls[0] ?? [];
  return { url: url as string, init: init as RequestInit };
}

test("la risposta di /me coincide con l'esempio del contratto", async () => {
  const { client, fetchMock } = setup(() => jsonResponse(example("Me")));
  const me = await client.me();
  expect(me).toEqual(example("Me"));
  const { url, init } = lastCall(fetchMock);
  expect(url).toBe("https://ca.example.org/v1/me");
  expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  expect(init.credentials).toBe("omit");
  expect(init.redirect).toBe("error");
});

test("senza token la richiesta non parte e la SPA viene avvisata", async () => {
  const { client, fetchMock, onUnauthenticated } = setup(() => jsonResponse(example("Me")), null);
  const error = (await client.me().catch((e: unknown) => e)) as ApiError;
  expect([error.status, error.code]).toEqual([401, "unauthenticated"]);
  expect(fetchMock).not.toHaveBeenCalled();
  expect(onUnauthenticated).toHaveBeenCalledTimes(1);
});

test("i filtri multipli si ripetono, i vuoti si omettono e i valori si codificano", async () => {
  const { client, fetchMock } = setup(() => jsonResponse(example("FindingPage")));
  await client.listFindings("repo/1", {
    level: ["critico", "alto"],
    q: "a&b=c",
    new: true,
    cursor: "",
    limit: 50,
  });
  expect(lastCall(fetchMock).url).toBe(
    "https://ca.example.org/v1/repositories/repo%2F1/findings?level=critico&level=alto&q=a%26b%3Dc&new=true&limit=50",
  );
});

test("l'elenco dei repository restituisce la forma dell'esempio", async () => {
  const page = { items: [example("RepositorySummary")], next_cursor: null };
  const { client } = setup(() => jsonResponse(page));
  const result = await client.listRepositories({ limit: 10 });
  expect(result.items[0]?.name).toBe("acme/shop");
});

test("un problema+json diventa un ApiError con codice e stato", async () => {
  const problem = example("Problem");
  const { client } = setup(() => jsonResponse(problem, 422, "application/problem+json"));
  const error = await client.getScan("x").catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ApiError);
  const api = error as ApiError;
  expect([api.status, api.code]).toEqual([422, "report-schema-invalid"]);
  expect(api.problem?.errors?.[0]?.pointer).toBe("/findings/0/level");
});

test("una risposta d'errore senza JSON lascia il solo stato", async () => {
  const { client } = setup(() => new Response("<html>boom</html>", { status: 502 }));
  const error = (await client.me().catch((e: unknown) => e)) as ApiError;
  expect([error.status, error.code, error.problem]).toEqual([502, "unknown-error", null]);
  expect(error.message).not.toContain("boom");
});

test("un errore di rete non porta l'indirizzo né la causa", async () => {
  const fetchMock = vi.fn(() => Promise.reject(new TypeError("fetch failed: https://ca.example.org")));
  const client = createClient({ baseUrl: "https://ca.example.org", getToken: () => "t", fetch: fetchMock });
  const error = (await client.me().catch((e: unknown) => e)) as ApiError;
  expect(error.code).toBe("network-error");
  expect(error.message).not.toContain("example.org");
});

test("un 401 avvisa la SPA una volta sola", async () => {
  const problem = { ...example("Problem"), status: 401, code: "unauthenticated" };
  const { client, onUnauthenticated } = setup(() => jsonResponse(problem, 401));
  await client.me().catch(() => undefined);
  expect(onUnauthenticated).toHaveBeenCalledTimes(1);
});

test("il triage invia il corpo dell'esempio come JSON", async () => {
  const { client, fetchMock } = setup(() => jsonResponse({}));
  await client.patchFinding("f-1", example("SetStatus"));
  const { url, init } = lastCall(fetchMock);
  expect([url, init.method]).toEqual(["https://ca.example.org/v1/findings/f-1", "PATCH"]);
  expect(JSON.parse(init.body as string)).toEqual(example("SetStatus"));
  expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
});

test("la richiesta annullata non diventa un errore del server", async () => {
  const controller = new AbortController();
  const fetchMock = vi.fn(() => Promise.reject(new DOMException("annullata", "AbortError")));
  const client = createClient({ getToken: () => "t", fetch: fetchMock });
  controller.abort();
  const error = await client.me(controller.signal).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(DOMException);
});
