import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { parseConfig } from "./config";
import { AuthError } from "./oidc";
import { SessionProvider, useSession } from "./session";
import type { SessionDeps } from "./session";

afterEach(cleanup);

const config = parseConfig({ issuer: "https://idp.example.org", clientId: "ca-spa" });
const endpoints = { authorization: "https://idp.example.org/a", token: "https://idp.example.org/t" };

function makeDeps(where: { pathname: string; search?: string; hash?: string }, extra: Partial<SessionDeps> = {}) {
  let clock = 0;
  const deps = {
    loadConfig: vi.fn(() => Promise.resolve(config)),
    discover: vi.fn(() => Promise.resolve(endpoints)),
    completeLogin: vi.fn(() =>
      Promise.resolve({ tokens: { accessToken: "tok", expiresAt: 600_000 }, returnTo: "/r/1?level=critico" }),
    ),
    startLogin: vi.fn(() => Promise.resolve()),
    navigate: vi.fn(),
    replaceUrl: vi.fn(),
    now: () => clock,
    location: () => ({ pathname: where.pathname, search: where.search ?? "", hash: where.hash ?? "" }),
    ...extra,
  } satisfies SessionDeps;
  return { deps, advance: (ms: number) => (clock += ms) };
}

function Probe() {
  const session = useSession();
  if (session.status === "error") return <p>errore {session.code}</p>;
  if (session.status === "signed-in") {
    return (
      <button
        onClick={() => {
          void session.client.me().catch(() => undefined);
        }}
      >
        accedi
      </button>
    );
  }
  return <p>{session.status}</p>;
}

test("senza token si va all'IdP e si ricorda la vista con i suoi filtri", async () => {
  const { deps } = makeDeps({ pathname: "/r/1", search: "?level=critico&q=sql", hash: "#f-2" });
  render(<SessionProvider deps={deps}><Probe /></SessionProvider>);
  await waitFor(() => { expect(deps.startLogin).toHaveBeenCalled(); });
  expect(vi.mocked(deps.startLogin).mock.calls[0]?.[2]).toBe("/r/1?level=critico&q=sql#f-2");
  expect(screen.getByText("loading")).toBeDefined();
});

test("il ritorno dall'IdP apre la sessione e riporta alla vista di partenza", async () => {
  const { deps } = makeDeps({ pathname: "/auth/callback", search: "?code=a&state=b" });
  render(<SessionProvider deps={deps}><Probe /></SessionProvider>);
  await screen.findByRole("button", { name: "accedi" });
  expect(deps.replaceUrl).toHaveBeenCalledWith("/r/1?level=critico");
  expect(deps.startLogin).not.toHaveBeenCalled();
});

test("l'indirizzo di ritorno è sempre ripulito, anche se l'IdP o lo stato ne portano uno ostile", async () => {
  const { deps } = makeDeps(
    { pathname: "/auth/callback", search: "?code=a&state=b" },
    { completeLogin: vi.fn(() => Promise.resolve({ tokens: { accessToken: "t", expiresAt: 1e9 }, returnTo: "//evil.example" })) },
  );
  render(<SessionProvider deps={deps}><Probe /></SessionProvider>);
  await screen.findByRole("button");
  expect(deps.replaceUrl).toHaveBeenCalledWith("/");
});

test("un ritorno fallito mostra solo il codice dell'errore e permette di riprovare", async () => {
  const { deps } = makeDeps(
    { pathname: "/auth/callback", search: "?error=access_denied" },
    { completeLogin: vi.fn(() => Promise.reject(new AuthError("denied"))) },
  );
  render(<SessionProvider deps={deps}><Probe /></SessionProvider>);
  expect((await screen.findByText("errore denied")).textContent).toBe("errore denied");
});

test("una configurazione che non si legge è un errore, non un'attesa infinita", async () => {
  const { deps } = makeDeps({ pathname: "/" }, { loadConfig: vi.fn(() => Promise.reject(new Error("boom https://idp"))) });
  render(<SessionProvider deps={deps}><Probe /></SessionProvider>);
  expect((await screen.findByText("errore config-unavailable")).textContent).toBe("errore config-unavailable");
});

test("un token scaduto non parte verso l'API: si rifà l'accesso tornando alla stessa vista", async () => {
  const where = { pathname: "/auth/callback", search: "?code=a", hash: "" };
  const { deps, advance } = makeDeps(where, {
    completeLogin: vi.fn(() => Promise.resolve({ tokens: { accessToken: "tok", expiresAt: 100_000 }, returnTo: "/r/1" })),
  });
  Object.assign(deps, { location: () => where });
  const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}"));
  render(<SessionProvider deps={deps}><Probe /></SessionProvider>);
  const button = await screen.findByRole("button");
  Object.assign(where, { pathname: "/r/1", search: "?status=aperto" }); // l'utente è sulla sua vista
  advance(80_000); // dentro il margine prima della scadenza
  button.click();
  await waitFor(() => { expect(deps.startLogin).toHaveBeenCalled(); });
  expect(vi.mocked(deps.startLogin).mock.calls[0]?.[2]).toBe("/r/1?status=aperto");
  expect(fetchSpy).not.toHaveBeenCalled();
});
