/** Sessione della SPA: il token in memoria, la scadenza e il ritorno alla stessa vista (W-03). */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { createClient } from "@/api/client";
import type { Client } from "@/api/client";

import { loadConfig } from "./config";
import type { AuthConfig } from "./config";
import { AuthError, CALLBACK_PATH, completeLogin, discover, safeReturnTo, startLogin } from "./oidc";
import type { Endpoints, Tokens } from "./oidc";

/** Margine prima della scadenza oltre il quale non si usa più il token. */
export const EXPIRY_MARGIN_MS = 30_000;

export type SessionState =
  | { status: "loading" }
  | { status: "signed-out" }
  | { status: "signed-in"; client: Client; signOut: () => void }
  | { status: "error"; code: string; retry: () => void };

const Context = createContext<SessionState>({ status: "loading" });

export const useSession = (): SessionState => useContext(Context);

export interface SessionDeps {
  loadConfig: () => Promise<AuthConfig>;
  discover: (config: AuthConfig) => Promise<Endpoints>;
  completeLogin: typeof completeLogin;
  startLogin: typeof startLogin;
  navigate: (url: string) => void;
  replaceUrl: (path: string) => void;
  now: () => number;
  location: () => { pathname: string; search: string; hash: string };
}

export const realDeps: SessionDeps = {
  loadConfig: () => loadConfig(),
  discover: (config) => discover(config),
  completeLogin,
  startLogin,
  navigate: (url) => {
    window.location.assign(url);
  },
  replaceUrl: (path) => {
    window.history.replaceState(null, "", path);
  },
  now: () => Date.now(),
  location: () => window.location,
};

export function SessionProvider({
  children,
  deps = realDeps,
}: {
  children: ReactNode;
  deps?: SessionDeps;
}) {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const tokens = useRef<Tokens | null>(null);
  const setup = useRef<{ config: AuthConfig; endpoints: Endpoints } | null>(null);
  const [attempt, setAttempt] = useState(0);

  const login = useCallback(
    (returnTo: string) => {
      if (setup.current === null) return;
      const { config, endpoints } = setup.current;
      tokens.current = null;
      deps.startLogin(config, endpoints, returnTo, deps.navigate).catch((cause: unknown) => {
        setState({
          status: "error",
          code: cause instanceof AuthError ? cause.code : "login-failed",
          retry: () => {
            setAttempt((n) => n + 1);
          },
        });
      });
    },
    [deps],
  );

  useEffect(() => {
    const life = { cancelled: false };
    const stopped = (): boolean => life.cancelled;
    const here = deps.location();
    const current = `${here.pathname}${here.search}${here.hash}`;

    const token = (): string | null => {
      const held = tokens.current;
      if (held === null || deps.now() >= held.expiresAt - EXPIRY_MARGIN_MS) return null;
      return held.accessToken;
    };

    const toSession = (config: AuthConfig, endpoints: Endpoints): SessionState => {
      const client = createClient({
        baseUrl: config.apiBase,
        getToken: token,
        // token scaduto o rifiutato: si rifà il flusso e si torna alla stessa vista, con i suoi filtri
        onUnauthenticated: () => {
          const now = deps.location();
          login(`${now.pathname}${now.search}${now.hash}`);
        },
      });
      setup.current = { config, endpoints };
      return {
        status: "signed-in",
        client,
        signOut: () => {
          tokens.current = null;
          setState({ status: "signed-out" });
        },
      };
    };

    void (async () => {
      try {
        const config = await deps.loadConfig();
        const endpoints = await deps.discover(config);
        if (stopped()) return;
        setup.current = { config, endpoints };
        if (here.pathname === CALLBACK_PATH) {
          const done = await deps.completeLogin(config, endpoints, here.search);
          if (stopped()) return;
          tokens.current = done.tokens;
          deps.replaceUrl(safeReturnTo(done.returnTo));
          setState(toSession(config, endpoints));
          return;
        }
        login(current); // senza token si va all'IdP; con la sua sessione attiva non chiede nulla
      } catch (cause) {
        if (stopped()) return;
        setState({
          status: "error",
          code: cause instanceof AuthError ? cause.code : "config-unavailable",
          retry: () => {
            // un ritorno fallito riparte dalla vista di partenza, non dall'indirizzo di ritorno
            deps.replaceUrl("/");
            setAttempt((n) => n + 1);
          },
        });
      }
    })();
    return () => {
      life.cancelled = true;
    };
  }, [deps, login, attempt]);

  const value = useMemo(() => state, [state]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
