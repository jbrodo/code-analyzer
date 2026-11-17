import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";

import type { Client, Schemas } from "@/api/client";
import { SessionContext } from "@/auth/session";
import { AnnounceProvider } from "@/layout/announce";
import { MeContext } from "@/layout/me";

/** Una vista dentro una sessione aperta con un client finto e un router in memoria. */
export function renderInSession(
  ui: ReactElement,
  client: Partial<Client>,
  route = "/",
  me: Schemas["Me"] | null = null,
) {
  return render(
    <SessionContext.Provider
      value={{ status: "signed-in", client: client as Client, signOut: () => undefined }}
    >
      <AnnounceProvider>
        <MeContext.Provider value={me}>
          <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
        </MeContext.Provider>
      </AnnounceProvider>
    </SessionContext.Provider>,
  );
}
