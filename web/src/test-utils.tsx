import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";

import type { Client } from "@/api/client";
import { SessionContext } from "@/auth/session";
import { AnnounceProvider } from "@/layout/announce";

/** Una vista dentro una sessione aperta con un client finto e un router in memoria. */
export function renderInSession(ui: ReactElement, client: Partial<Client>, route = "/") {
  return render(
    <SessionContext.Provider
      value={{ status: "signed-in", client: client as Client, signOut: () => undefined }}
    >
      <AnnounceProvider>
        <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
      </AnnounceProvider>
    </SessionContext.Provider>,
  );
}
