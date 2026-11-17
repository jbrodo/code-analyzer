import { createContext, useContext } from "react";

import type { Schemas } from "@/api/client";

/** L'utente autenticato (`GET /v1/me`), per le viste che mostrano o disattivano le azioni. */
export const MeContext = createContext<Schemas["Me"] | null>(null);

export const useMe = (): Schemas["Me"] | null => useContext(MeContext);
