import { afterEach } from "vitest";

// Le bozze dei dialoghi stanno in `sessionStorage` (G11): ogni prova parte da un archivio vuoto.
afterEach(() => {
  if (typeof window !== "undefined") window.sessionStorage.clear(); // alcune prove girano senza DOM
});
