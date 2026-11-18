import { expect, test } from "vitest";

import { applyCspNonce } from "./csp";

function page(content: string | null): Document {
  const doc = document.implementation.createHTMLDocument("t");
  if (content !== null) doc.head.innerHTML = `<meta name="csp-nonce" content="${content}">`;
  return doc;
}

test("il nonce del server diventa quello che le librerie leggono", () => {
  const target: { __webpack_nonce__?: string } = {};
  expect(applyCspNonce(page("abcDEF123_-xyz789"), target)).toBe("abcDEF123_-xyz789");
  expect(target.__webpack_nonce__).toBe("abcDEF123_-xyz789");
});

test("il segnaposto di sviluppo, un meta assente o un valore strano non impostano nulla", () => {
  for (const doc of [page("__CSP_NONCE__"), page(null), page(""), page("a b"), page("x".repeat(200))]) {
    const target: { __webpack_nonce__?: string } = {};
    expect(applyCspNonce(doc, target)).toBeNull();
    expect(target.__webpack_nonce__).toBeUndefined();
  }
});
