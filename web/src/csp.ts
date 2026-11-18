/** Il nonce della Content-Security-Policy, per gli stili che le librerie iniettano a run time (I-03).
 *
 * Radix blocca lo scorrimento della pagina sotto un dialogo con un elemento `<style>`: con
 * `style-src 'self'` il browser lo rifiuta, a meno che porti il nonce della risposta. Il server lo
 * mette nel meta `csp-nonce` di `index.html` (nuovo a ogni risposta) e `react-style-singleton`, che
 * Radix usa, lo legge da `__webpack_nonce__`. In sviluppo il meta ha ancora il segnaposto e non si fa nulla.
 */
export const PLACEHOLDER = "__CSP_NONCE__";

export function applyCspNonce(doc: Document, target: object = globalThis): string | null {
  const value = doc.querySelector('meta[name="csp-nonce"]')?.getAttribute("content") ?? "";
  if (value === "" || value === PLACEHOLDER || !/^[A-Za-z0-9_-]{8,128}$/.test(value)) return null;
  (target as { __webpack_nonce__?: string }).__webpack_nonce__ = value;
  return value;
}
