/** Controlli automatici di accessibilità (W-08, U-03) con axe-core su un nodo del DOM di prova.
 *
 * jsdom non calcola layout né colori: il contrasto (`color-contrast`) lo copre
 * `doc/ux/check_tokens.py` sui token, nei due temi; qui si disattiva. Un test verde non dimostra la
 * conformità: axe ne copre una parte, il resto è la revisione manuale di U-05.
 */
import axe from "axe-core";

export async function violations(root: Element = document.body): Promise<string[]> {
  const result = await axe.run(root, {
    rules: { "color-contrast": { enabled: false }, region: { enabled: false } },
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] },
  });
  return result.violations.map(
    (v) => `${v.id}: ${v.help} — ${v.nodes.map((n) => n.target.join(" ")).slice(0, 3).join("; ")}`,
  );
}
