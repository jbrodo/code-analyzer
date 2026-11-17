/** Evidenze dei fattori e dei finding: sempre coppie «nome: valore» in testo (U-04). */

const LABELS: Record<string, string> = {
  rule: "Regola",
  source: "Origine",
  tier: "Tier",
  commits: "Commit nella finestra",
  exposure: "Esposizione",
  fallback: "Ripiego",
  fallbacks: "Ripieghi",
  members: "Elementi",
  cvss: "CVSS",
  epss: "EPSS",
  kev: "KEV",
  reach: "Raggiungibilità",
  taint: "Percorso confermato",
};

export const VARIANT_B_UNDEFINED = "variante-b-non-definita";
const MAX_ENTRIES = 30;
const MAX_VALUE = 300;

function plain(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value.slice(0, MAX_VALUE);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(plain).join(", ").slice(0, MAX_VALUE);
  return "";
}

/** Le voci di un'evidenza, appiattite di un livello, con le etichette italiane dove note. */
export function evidenceEntries(evidence: unknown, prefix = ""): [string, string][] {
  if (typeof evidence !== "object" || evidence === null || Array.isArray(evidence)) return [];
  const out: [string, string][] = [];
  for (const [key, value] of Object.entries(evidence as Record<string, unknown>)) {
    const name = `${prefix}${LABELS[key] ?? key}`;
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      out.push(...evidenceEntries(value, `${name} · `));
    } else {
      out.push([name, plain(value)]);
    }
    if (out.length >= MAX_ENTRIES) break;
  }
  return out.slice(0, MAX_ENTRIES);
}

export function hasFallback(evidence: unknown, code: string): boolean {
  if (typeof evidence !== "object" || evidence === null) return false;
  const record = evidence as Record<string, unknown>;
  const list = record.fallbacks;
  return (
    record.fallback === code ||
    (Array.isArray(list) && list.includes(code)) ||
    Object.values(record).some(
      (v) => typeof v === "object" && v !== null && !Array.isArray(v) && hasFallback(v, code),
    )
  );
}

/** Due decimali con la virgola: 0,75; 18,00. */
export function fixed2(value: number): string {
  return new Intl.NumberFormat("it", { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(
    value,
  );
}
