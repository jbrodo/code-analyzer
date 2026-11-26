/** Dati di prova condivisi dai test delle viste: derivati dagli esempi dell'OpenAPI dove ce n'è uno. */
import type { Schemas } from "@/api/client";
import { example } from "@/api/examples";

export const REPO = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11";
export const uuid = (n: number) => `0192f3a2-7c1e-7b55-9d0a-${String(n).padStart(12, "0")}`;

export function scan(n = 1, over: Partial<Schemas["ScanSummary"]> = {}): Schemas["ScanSummary"] {
  return { ...example("ScanSummary"), id: uuid(n), ...over };
}

export function repository(over: Partial<Schemas["RepositorySummary"]> = {}): Schemas["RepositorySummary"] {
  return { ...example("RepositorySummary"), id: REPO, current_scan: scan(1), ...over };
}

export function item(n: number, over: Partial<Schemas["FindingListItem"]> = {}): Schemas["FindingListItem"] {
  return {
    ...example("FindingListItem"),
    id: uuid(n),
    title: `Problema ${String(n)}`,
    rule_id: `regola-${String(n)}`,
    level: "alto",
    ...over,
  };
}

export function page(items: Schemas["FindingListItem"][], next: string | null = null, totalNew = 0): Schemas["FindingPage"] {
  return { items, total: items.length, total_new: totalNew, next_cursor: next };
}

export function score(variant: "A" | "B", level: Schemas["Level"] = "medio", value = 18): Schemas["VariantScore"] {
  return {
    variant,
    score: value,
    level,
    impact: {
      g: 0.75, p: 0.4, e: 0.6, c: 1, variant,
      evidence: { g: { rule: "severity" }, p: { rule: "epss", epss: 0.12 }, e: { rule: "reach" }, c: { rule: "tier", tier: 2 } },
    },
  };
}

export function detail(over: Partial<Schemas["FindingDetail"]> = {}, finding: Partial<Schemas["Finding"]> = {}): Schemas["FindingDetail"] {
  return {
    finding: {
      id: uuid(1), fingerprint: `sha256:${"a".repeat(64)}`, category: "sast", rule_id: "regola-1", tool: "bandit", tools: ["bandit"],
      title: "Query SQL costruita con una stringa", message: "m", location: { repository: "shop", path: "app/db.py", start_line: 12 },
      first_seen: "2026-06-01T12:00:00Z", last_seen: "2026-11-17T12:00:00Z", status: "aperto", level: "alto", level_source: "tool_severity",
      remediation: { text: "Usa una query parametrizzata.", source: "tool" },
      ...finding,
    },
    occurrence: { scan_id: uuid(1), commit: "c".repeat(40), variant_scores: [score("A"), score("B")] },
    exceptions: [],
    events: [],
    ...over,
  };
}

export function scanDetail(over: Partial<Schemas["ScanDetail"]> = {}, summary: Partial<Schemas["ScanSummary"]> = {}): Schemas["ScanDetail"] {
  return {
    summary: scan(1, summary),
    plugins: [
      { name: "bandit", version: "1.8.0", outcome: "ok", duration_seconds: 4.2, signature: "verified", isolation: "gvisor", digest: "sha256:x" },
      { name: "semgrep", version: "1.99", outcome: "failed", failure: "tempo scaduto", duration_seconds: 125, signature: "skipped", isolation: "hardened-container", digest: "sha256:y" },
    ],
    warnings: [{ code: "feeds-stale", message: "I feed sono vecchi" }],
    gate: { mode: "all", effective_mode: "all" },
    ...over,
  };
}
