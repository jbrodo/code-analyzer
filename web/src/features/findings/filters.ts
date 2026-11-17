/** Filtri, ordinamento e selezione della lista: stanno tutti nell'indirizzo (U-01). */
import { CATEGORIES, LEVELS, STATUSES } from "@/lib/format";
import type { Category, Level, Status } from "@/lib/format";

export const SORTS = ["impact", "first_seen", "path", "score_a", "score_b"] as const;
export type Sort = (typeof SORTS)[number];

/** Predefinito di U-01: aperti e in corso. `status=any` toglie il filtro. */
export const DEFAULT_STATUS: readonly Status[] = ["aperto", "in_corso"];

export interface Filters {
  level: Level[];
  category: Category[];
  /** `null` = nessun filtro sullo stato (`status=any`). */
  status: Status[] | null;
  tool: string[];
  onlyNew: boolean;
  q: string;
  sort: Sort;
  /** Scansione in esame (una PR); assente = la scansione corrente del repository. */
  scan: string | null;
}

function pick<T extends string>(values: string[], allowed: readonly T[]): T[] {
  return allowed.filter((item) => values.includes(item));
}

export function parseFilters(params: URLSearchParams): Filters {
  const rawStatus = params.getAll("status");
  const sort = params.get("sort");
  return {
    level: pick(params.getAll("level"), LEVELS),
    category: pick(params.getAll("category"), CATEGORIES),
    status: rawStatus.includes("any")
      ? null
      : rawStatus.length === 0
        ? [...DEFAULT_STATUS]
        : pick(rawStatus, STATUSES),
    tool: params
      .getAll("tool")
      .filter((t) => t !== "" && t.length <= 100)
      .slice(0, 20),
    onlyNew: params.get("new") === "true",
    q: (params.get("q") ?? "").slice(0, 200),
    sort: SORTS.find((s) => s === sort) ?? "impact",
    scan: /^[0-9a-f-]{36}$/.test(params.get("scan") ?? "") ? params.get("scan") : null,
  };
}

const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((x) => b.includes(x));

/** Il contrario di `parseFilters`: solo ciò che si scosta dal predefinito entra nell'indirizzo. */
export function toParams(filters: Filters, keep: URLSearchParams = new URLSearchParams()) {
  const params = new URLSearchParams();
  for (const name of ["scan"]) if (keep.has(name) && filters.scan === null) params.delete(name);
  filters.level.forEach((v) => {
    params.append("level", v);
  });
  filters.category.forEach((v) => {
    params.append("category", v);
  });
  if (filters.status === null) params.append("status", "any");
  else if (!sameSet(filters.status, DEFAULT_STATUS)) {
    filters.status.forEach((v) => {
      params.append("status", v);
    });
    if (filters.status.length === 0) params.append("status", "any");
  }
  filters.tool.forEach((v) => {
    params.append("tool", v);
  });
  if (filters.onlyNew) params.set("new", "true");
  if (filters.q !== "") params.set("q", filters.q);
  if (filters.sort !== "impact") params.set("sort", filters.sort);
  if (filters.scan !== null) params.set("scan", filters.scan);
  return params;
}

export function activeFilterCount(filters: Filters): number {
  return (
    filters.level.length +
    filters.category.length +
    filters.tool.length +
    (filters.onlyNew ? 1 : 0) +
    (filters.q === "" ? 0 : 1) +
    (filters.status !== null && sameSet(filters.status, DEFAULT_STATUS) ? 0 : 1)
  );
}

/** I parametri della richiesta all'API; l'ordinamento e il cursore li aggiunge chi chiama. */
export function toQuery(filters: Filters) {
  return {
    ...(filters.level.length > 0 ? { level: filters.level } : {}),
    ...(filters.category.length > 0 ? { category: filters.category } : {}),
    ...(filters.status !== null && filters.status.length > 0 ? { status: filters.status } : {}),
    ...(filters.tool.length > 0 ? { tool: filters.tool } : {}),
    ...(filters.onlyNew ? { new: true } : {}),
    ...(filters.q.length >= 2 ? { q: filters.q } : {}),
    ...(filters.scan !== null ? { scan: filters.scan } : {}),
    sort: filters.sort,
  };
}
