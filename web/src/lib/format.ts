/** Testi e formati della UI: sempre in italiano, sempre come testo (mai HTML dal report). */
import type { Schemas } from "@/api/client";

export type Level = Schemas["Level"];
export type Status = Schemas["Status"];
export type Category = Schemas["Category"];

export const LEVELS: readonly Level[] = ["critico", "alto", "medio", "basso"];
export const LEVEL_LABEL: Record<Level, string> = {
  critico: "Critico",
  alto: "Alto",
  medio: "Medio",
  basso: "Basso",
};

export const STATUSES: readonly Status[] = [
  "aperto",
  "in_corso",
  "accettato",
  "falso_positivo",
  "risolto",
];
export const STATUS_LABEL: Record<Status, string> = {
  aperto: "Aperto",
  in_corso: "In corso",
  accettato: "Accettato",
  falso_positivo: "Falso positivo",
  risolto: "Risolto",
};

export const CATEGORIES: readonly Category[] = [
  "quality",
  "architecture",
  "test",
  "sast",
  "dependency",
  "license",
  "secret",
  "iac",
  "health",
];
export const CATEGORY_LABEL: Record<Category, string> = {
  quality: "Qualità",
  architecture: "Architettura",
  test: "Test",
  sast: "SAST",
  dependency: "Dipendenze",
  license: "Licenze",
  secret: "Segreti",
  iac: "IaC",
  health: "Salute",
};

/** "3 giorni", "5 mesi": l'età di una rilevazione, senza "fa" (la colonna dice già cos'è). */
export function age(from: string, now: Date): string {
  const seconds = Math.max(0, (now.getTime() - new Date(from).getTime()) / 1000);
  const steps: [number, Intl.NumberFormatOptions["unit"]][] = [
    [365 * 86400, "year"],
    [30 * 86400, "month"],
    [86400, "day"],
    [3600, "hour"],
    [60, "minute"],
  ];
  for (const [size, unit] of steps) {
    if (seconds >= size) {
      return new Intl.NumberFormat("it", { style: "unit", unit, unitDisplay: "long" }).format(
        Math.floor(seconds / size),
      );
    }
  }
  return "meno di un minuto";
}

export function dateTime(value: string): string {
  return new Intl.DateTimeFormat("it", { dateStyle: "long", timeStyle: "short" }).format(
    new Date(value),
  );
}

/** Percorso troncato al centro, mantenendo il nome del file: `app/…/profile.py`. */
export function middleTruncate(path: string, max = 48): string {
  if (path.length <= max) return path;
  const keep = max - 1;
  const tail = Math.ceil(keep * 0.6);
  return `${path.slice(0, keep - tail)}…${path.slice(path.length - tail)}`;
}

export function location(path: string | null | undefined, line: number | null | undefined) {
  if (path === null || path === undefined || path === "") return null;
  return line === null || line === undefined ? path : `${path}:${String(line)}`;
}

/** Gli strumenti che producono finding (plugin del prodotto): le opzioni del filtro per strumento. */
export const TOOLS: readonly string[] = [
  "bandit",
  "ca-graph",
  "checkov",
  "eslint",
  "gitleaks",
  "hadolint",
  "osv-scanner",
  "ruff",
  "scancode",
  "semgrep",
  "trivy",
];
