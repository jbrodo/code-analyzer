import { LEVEL_LABEL } from "@/lib/format";
import type { Level } from "@/lib/format";

/** Il livello è sempre una parola: il colore l'accompagna, non la sostituisce (G7, L6). */
export function LevelBadge({ level }: { level: Level | null | undefined }) {
  const tone = level ?? "basso";
  return (
    <span className="level-badge" data-level={tone}>
      {level === null || level === undefined ? "Senza livello" : LEVEL_LABEL[level]}
    </span>
  );
}
