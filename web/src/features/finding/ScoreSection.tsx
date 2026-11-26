import type { Schemas } from "@/api/client";
import { LevelBadge } from "@/components/LevelBadge";
import { LEVEL_LABEL } from "@/lib/format";
import { VARIANT_B_UNDEFINED, evidenceEntries, fixed2, hasFallback } from "./evidence";

type Score = Schemas["VariantScore"];

const FACTORS = [
  ["g", "Gravità (G)"],
  ["p", "Probabilità (P)"],
  ["e", "Esposizione (E)"],
  ["c", "Contesto (C)"],
] as const;

/** Un fattore ha una sola evidenza per variante: `evidence.g`, `.p`, `.e`, `.c` o a livello di punteggio. */
function factorEvidence(score: Score, key: (typeof FACTORS)[number][0]): [string, string][] {
  const evidence = score.impact.evidence;
  const own = (evidence as Record<string, unknown> | undefined)?.[key];
  return evidenceEntries(own ?? {});
}

function VariantBlock({ score }: { score: Score }) {
  const { g, p, e, c } = score.impact;
  const fallback =
    score.variant === "B" && VARIANT_B_UNDEFINED.some((code) => hasFallback(score.impact.evidence, code));
  const shared = evidenceEntries(
    Object.fromEntries(
      Object.entries(score.impact.evidence ?? {}).filter(([k]) => !["g", "p", "e", "c"].includes(k)),
    ),
  );
  return (
    <section className="variant" aria-labelledby={`variant-${score.variant}`}>
      <h4 id={`variant-${score.variant}`}>Variante {score.variant}</h4>
      {fallback && <p>Variante B non configurata per questa categoria: coincide con A.</p>}
      <table className="factors">
        <caption>Fattori della variante {score.variant}</caption>
        <thead>
          <tr>
            <th scope="col">Fattore</th>
            <th scope="col">Valore</th>
            <th scope="col">Da dove viene</th>
          </tr>
        </thead>
        <tbody>
          {FACTORS.map(([key, name]) => {
            const entries = factorEvidence(score, key);
            return (
              <tr key={key}>
                <th scope="row">{name}</th>
                <td className="num">{fixed2(score.impact[key])}</td>
                <td>
                  {entries.length === 0 ? (
                    <span className="muted">—</span>
                  ) : (
                    <dl className="evidence">
                      {entries.map(([label, value]) => (
                        <div key={label}>
                          <dt>{label}</dt>
                          <dd>{value}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {shared.length > 0 && (
        <dl className="evidence">
          {shared.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      )}
      <p className="formula">
        100 × {fixed2(g)} × {fixed2(p)} × {fixed2(e)} × {fixed2(c)} = <strong>{fixed2(score.score)}</strong>
      </p>
      <p>Livello da punteggio: {LEVEL_LABEL[score.level].toLowerCase()}</p>
    </section>
  );
}

const ORIGIN: Record<NonNullable<Schemas["Finding"]["level_source"]>, string> = {
  tool_severity: "Livello provvisorio dalla severità dello strumento",
  policy: "Livello provvisorio dalla policy del repository",
  default: "Livello provvisorio predefinito",
  score: "Livello da punteggio",
  override: "Livello alzato da un override",
};

export function ScoreSection({
  level,
  source,
  scores,
}: {
  level: Schemas["Finding"]["level"];
  source: Schemas["Finding"]["level_source"];
  scores: readonly Score[];
}) {
  const a = scores.find((s) => s.variant === "A");
  const b = scores.find((s) => s.variant === "B");
  return (
    <>
      <p className="level-origin">
        <LevelBadge level={level} />{" "}
        <span>{source ? ORIGIN[source] : "Origine del livello non indicata"}</span>
      </p>
      <h4>Punteggi in ombra</h4>
      {scores.length === 0 ? (
        <p className="muted">Questa scansione non ha punteggi.</p>
      ) : (
        <>
          <p className="muted">Non decidono il livello. Servono al confronto delle due varianti.</p>
          <div className="variants">
            {a && <VariantBlock score={a} />}
            {b && <VariantBlock score={b} />}
          </div>
          {a && b && (
            <p className="compare">
              {a.level === b.level
                ? "Le due varianti coincidono."
                : `Le due varianti danno livelli diversi: A ${LEVEL_LABEL[a.level].toLowerCase()}, B ${LEVEL_LABEL[b.level].toLowerCase()}.`}
            </p>
          )}
        </>
      )}
    </>
  );
}
