import { Link } from "react-router";
import { useRef } from "react";

import type { Schemas } from "@/api/client";
import { LevelBadge } from "@/components/LevelBadge";
import {
  CATEGORY_LABEL,
  LEVEL_LABEL,
  STATUS_LABEL,
  age,
  location,
  middleTruncate,
} from "@/lib/format";
import type { Sort } from "./filters";

type Item = Schemas["FindingListItem"];

interface Props {
  caption: string;
  items: readonly Item[];
  loading: boolean;
  selectedId: string | null;
  sort: Sort;
  now: Date;
  /** Indirizzo del dettaglio di un finding, con i filtri correnti. */
  hrefFor: (id: string) => string;
  onSort: (sort: Sort) => void;
  onFocusSearch: () => void;
  /** Il testo da mostrare al posto delle righe (vuoto, errore), con il suo rimedio. */
  empty: React.ReactNode | null;
  footer: React.ReactNode;
}

const SORTABLE: { sort: Sort; label: string; column: string }[] = [
  { sort: "impact", label: "Livello", column: "level" },
  { sort: "path", label: "Posizione", column: "path" },
  { sort: "first_seen", label: "Prima rilevazione", column: "seen" },
];

function SkeletonRows() {
  return Array.from({ length: 8 }, (_, i) => (
    <tr key={i} className="row-skeleton" aria-hidden="true">
      <td colSpan={8}>
        <span className="skeleton-bar" />
      </td>
    </tr>
  ));
}

function dueNote(item: Item): string | null {
  if (item.status !== "accettato" || item.exception_origin === null || item.exception_origin === undefined) return null;
  return item.exception_origin === "server" ? "dal server" : "dal repository";
}

export function FindingsTable({
  caption, items, loading, selectedId, sort, now, hrefFor, onSort, onFocusSearch, empty, footer,
}: Props) {
  const body = useRef<HTMLTableSectionElement>(null);

  const move = (from: HTMLElement, delta: number | "first" | "last") => {
    const links = Array.from(body.current?.querySelectorAll<HTMLElement>("a[data-row-link]") ?? []);
    const at = links.indexOf(from);
    const target =
      delta === "first" ? links[0] : delta === "last" ? links[links.length - 1] : links[at + delta];
    target?.focus();
  };

  // Le scorciatoie a un carattere valgono solo con il fuoco dentro la tabella (L4).
  // Dal riquadro stesso, raggiungibile col Tab, i tasti di movimento portano alla prima riga.
  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const from = event.target as HTMLElement;
    const onRegion = from === event.currentTarget;
    if (!(onRegion || from.matches("a[data-row-link]")) || event.ctrlKey || event.metaKey || event.altKey) return;
    // senza righe i tasti restano al browser (scorrimento del riquadro)
    if (onRegion && event.key !== "/" && body.current?.querySelector("a[data-row-link]") === null) return;
    const handled = (() => {
      switch (event.key) {
        case "ArrowDown":
        case "j":
          move(from, onRegion ? "first" : 1);
          return true;
        case "ArrowUp":
        case "k":
          move(from, onRegion ? "first" : -1);
          return true;
        case "Home":
          move(from, "first");
          return true;
        case "End":
          move(from, "last");
          return true;
        case "/":
          onFocusSearch();
          return true;
        default:
          return false;
      }
    })();
    if (handled) event.preventDefault();
  };

  const ariaSort = (column: Sort): "ascending" | "none" => (sort === column ? "ascending" : "none");

  return (
    <div className="table-region" role="region" aria-label="Elenco dei finding" tabIndex={0} onKeyDown={onKeyDown}>
      <table className="findings" aria-busy={loading}>
        <caption>{caption}</caption>
        <thead>
          <tr>
            {SORTABLE.slice(0, 1).map((c) => (
              <th key={c.sort} scope="col" className="col-level" aria-sort={ariaSort(c.sort)}>
                <button type="button" className="sort" onClick={() => { onSort(c.sort); }}>
                  {c.label}
                </button>
              </th>
            ))}
            <th scope="col" className="col-problem">Problema</th>
            <th scope="col" className="col-category">Categoria</th>
            <th scope="col" className="col-path" aria-sort={ariaSort("path")}>
              <button type="button" className="sort" onClick={() => { onSort("path"); }}>Posizione</button>
            </th>
            <th scope="col" className="col-status">Stato</th>
            <th scope="col" className="col-new">Novità</th>
            <th scope="col" className="col-seen" aria-sort={ariaSort("first_seen")}>
              <button type="button" className="sort" onClick={() => { onSort("first_seen"); }}>Prima rilevazione</button>
            </th>
            <th scope="col" className="col-owner">Assegnato a</th>
          </tr>
        </thead>
        <tbody ref={body}>
          {loading && items.length === 0 ? <SkeletonRows /> : null}
          {items.map((item) => {
            const place = location(item.path, item.start_line);
            const note = dueNote(item);
            return (
              <tr key={item.id} data-selected={item.id === selectedId} aria-current={item.id === selectedId ? "true" : undefined}>
                <td className="col-level"><LevelBadge level={item.level} /></td>
                <td className="col-problem">
                  <Link
                    to={hrefFor(item.id)}
                    data-row-link=""
                    className="row-link"
                    aria-label={`${item.level ? LEVEL_LABEL[item.level] : "Senza livello"}: ${item.title}`}
                  >
                    {item.title}
                  </Link>
                  <span className="rule">{item.rule_id}</span>
                </td>
                <td className="col-category">{CATEGORY_LABEL[item.category]}</td>
                <td className="col-path mono" title={place ?? undefined}>
                  {place === null ? (
                    "—"
                  ) : (
                    <>
                      <span aria-hidden="true">{middleTruncate(place)}</span>
                      <span className="visually-hidden">{place}</span>
                    </>
                  )}
                </td>
                <td className="col-status">
                  <span className={item.status === "aperto" ? "muted" : undefined}>{STATUS_LABEL[item.status]}</span>
                  {note !== null && <span className="sub">{note}</span>}
                </td>
                <td className="col-new">{item.new === true ? <strong className="new">Nuovo</strong> : null}</td>
                <td className="col-seen">{item.first_seen ? age(item.first_seen, now) : "—"}</td>
                <td className="col-owner">{item.owner ?? "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {empty !== null && <div className="table-empty">{empty}</div>}
      {footer}
    </div>
  );
}
