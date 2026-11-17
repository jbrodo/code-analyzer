import { DropdownMenu } from "radix-ui";
import { useEffect, useId, useState } from "react";

import {
  CATEGORIES,
  CATEGORY_LABEL,
  LEVELS,
  LEVEL_LABEL,
  STATUSES,
  STATUS_LABEL,
  TOOLS,
} from "@/lib/format";
import type { Filters } from "./filters";
import { DEFAULT_STATUS, activeFilterCount } from "./filters";

interface Props {
  filters: Filters;
  onChange: (next: Filters) => void;
  /** Numero di finding con i filtri attivi, e quanti sono nuovi; `null` mentre si carica. */
  total: number | null;
  totalNew: number | null;
  searchRef: React.RefObject<HTMLInputElement | null>;
}

interface MultiProps<T extends string> {
  label: string;
  options: readonly T[];
  labels: Partial<Record<T, string>>;
  selected: readonly T[];
  onChange: (next: T[]) => void;
}

/** Un filtro a scelta multipla: un menu di caselle, con il fuoco gestito dal componente Radix. */
function MultiFilter<T extends string>({ label, options, labels, selected, onChange }: MultiProps<T>) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="control" aria-label={`Filtro ${label}`}>
        {label}
        {selected.length > 0 ? ` (${String(selected.length)})` : ""}
        <span aria-hidden="true"> ▾</span>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="menu" align="start" sideOffset={4}>
          {options.map((option) => (
            <DropdownMenu.CheckboxItem
              key={option}
              className="menu-item"
              checked={selected.includes(option)}
              onSelect={(event) => {
                event.preventDefault(); // il menu resta aperto: si scelgono più valori di fila
              }}
              onCheckedChange={(checked) => {
                onChange(checked ? [...selected, option] : selected.filter((s) => s !== option));
              }}
            >
              <DropdownMenu.ItemIndicator className="menu-check">✓</DropdownMenu.ItemIndicator>
              {labels[option] ?? option}
            </DropdownMenu.CheckboxItem>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function SearchBox({ value, onCommit, inputRef }: {
  value: string;
  onCommit: (next: string) => void;
  inputRef: React.RefObject<HTMLInputElement | null>;
}) {
  const id = useId();
  const [text, setText] = useState(value);
  const [seen, setSeen] = useState(value);
  if (seen !== value) {
    // l'indirizzo è cambiato da fuori (azzeramento dei filtri): il campo lo segue
    setSeen(value);
    setText(value);
  }
  useEffect(() => {
    if (text === value) return;
    const timer = setTimeout(() => {
      onCommit(text);
    }, 300);
    return () => {
      clearTimeout(timer);
    };
  }, [text, value, onCommit]);
  return (
    <div className="field">
      <label htmlFor={id}>Cerca</label>
      <input
        id={id}
        ref={inputRef}
        type="search"
        value={text}
        maxLength={200}
        placeholder="Titolo, regola o percorso"
        autoComplete="off"
        onChange={(event) => {
          setText(event.target.value);
        }}
      />
    </div>
  );
}

export function FilterBar({ filters, onChange, total, totalNew, searchRef }: Props) {
  const set = (patch: Partial<Filters>) => {
    onChange({ ...filters, ...patch });
  };
  const chips: { key: string; name: string; remove: () => void }[] = [
    ...filters.level.map((v) => ({
      key: `level-${v}`,
      name: `livello ${LEVEL_LABEL[v]}`,
      remove: () => {
        set({ level: filters.level.filter((x) => x !== v) });
      },
    })),
    ...filters.category.map((v) => ({
      key: `category-${v}`,
      name: `categoria ${CATEGORY_LABEL[v]}`,
      remove: () => {
        set({ category: filters.category.filter((x) => x !== v) });
      },
    })),
    ...filters.tool.map((v) => ({
      key: `tool-${v}`,
      name: `strumento ${v}`,
      remove: () => {
        set({ tool: filters.tool.filter((x) => x !== v) });
      },
    })),
  ];
  const statusIsDefault =
    filters.status !== null &&
    filters.status.length === DEFAULT_STATUS.length &&
    DEFAULT_STATUS.every((s) => filters.status?.includes(s));
  if (filters.status === null) {
    chips.push({ key: "status-any", name: "tutti gli stati", remove: () => { set({ status: [...DEFAULT_STATUS] }); } });
  } else if (!statusIsDefault) {
    for (const v of filters.status) {
      chips.push({
        key: `status-${v}`,
        name: `stato ${STATUS_LABEL[v]}`,
        remove: () => {
          const rest = (filters.status ?? []).filter((x) => x !== v);
          set({ status: rest.length > 0 ? rest : [...DEFAULT_STATUS] });
        },
      });
    }
  }
  if (filters.q !== "") {
    chips.push({ key: "q", name: `ricerca “${filters.q}”`, remove: () => { set({ q: "" }); } });
  }
  const active = activeFilterCount(filters);

  return (
    <section className="filters" aria-label="Filtri">
      <div className="filters-row">
        <SearchBox value={filters.q} onCommit={(q) => { set({ q }); }} inputRef={searchRef} />
        <MultiFilter label="Livello" options={LEVELS} labels={LEVEL_LABEL} selected={filters.level} onChange={(level) => { set({ level }); }} />
        <MultiFilter label="Categoria" options={CATEGORIES} labels={CATEGORY_LABEL} selected={filters.category} onChange={(category) => { set({ category }); }} />
        <MultiFilter
          label="Stato"
          options={STATUSES}
          labels={STATUS_LABEL}
          selected={filters.status ?? []}
          onChange={(status) => { set({ status: status.length > 0 ? status : null }); }}
        />
        <MultiFilter label="Strumento" options={TOOLS} labels={{}} selected={filters.tool} onChange={(tool) => { set({ tool }); }} />
        <label className="toggle">
          <input type="checkbox" checked={filters.onlyNew} onChange={(event) => { set({ onlyNew: event.target.checked }); }} />
          Solo nuovi{totalNew !== null ? ` (${String(totalNew)})` : ""}
        </label>
      </div>
      <div className="filters-row filters-summary">
        {chips.length > 0 && (
          <ul className="chips" aria-label="Filtri attivi">
            {chips.map((chip) => (
              <li key={chip.key}>
                <button type="button" className="chip" aria-label={`Rimuovi filtro ${chip.name}`} onClick={chip.remove}>
                  {chip.name} <span aria-hidden="true">×</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        {active > 0 && (
          <button
            type="button"
            className="link-button"
            onClick={() => {
              onChange({ ...filters, level: [], category: [], tool: [], onlyNew: false, q: "", status: [...DEFAULT_STATUS] });
            }}
          >
            Azzera filtri
          </button>
        )}
        <p className="count" aria-hidden={total === null}>
          {total === null ? "" : `${String(total)} finding`}
        </p>
      </div>
    </section>
  );
}
