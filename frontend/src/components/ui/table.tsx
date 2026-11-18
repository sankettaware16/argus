import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export interface Column<T> {
  key: string;
  header: ReactNode;
  cell: (row: T, index: number) => ReactNode;
  numeric?: boolean;
}

/**
 * A plain data table: a caption for screen readers, column headers, numbers aligned right.
 * `reachable`: the table holds nothing a keyboard can reach (no link or button in it), so where
 * it scrolls sideways (320 px) the keyboard needs the scrolling region itself to be a tab stop
 * (WCAG 2.1.1; axe: scrollable-region-focusable).
 */
export function DataTable<T>({ caption, columns, rows, rowKey, empty, className, reachable = false }: { caption: string; columns: Column<T>[]; rows: readonly T[]; rowKey: (row: T, index: number) => string; empty?: ReactNode; className?: string; reachable?: boolean }) {
  if (rows.length === 0 && empty !== undefined) return <p className="m-0 text-sm text-muted">{empty}</p>;
  const scroll = reachable ? { tabIndex: 0, role: "region", "aria-label": caption } : {};
  return (
    <div className={cn("relative overflow-x-auto", className)} {...scroll}>
      <table className="w-full border-collapse text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col" className={cn("border-b border-border px-3 py-2 text-left text-xs font-medium text-muted", c.numeric && "text-right")}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={rowKey(row, i)} className="border-b border-border last:border-b-0">
              {columns.map((c) => (
                <td key={c.key} className={cn("px-3 py-2 align-top", c.numeric && "text-right tabular-nums")}>
                  {c.cell(row, i)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
