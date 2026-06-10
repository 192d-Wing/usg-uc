// Shared list-page state: load + error formatting + text filtering + optional
// polling. Used by all nine table pages so they don't each re-implement the
// items/loading/error/filter dance.
//
// Polling never blanks the table: only the initial load and explicit reload()
// set loading=true; background polls swap the data in place. A sequence
// counter guards against out-of-order responses (a slow poll resolving after
// a newer reload must not overwrite the newer data).

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api, ApiError } from '../api';

export type UseApiListOptions<T> = {
  /** Poll interval in milliseconds. Background polls don't toggle `loading`. */
  readonly pollMs?: number;
  /** Haystack builder for case-insensitive substring filtering. */
  readonly searchText?: (item: T) => string;
};

export type UseApiListResult<T> = {
  readonly items: T[];
  readonly filteredItems: T[];
  readonly loading: boolean;
  readonly error: string | null;
  readonly filterText: string;
  readonly setFilterText: (text: string) => void;
  readonly reload: () => void;
};

export function useApiList<T>(
  path: string,
  // `any` is deliberate: each page narrows the daemon's response envelope
  // (e.g. { users: [...] } vs { trunk_groups: [...] }) in its extract fn.
  extract: (resp: any) => T[],
  opts?: UseApiListOptions<T>,
): UseApiListResult<T> {
  const [items, setItems] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterText, setFilterText] = useState('');

  // Monotonic sequence: each request takes a ticket; only the most recent
  // ticket is allowed to commit state (stale-response guard).
  const seqRef = useRef(0);
  const mountedRef = useRef(true);
  // Keep the latest extract without making it a load() dependency, so callers
  // can pass inline arrow functions.
  const extractRef = useRef(extract);
  extractRef.current = extract;

  const load = useCallback(
    async (background: boolean) => {
      const seq = ++seqRef.current;
      if (!background) {
        setLoading(true);
        setError(null);
      }
      try {
        const resp = await api.get<unknown>(path);
        if (!mountedRef.current || seq !== seqRef.current) return;
        setItems(extractRef.current(resp) ?? []);
        setError(null);
      } catch (e) {
        if (!mountedRef.current || seq !== seqRef.current) return;
        setError(e instanceof ApiError ? e.message : String(e));
      } finally {
        // Latest request always clears the spinner, even if it was a
        // background poll that superseded an in-flight manual load.
        if (mountedRef.current && seq === seqRef.current) {
          setLoading(false);
        }
      }
    },
    [path],
  );

  const pollMs = opts?.pollMs;

  useEffect(() => {
    mountedRef.current = true;
    void load(false);
    const intervalId =
      pollMs && pollMs > 0 ? globalThis.setInterval(() => void load(true), pollMs) : undefined;
    return () => {
      mountedRef.current = false;
      if (intervalId !== undefined) {
        globalThis.clearInterval(intervalId);
      }
    };
  }, [load, pollMs]);

  const reload = useCallback(() => {
    void load(false);
  }, [load]);

  const searchText = opts?.searchText;
  const filteredItems = useMemo(() => {
    if (!filterText || !searchText) return items;
    const needle = filterText.toLowerCase();
    return items.filter((item) => searchText(item).toLowerCase().includes(needle));
  }, [items, filterText, searchText]);

  return { items, filteredItems, loading, error, filterText, setFilterText, reload };
}
