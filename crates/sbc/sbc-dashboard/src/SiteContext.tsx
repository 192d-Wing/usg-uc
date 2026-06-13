// Site selection for the central config surface.
//
// Central config is sharded by site, so the config pages need a "current
// site". This context fetches the site list from the central API once the
// operator is authenticated, holds the selection (persisted), and exposes a
// selector for the top nav. Config pages read `useSite()` and re-load when it
// changes; runtime pages ignore it.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import Select from '@cloudscape-design/components/select';

import { centralApi, type SiteInfo } from './centralApi';

const STORAGE_KEY = 'sbc.central.site';

type SiteContextValue = {
  /** Currently selected site code, or null before sites load / none exist. */
  site: string | null;
  /** All registered sites. */
  sites: SiteInfo[];
  /** Select a site (persisted). */
  setSite: (code: string) => void;
  /** Re-fetch the site list. */
  reload: () => void;
  loading: boolean;
  error: string | null;
};

const Ctx = createContext<SiteContextValue | null>(null);

export function SiteProvider({ children }: { children: ReactNode }) {
  const [sites, setSites] = useState<SiteInfo[]>([]);
  const [site, setSiteState] = useState<string | null>(localStorage.getItem(STORAGE_KEY));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const setSite = useCallback((code: string) => {
    localStorage.setItem(STORAGE_KEY, code);
    setSiteState(code);
  }, []);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    centralApi
      .listSites()
      .then((list) => {
        setSites(list);
        // Default the selection to the stored site if still present, else
        // the first site.
        setSiteState((cur) => {
          if (cur && list.some((s) => s.site_code === cur)) return cur;
          const first = list[0]?.site_code ?? null;
          if (first) localStorage.setItem(STORAGE_KEY, first);
          return first;
        });
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const value = useMemo(
    () => ({ site, sites, setSite, reload, loading, error }),
    [site, sites, setSite, reload, loading, error],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Access the site context. Throws if used outside [`SiteProvider`]. */
export function useSite(): SiteContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('useSite must be used within SiteProvider');
  return v;
}

/** Top-nav dropdown for choosing the active site. */
export function SiteSelector() {
  const { site, sites, setSite } = useSite();
  const options = sites.map((s) => ({
    value: s.site_code,
    label: s.site_code,
    description: s.display_name !== s.site_code ? s.display_name : undefined,
  }));
  const selected = options.find((o) => o.value === site) ?? null;
  return (
    <Select
      selectedOption={selected}
      onChange={({ detail }) => {
        if (detail.selectedOption?.value) setSite(detail.selectedOption.value);
      }}
      options={options}
      placeholder="Select site"
      ariaLabel="Active site"
      expandToViewport
    />
  );
}
