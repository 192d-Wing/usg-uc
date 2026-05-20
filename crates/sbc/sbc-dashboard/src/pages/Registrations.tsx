import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type Registration = {
  aor: string;
  contact: string;
  expires?: number;
  registered_at?: number;
};

export function Registrations() {
  const [items, setItems] = useState<Registration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ registrations: Registration[] }>('/registrations');
      setItems(res.registrations ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const id = globalThis.setInterval(load, 15_000);
    return () => globalThis.clearInterval(id);
  }, []);

  const filtered = filter
    ? items.filter((r) => `${r.aor} ${r.contact}`.toLowerCase().includes(filter.toLowerCase()))
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Live SIP registration bindings. Auto-refreshes every 15s."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Registrations
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading registrations…"
        variant="full-page"
        stickyHeader
        trackBy={(r) => `${r.aor}|${r.contact}`}
        columnDefinitions={[
          { id: 'aor', header: 'Address of Record', cell: (r) => r.aor, isRowHeader: true, sortingField: 'aor' },
          { id: 'contact', header: 'Contact', cell: (r) => r.contact },
          {
            id: 'expires',
            header: 'Expires (s)',
            cell: (r) => r.expires ?? '—',
            sortingField: 'expires',
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by AOR or contact"
            filteringText={filter}
            onChange={({ detail }) => setFilter(detail.filteringText)}
            countText={`${filtered.length} matches`}
          />
        }
        empty={
          error ? (
            <StatusIndicator type="error">{error}</StatusIndicator>
          ) : (
            <SpaceBetween size="xxs" alignItems="center">
              <b>No active registrations</b>
              <span>No SIP endpoints are currently registered with this SBC.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
