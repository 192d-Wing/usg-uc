import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type TrunkGroup = {
  id?: string;
  name?: string;
  description?: string;
  trunks?: Array<{ id?: string; host?: string; port?: number; transport?: string }>;
};

export function Trunkgroups() {
  const [items, setItems] = useState<TrunkGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ trunk_groups: TrunkGroup[] } | { trunkgroups: TrunkGroup[] }>(
        '/trunkgroups',
      );
      // The API returns the field as `trunk_groups` or `trunkgroups` depending
      // on the daemon version; tolerate both.
      const list =
        (res as { trunk_groups?: TrunkGroup[] }).trunk_groups ??
        (res as { trunkgroups?: TrunkGroup[] }).trunkgroups ??
        [];
      setItems(list);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const filtered = filter
    ? items.filter((g) => {
        const hay = `${g.name ?? ''} ${g.description ?? ''} ${g.id ?? ''}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="SIP trunk groups for outbound call routing."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Route Groups
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading trunk groups…"
        variant="full-page"
        stickyHeader
        trackBy={(g) => g.id ?? g.name ?? ''}
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (g) => g.name ?? '—', isRowHeader: true, sortingField: 'name' },
          { id: 'description', header: 'Description', cell: (g) => g.description ?? '—' },
          {
            id: 'trunks',
            header: 'Trunks',
            cell: (g) =>
              g.trunks?.length
                ? g.trunks.map((t) => `${t.host ?? '?'}:${t.port ?? ''}${t.transport ? `/${t.transport}` : ''}`).join(', ')
                : '0',
          },
          { id: 'id', header: 'ID', cell: (g) => g.id ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find trunk group"
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
              <b>No trunk groups</b>
              <span>Create one via POST /api/v1/trunkgroups.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
