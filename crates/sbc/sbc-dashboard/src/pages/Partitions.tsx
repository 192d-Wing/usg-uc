import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type Partition = {
  id: string;
  name?: string;
  description?: string | null;
};

export function Partitions() {
  const [items, setItems] = useState<Partition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ partitions: Partition[] }>('/partitions');
      setItems(res.partitions ?? []);
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
    ? items.filter((p) =>
        `${p.id} ${p.name ?? ''} ${p.description ?? ''}`.toLowerCase().includes(filter.toLowerCase()),
      )
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Route partitions — groupings used by Calling Search Spaces to scope what numbers a caller can reach."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Partitions
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading partitions…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (p) => p.name ?? p.id, isRowHeader: true, sortingField: 'name' },
          { id: 'id', header: 'ID', cell: (p) => p.id },
          { id: 'description', header: 'Description', cell: (p) => p.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find partition"
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
              <b>No partitions</b>
              <span>Create one via POST /api/v1/partitions.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
