import { useEffect, useState } from 'react';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type Css = {
  id: string;
  name?: string;
  partitions?: string[];
  partition_count?: number;
};

function PartitionBadges({ cssId, partitions }: Readonly<{ cssId: string; partitions?: string[] }>) {
  if (!partitions?.length) {
    return <Box variant="small">none</Box>;
  }
  return (
    <SpaceBetween direction="horizontal" size="xxs">
      {partitions.map((p, i) => (
        <Badge key={`${cssId}-${i}-${p}`}>{`${i + 1}. ${p}`}</Badge>
      ))}
    </SpaceBetween>
  );
}

function renderPartitionsCell(c: Css) {
  return <PartitionBadges cssId={c.id} partitions={c.partitions} />;
}

export function CallingSearchSpaces() {
  const [items, setItems] = useState<Css[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ calling_search_spaces: Css[] }>('/css');
      setItems(res.calling_search_spaces ?? []);
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
    ? items.filter((c) => {
        const hay = `${c.id} ${c.name ?? ''} ${(c.partitions ?? []).join(' ')}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Ordered partition lists that determine which numbers a caller can reach. First match wins."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Calling Search Spaces
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading calling search spaces…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (c) => c.name ?? c.id, isRowHeader: true, sortingField: 'name' },
          { id: 'id', header: 'ID', cell: (c) => c.id },
          {
            id: 'partitions',
            header: 'Partitions (in search order)',
            cell: renderPartitionsCell,
          },
          {
            id: 'count',
            header: 'Count',
            cell: (c) => c.partition_count ?? c.partitions?.length ?? 0,
            sortingField: 'partition_count',
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find CSS by name / partition"
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
              <b>No calling search spaces</b>
              <span>Create one via POST /api/v1/css.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
