import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type DirectoryNumber = {
  did: string;
  user?: string;
  partition?: string;
  description?: string;
};

export function Directory() {
  const [items, setItems] = useState<DirectoryNumber[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ directory_numbers: DirectoryNumber[] }>('/directory');
      setItems(res.directory_numbers ?? []);
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
    ? items.filter((d) =>
        `${d.did} ${d.user ?? ''} ${d.partition ?? ''} ${d.description ?? ''}`
          .toLowerCase()
          .includes(filter.toLowerCase()),
      )
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Provisioned directory numbers and their owning users."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Directory Numbers
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading directory numbers…"
        variant="full-page"
        stickyHeader
        trackBy="did"
        columnDefinitions={[
          { id: 'did', header: 'Number', cell: (d) => d.did, isRowHeader: true, sortingField: 'did' },
          { id: 'user', header: 'User', cell: (d) => d.user ?? '—' },
          { id: 'partition', header: 'Partition', cell: (d) => d.partition ?? '—' },
          { id: 'description', header: 'Description', cell: (d) => d.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by number / user / partition"
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
              <b>No directory numbers</b>
              <span>Create one via POST /api/v1/directory.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
