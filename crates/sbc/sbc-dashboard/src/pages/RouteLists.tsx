import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type RouteList = {
  id: string;
  name?: string;
  member_count?: number;
};

export function RouteLists() {
  const [items, setItems] = useState<RouteList[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ route_lists: RouteList[] }>('/routelists');
      setItems(res.route_lists ?? []);
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
    ? items.filter((l) => `${l.id} ${l.name ?? ''}`.toLowerCase().includes(filter.toLowerCase()))
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Ordered route group lists used by route patterns to direct outbound calls."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Route Lists
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading route lists…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (l) => l.name ?? l.id, isRowHeader: true, sortingField: 'name' },
          { id: 'id', header: 'ID', cell: (l) => l.id },
          { id: 'members', header: 'Members', cell: (l) => l.member_count ?? 0, sortingField: 'member_count' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find route list"
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
              <b>No route lists</b>
              <span>Create one via POST /api/v1/routelists.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
