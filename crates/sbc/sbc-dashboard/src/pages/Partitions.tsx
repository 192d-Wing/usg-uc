import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type Partition = {
  id: string;
  name?: string;
  description?: string | null;
};

function partitionSearchText(p: Partition): string {
  return `${p.id} ${p.name ?? ''} ${p.description ?? ''}`;
}

export function Partitions() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<Partition>('/partitions', (r) => r.partitions ?? [], {
      searchText: partitionSearchText,
    });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Route partitions — groupings used by Calling Search Spaces to scope what numbers a caller can reach."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Partitions
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading partitions…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (p) => p.name ?? p.id, isRowHeader: true },
          { id: 'id', header: 'ID', cell: (p) => p.id },
          { id: 'description', header: 'Description', cell: (p) => p.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find partition"
            filteringText={filterText}
            onChange={({ detail }) => setFilterText(detail.filteringText)}
            countText={`${filteredItems.length} matches`}
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
