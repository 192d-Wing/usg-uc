import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

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

function cssSearchText(c: Css): string {
  return `${c.id} ${c.name ?? ''} ${(c.partitions ?? []).join(' ')}`;
}

export function CallingSearchSpaces() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<Css>('/css', (r) => r.calling_search_spaces ?? [], { searchText: cssSearchText });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Ordered partition lists that determine which numbers a caller can reach. First match wins."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Calling Search Spaces
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading calling search spaces…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (c) => c.name ?? c.id, isRowHeader: true },
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
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find CSS by name / partition"
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
              <b>No calling search spaces</b>
              <span>Create one via POST /api/v1/css.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
