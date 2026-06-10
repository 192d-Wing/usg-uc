import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type DirectoryNumber = {
  did: string;
  user?: string;
  partition?: string;
  description?: string;
};

function directorySearchText(d: DirectoryNumber): string {
  return `${d.did} ${d.user ?? ''} ${d.partition ?? ''} ${d.description ?? ''}`;
}

export function Directory() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<DirectoryNumber>('/directory', (r) => r.directory_numbers ?? [], {
      searchText: directorySearchText,
    });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Provisioned directory numbers and their owning users."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Directory Numbers
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading directory numbers…"
        variant="full-page"
        stickyHeader
        trackBy="did"
        columnDefinitions={[
          { id: 'did', header: 'Number', cell: (d) => d.did, isRowHeader: true },
          { id: 'user', header: 'User', cell: (d) => d.user ?? '—' },
          { id: 'partition', header: 'Partition', cell: (d) => d.partition ?? '—' },
          { id: 'description', header: 'Description', cell: (d) => d.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by number / user / partition"
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
              <b>No directory numbers</b>
              <span>Create one via POST /api/v1/directory.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
