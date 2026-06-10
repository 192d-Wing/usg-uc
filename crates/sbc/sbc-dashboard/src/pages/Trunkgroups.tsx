import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type TrunkGroup = {
  id?: string;
  name?: string;
  description?: string;
  trunks?: Array<{ id?: string; host?: string; port?: number; transport?: string }>;
};

function trunkGroupSearchText(g: TrunkGroup): string {
  return `${g.name ?? ''} ${g.description ?? ''} ${g.id ?? ''}`;
}

export function Trunkgroups() {
  // The API returns the field as `trunk_groups` or `trunkgroups` depending
  // on the daemon version; tolerate both.
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<TrunkGroup>('/trunkgroups', (r) => r.trunk_groups ?? r.trunkgroups ?? [], {
      searchText: trunkGroupSearchText,
    });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="SIP trunk groups for outbound call routing."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Route Groups
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading trunk groups…"
        variant="full-page"
        stickyHeader
        trackBy={(g) => g.id ?? g.name ?? ''}
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (g) => g.name ?? '—', isRowHeader: true },
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
              <b>No trunk groups</b>
              <span>Create one via POST /api/v1/trunkgroups.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
