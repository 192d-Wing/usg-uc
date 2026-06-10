import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type RouteList = {
  id: string;
  name?: string;
  member_count?: number;
};

function routeListSearchText(l: RouteList): string {
  return `${l.id} ${l.name ?? ''}`;
}

export function RouteLists() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<RouteList>('/routelists', (r) => r.route_lists ?? [], {
      searchText: routeListSearchText,
    });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Ordered route group lists used by route patterns to direct outbound calls."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Route Lists
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading route lists…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (l) => l.name ?? l.id, isRowHeader: true },
          { id: 'id', header: 'ID', cell: (l) => l.id },
          { id: 'members', header: 'Members', cell: (l) => l.member_count ?? 0 },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find route list"
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
              <b>No route lists</b>
              <span>Create one via POST /api/v1/routelists.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
