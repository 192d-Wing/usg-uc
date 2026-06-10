import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type RoutePattern = {
  id: string;
  pattern: string;
  partition_id?: string | null;
  route_list_id?: string | null;
  route_group_id?: string | null;
  description?: string | null;
  priority?: number;
  blocked?: boolean;
};

function BlockedIndicator({ blocked }: Readonly<{ blocked?: boolean }>) {
  return blocked ? (
    <StatusIndicator type="stopped">Blocked</StatusIndicator>
  ) : (
    <StatusIndicator type="success">Active</StatusIndicator>
  );
}

function TargetCell({ pattern }: Readonly<{ pattern: RoutePattern }>) {
  if (pattern.route_list_id) {
    return (
      <Box>
        <Box variant="small">list</Box>
        {pattern.route_list_id}
      </Box>
    );
  }
  if (pattern.route_group_id) {
    return (
      <Box>
        <Box variant="small">group</Box>
        {pattern.route_group_id}
      </Box>
    );
  }
  return <span>—</span>;
}

// Module-scope cell renderers — defined here (not inline inside the page
// component) so Sonar S6478 doesn't see them as nested component definitions.
function renderTargetCell(p: RoutePattern) {
  return <TargetCell pattern={p} />;
}

function renderBlockedCell(p: RoutePattern) {
  return <BlockedIndicator blocked={p.blocked} />;
}

function routePatternSearchText(p: RoutePattern): string {
  return `${p.pattern} ${p.partition_id ?? ''} ${p.route_list_id ?? ''} ${p.route_group_id ?? ''} ${p.description ?? ''}`;
}

export function RoutePatterns() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<RoutePattern>('/routepatterns', (r) => r.route_patterns ?? [], {
      searchText: routePatternSearchText,
    });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Dial patterns mapped to a route list or group. See docs/route-patterns.md for syntax."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Route Patterns
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading route patterns…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          {
            id: 'pattern',
            header: 'Pattern',
            cell: (p) => p.pattern,
            isRowHeader: true,
          },
          { id: 'partition', header: 'Partition', cell: (p) => p.partition_id ?? '—' },
          { id: 'target', header: 'Target', cell: renderTargetCell },
          { id: 'priority', header: 'Priority', cell: (p) => p.priority ?? 0 },
          { id: 'status', header: 'Status', cell: renderBlockedCell },
          { id: 'description', header: 'Description', cell: (p) => p.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by pattern / partition / target"
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
              <b>No route patterns</b>
              <span>Create one via POST /api/v1/routepatterns.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
