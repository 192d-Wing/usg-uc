import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type Registration = {
  aor: string;
  contact: string;
  expires?: number;
  registered_at?: number;
};

function registrationSearchText(r: Registration): string {
  return `${r.aor} ${r.contact}`;
}

export function Registrations() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<Registration>('/registrations', (r) => r.registrations ?? [], {
      pollMs: 15_000,
      searchText: registrationSearchText,
    });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Live SIP registration bindings. Auto-refreshes every 15s."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Registrations
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading registrations…"
        variant="full-page"
        stickyHeader
        trackBy={(r) => `${r.aor}|${r.contact}`}
        columnDefinitions={[
          { id: 'aor', header: 'Address of Record', cell: (r) => r.aor, isRowHeader: true },
          { id: 'contact', header: 'Contact', cell: (r) => r.contact },
          {
            id: 'expires',
            header: 'Expires (s)',
            cell: (r) => r.expires ?? '—',
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by AOR or contact"
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
              <b>No active registrations</b>
              <span>No SIP endpoints are currently registered with this SBC.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
