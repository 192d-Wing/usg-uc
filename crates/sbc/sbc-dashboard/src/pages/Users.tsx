import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

type User = {
  id?: string;
  username?: string;
  display_name?: string;
  email?: string;
  sip_uri?: string;
  auth_type?: string;
  enabled?: boolean;
};

function userSearchText(u: User): string {
  return `${u.username ?? ''} ${u.display_name ?? ''} ${u.email ?? ''} ${u.sip_uri ?? ''}`;
}

export function Users() {
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<User>('/users', (r) => r.users ?? [], { searchText: userSearchText });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Registered SIP users and their authentication settings."
          actions={
            <Button onClick={reload} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Users
        </Header>
      }
    >
      <Table
        items={filteredItems}
        loading={loading}
        loadingText="Loading users…"
        variant="full-page"
        stickyHeader
        trackBy={(u) => u.id ?? u.username ?? ''}
        columnDefinitions={[
          {
            id: 'username',
            header: 'Username',
            cell: (u) => u.username ?? '—',
            isRowHeader: true,
          },
          { id: 'display', header: 'Display name', cell: (u) => u.display_name ?? '—' },
          { id: 'sip', header: 'SIP URI', cell: (u) => u.sip_uri ?? '—' },
          { id: 'email', header: 'Email', cell: (u) => u.email ?? '—' },
          { id: 'auth', header: 'Auth', cell: (u) => u.auth_type ?? '—' },
          {
            id: 'enabled',
            header: 'Enabled',
            cell: (u) =>
              u.enabled === false ? (
                <StatusIndicator type="stopped">Disabled</StatusIndicator>
              ) : (
                <StatusIndicator type="success">Enabled</StatusIndicator>
              ),
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find user"
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
              <b>No users</b>
              <span>Create one via POST /api/v1/users.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
