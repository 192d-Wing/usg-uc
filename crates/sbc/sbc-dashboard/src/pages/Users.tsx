import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type User = {
  id?: string;
  username?: string;
  display_name?: string;
  email?: string;
  sip_uri?: string;
  auth_type?: string;
  enabled?: boolean;
};

export function Users() {
  const [items, setItems] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ users?: User[]; total?: number }>('/users');
      setItems(res.users ?? []);
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
    ? items.filter((u) => {
        const hay = `${u.username ?? ''} ${u.display_name ?? ''} ${u.email ?? ''} ${u.sip_uri ?? ''}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : items;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Registered SIP users and their authentication settings."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          Users
        </Header>
      }
    >
      <Table
        items={filtered}
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
            sortingField: 'username',
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
              <b>No users</b>
              <span>Create one via POST /api/v1/users.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
