import { useEffect, useState } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import { api, ApiError } from '../api';

type Cdr = {
  call_id?: string;
  caller?: string;
  callee?: string;
  start?: number | string;
  end?: number | string;
  duration_seconds?: number;
  status?: string;
  disposition?: string;
};

export function Cdrs() {
  const [items, setItems] = useState<Cdr[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ cdrs: Cdr[]; total: number; page?: number; page_size?: number }>(
        '/cdrs',
      );
      setItems(res.cdrs ?? []);
      setTotal(res.total ?? 0);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${total})`}
          description="Call Detail Records. CDR storage is server-side; pagination + date filters will follow once the backend supports them."
          actions={
            <Button onClick={load} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          CDR Records
        </Header>
      }
    >
      <Table
        items={items}
        loading={loading}
        loadingText="Loading CDRs…"
        variant="full-page"
        stickyHeader
        trackBy={(c) => c.call_id ?? ''}
        columnDefinitions={[
          { id: 'start', header: 'Start', cell: (c) => String(c.start ?? '—'), isRowHeader: true },
          { id: 'caller', header: 'Caller', cell: (c) => c.caller ?? '—' },
          { id: 'callee', header: 'Callee', cell: (c) => c.callee ?? '—' },
          { id: 'duration', header: 'Duration (s)', cell: (c) => c.duration_seconds ?? '—' },
          { id: 'status', header: 'Status', cell: (c) => c.status ?? c.disposition ?? '—' },
          { id: 'callid', header: 'Call ID', cell: (c) => c.call_id ?? '—' },
        ]}
        empty={
          error ? (
            <StatusIndicator type="error">{error}</StatusIndicator>
          ) : (
            <SpaceBetween size="xxs" alignItems="center">
              <b>No CDRs yet</b>
              <Box variant="p">CDR storage is not yet wired up server-side; the endpoint returns an empty list.</Box>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
