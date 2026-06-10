import { useCallback, useEffect, useRef, useState } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Pagination from '@cloudscape-design/components/pagination';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import { api, ApiError } from '../api';

const PAGE_SIZE = 50;

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

// call_id can be missing on partial records; fall back to the row index so
// trackBy keys never collide on the empty string.
type CdrRow = Cdr & { rowKey: string };

export function Cdrs() {
  const [rows, setRows] = useState<CdrRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Stale-response guard: only the most recent request may commit state.
  const seqRef = useRef(0);

  const load = useCallback(async (p: number) => {
    const seq = ++seqRef.current;
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ cdrs: Cdr[]; total: number; page?: number; page_size?: number }>(
        `/cdrs?page=${p}&page_size=${PAGE_SIZE}`,
      );
      if (seq !== seqRef.current) return;
      setRows((res.cdrs ?? []).map((c, i) => ({ ...c, rowKey: c.call_id ?? `row-${i}` })));
      setTotal(res.total ?? 0);
    } catch (e) {
      if (seq !== seqRef.current) return;
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      if (seq === seqRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(page);
  }, [load, page]);

  const pagesCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${rows.length} of ${total})`}
          description="Call Detail Records, paged from the SBC daemon (50 per page)."
          actions={
            <Button onClick={() => void load(page)} iconName="refresh" loading={loading}>
              Refresh
            </Button>
          }
        >
          CDR Records
        </Header>
      }
    >
      <Table
        items={rows}
        loading={loading}
        loadingText="Loading CDRs…"
        variant="full-page"
        stickyHeader
        trackBy="rowKey"
        columnDefinitions={[
          { id: 'start', header: 'Start', cell: (c) => String(c.start ?? '—'), isRowHeader: true },
          { id: 'caller', header: 'Caller', cell: (c) => c.caller ?? '—' },
          { id: 'callee', header: 'Callee', cell: (c) => c.callee ?? '—' },
          { id: 'duration', header: 'Duration (s)', cell: (c) => c.duration_seconds ?? '—' },
          { id: 'status', header: 'Status', cell: (c) => c.status ?? c.disposition ?? '—' },
          { id: 'callid', header: 'Call ID', cell: (c) => c.call_id ?? '—' },
        ]}
        pagination={
          <Pagination
            currentPageIndex={page}
            pagesCount={pagesCount}
            onChange={({ detail }) => setPage(detail.currentPageIndex)}
            disabled={loading}
          />
        }
        empty={
          error ? (
            <StatusIndicator type="error">{error}</StatusIndicator>
          ) : (
            <SpaceBetween size="xxs" alignItems="center">
              <b>No CDRs yet</b>
              <Box variant="p">No call detail records match this page.</Box>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
