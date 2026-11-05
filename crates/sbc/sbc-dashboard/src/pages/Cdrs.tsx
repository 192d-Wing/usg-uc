import { useCallback, useEffect, useState } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import {
  ApiError,
  CDR_DISPOSITIONS,
  type CdrDisposition,
  type CdrQuery,
  type CdrRecord,
  listCdrs,
} from '../api';

const PAGE_SIZE = 50;

const RANGES: SelectProps.Option[] = [
  { label: 'Last 15 minutes', value: String(15 * 60_000) },
  { label: 'Last hour', value: String(3_600_000) },
  { label: 'Last 24 hours', value: String(86_400_000) },
  { label: 'Last 7 days', value: String(7 * 86_400_000) },
  { label: 'All in memory', value: '0' },
];

const ANY_DISPOSITION: SelectProps.Option = { label: 'Any disposition', value: '' };
const DISPOSITIONS: SelectProps.Option[] = [
  ANY_DISPOSITION,
  ...CDR_DISPOSITIONS.map((d) => ({ label: d.replace('_', ' '), value: d })),
];

const fmtTime = (ms: number | null) => (ms ? new Date(ms).toLocaleString() : '—');

const dispositionType = (d: CdrDisposition): 'success' | 'error' | 'stopped' | 'warning' => {
  switch (d) {
    case 'answered':
      return 'success';
    case 'cancelled':
    case 'operator_terminated':
      return 'stopped';
    case 'busy':
    case 'no_answer':
    case 'rejected':
      return 'warning';
    default:
      return 'error';
  }
};

export function Cdrs() {
  const [items, setItems] = useState<CdrRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [node, setNode] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [range, setRange] = useState<SelectProps.Option>(RANGES[1]);
  const [disposition, setDisposition] = useState<SelectProps.Option>(ANY_DISPOSITION);
  const [caller, setCaller] = useState('');
  const [callee, setCallee] = useState('');

  // Token-based paging: tokens[i] fetches page i; tokens[0] is the first page.
  const [tokens, setTokens] = useState<(string | undefined)[]>([undefined]);
  const [page, setPage] = useState(0);
  const [nextToken, setNextToken] = useState<string | null>(null);

  const load = useCallback(
    async (pageIndex: number, pageTokens: (string | undefined)[]) => {
      setLoading(true);
      setError(null);
      const windowMs = Number(range.value ?? 0);
      const q: CdrQuery = {
        page_size: PAGE_SIZE,
        page_token: pageTokens[pageIndex],
        start: windowMs > 0 ? Date.now() - windowMs : undefined,
        caller: caller.trim() || undefined,
        callee: callee.trim() || undefined,
        disposition: (disposition.value || undefined) as CdrDisposition | undefined,
      };
      try {
        const res = await listCdrs(q);
        setItems(res.cdrs ?? []);
        setTotal(res.total ?? 0);
        setNode(res.node_id ?? '');
        setNextToken(res.next_page_token ?? null);
      } catch (e) {
        setItems([]);
        setNextToken(null);
        if (e instanceof ApiError && e.status === 403) {
          setError('You do not have the cdr:read permission.');
        } else {
          setError(e instanceof ApiError ? e.message : String(e));
        }
      } finally {
        setLoading(false);
      }
    },
    [range, disposition, caller, callee],
  );

  const reset = useCallback(() => {
    setTokens([undefined]);
    setPage(0);
    void load(0, [undefined]);
  }, [load]);

  useEffect(() => {
    reset();
    // Re-query from the first page when the range or disposition changes;
    // text filters apply on Enter / Search.
  }, [range, disposition]);

  const next = () => {
    if (!nextToken) return;
    const t = [...tokens.slice(0, page + 1), nextToken];
    setTokens(t);
    setPage(page + 1);
    void load(page + 1, t);
  };
  const prev = () => {
    if (page === 0) return;
    setPage(page - 1);
    void load(page - 1, tokens);
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${total} in memory${node ? ` on ${node}` : ''})`}
          description="Recent Call Detail Records held in the SBC node's memory, newest first. The rotated CDR files on the node are the durable record."
          actions={
            <Button onClick={reset} iconName="refresh" loading={loading}>
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
        trackBy="record_id"
        filter={
          <SpaceBetween direction="horizontal" size="xs">
            <Select
              selectedOption={range}
              onChange={({ detail }) => setRange(detail.selectedOption)}
              options={RANGES}
              ariaLabel="Time range"
            />
            <Select
              selectedOption={disposition}
              onChange={({ detail }) => setDisposition(detail.selectedOption)}
              options={DISPOSITIONS}
              ariaLabel="Disposition"
            />
            <Input
              value={caller}
              onChange={({ detail }) => setCaller(detail.value)}
              onKeyDown={({ detail }) => detail.key === 'Enter' && reset()}
              placeholder="Caller (exact)"
              ariaLabel="Caller"
            />
            <Input
              value={callee}
              onChange={({ detail }) => setCallee(detail.value)}
              onKeyDown={({ detail }) => detail.key === 'Enter' && reset()}
              placeholder="Callee (exact)"
              ariaLabel="Callee"
            />
            <Button onClick={reset}>Search</Button>
          </SpaceBetween>
        }
        pagination={
          <SpaceBetween direction="horizontal" size="xs" alignItems="center">
            <Button iconName="angle-left" variant="icon" ariaLabel="Previous page" disabled={page === 0 || loading} onClick={prev} />
            <Box>Page {page + 1}</Box>
            <Button iconName="angle-right" variant="icon" ariaLabel="Next page" disabled={!nextToken || loading} onClick={next} />
          </SpaceBetween>
        }
        columnDefinitions={[
          { id: 'setup', header: 'Setup', cell: (c) => fmtTime(c.setup_ms), isRowHeader: true },
          { id: 'caller', header: 'Caller', cell: (c) => c.caller || '—' },
          {
            id: 'callee',
            header: 'Callee',
            cell: (c) =>
              c.callee_translated && c.callee_translated !== c.callee_dialed
                ? `${c.callee_dialed} → ${c.callee_translated}`
                : c.callee_dialed || '—',
          },
          {
            id: 'disposition',
            header: 'Disposition',
            cell: (c) => (
              <StatusIndicator type={dispositionType(c.disposition)}>
                {c.disposition.replace('_', ' ')}
                {c.emergency ? ' (emergency)' : ''}
              </StatusIndicator>
            ),
          },
          { id: 'status', header: 'SIP', cell: (c) => c.final_sip_status },
          { id: 'duration', header: 'Duration (s)', cell: (c) => (c.duration_ms / 1000).toFixed(1) },
          { id: 'cause', header: 'Release', cell: (c) => `${c.release_cause} (${c.release_side})` },
          {
            id: 'trunk',
            header: 'Trunk',
            cell: (c) =>
              c.final_trunk
                ? `${c.final_trunk}${c.failover_count > 0 ? ` (+${c.failover_count} failover)` : ''}`
                : '—',
          },
          {
            id: 'stir',
            header: 'STIR',
            cell: (c) => {
              const parts: string[] = [];
              if (c.stir_attestation) parts.push(`signed ${c.stir_attestation}`);
              if (c.stir_verstat === 'tn-validation-passed')
                parts.push(`verified ${c.stir_inbound_attestation ?? ''}`.trim());
              if (c.stir_verstat === 'tn-validation-failed')
                parts.push(`failed (${c.stir_verify_reason ?? 'unknown'})`);
              if (c.stir_verstat === 'no-tn-validation') parts.push('no identity');
              return parts.length ? parts.join(', ') : '—';
            },
          },
          { id: 'source', header: 'Source', cell: (c) => `${c.source_ip}:${c.source_port}` },
          { id: 'callid', header: 'Call-ID', cell: (c) => c.a_call_id || '—' },
        ]}
        empty={
          error ? (
            <StatusIndicator type="error">{error}</StatusIndicator>
          ) : (
            <SpaceBetween size="xxs" alignItems="center">
              <b>No CDRs</b>
              <Box variant="p">No calls in the selected range are held in memory on this node.</Box>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
