import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';

type Phone = {
  id: string;
  mac_address: string;
  name: string;
  model: unknown; // serde-tagged enum from uc-phone-mgmt; render as JSON-ish
  status?: string | Record<string, string>;
  ip_address?: string | null;
  lines?: Array<{ index?: number; directory_number?: string }>;
};

function modelLabel(model: unknown): string {
  if (typeof model === 'string') return model;
  if (model && typeof model === 'object') {
    // PhoneModel::Generic(String) serializes as { Generic: "..." }
    const entry = Object.entries(model)[0];
    if (entry) return `${entry[0]}${typeof entry[1] === 'string' ? `: ${entry[1]}` : ''}`;
  }
  return '—';
}

function statusIndicator(status: Phone['status']) {
  const text = typeof status === 'string' ? status : Object.keys(status ?? {})[0] ?? 'Unknown';
  if (text === 'Registered') return <StatusIndicator type="success">Registered</StatusIndicator>;
  if (text === 'Offline') return <StatusIndicator type="error">Offline</StatusIndicator>;
  if (text === 'Provisioning')
    return <StatusIndicator type="in-progress">Provisioning</StatusIndicator>;
  if (text === 'Error') return <StatusIndicator type="error">Error</StatusIndicator>;
  return <StatusIndicator type="pending">{text}</StatusIndicator>;
}

export function Phones() {
  const navigate = useNavigate();
  const [phones, setPhones] = useState<Phone[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ phones: Phone[] }>('/phones');
      setPhones(res.phones ?? []);
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
    ? phones.filter((p) => {
        const hay = `${p.mac_address} ${p.name} ${p.ip_address ?? ''} ${modelLabel(p.model)}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : phones;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${phones.length})`}
          description="Provisioned phone devices. Click a row to view details."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={load} iconName="refresh" loading={loading}>
                Refresh
              </Button>
            </SpaceBetween>
          }
        >
          Phones
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading phones…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        columnDefinitions={[
          {
            id: 'mac',
            header: 'MAC',
            cell: (p) => (
              <Link onFollow={(e) => { e.preventDefault(); navigate(`/phones/${p.id}`); }} href={`/phones/${p.id}`}>
                {p.mac_address}
              </Link>
            ),
            isRowHeader: true,
            sortingField: 'mac_address',
          },
          { id: 'name', header: 'Name', cell: (p) => p.name, sortingField: 'name' },
          { id: 'model', header: 'Model', cell: (p) => modelLabel(p.model) },
          { id: 'ip', header: 'IP', cell: (p) => p.ip_address ?? '—' },
          {
            id: 'lines',
            header: 'Lines',
            cell: (p) => (p.lines ?? []).map((l) => l.directory_number).filter(Boolean).join(', ') || '—',
          },
          { id: 'status', header: 'Status', cell: (p) => statusIndicator(p.status) },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find phone"
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
              <b>No phones</b>
              <span>Provision a phone via POST /api/v1/phones.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
