import { useNavigate } from 'react-router-dom';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { useApiList } from '../hooks/useApiList';

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

function phoneSearchText(p: Phone): string {
  return `${p.mac_address} ${p.name} ${p.ip_address ?? ''} ${modelLabel(p.model)}`;
}

export function Phones() {
  const navigate = useNavigate();
  const { items, filteredItems, loading, error, filterText, setFilterText, reload } =
    useApiList<Phone>('/phones', (r) => r.phones ?? [], { searchText: phoneSearchText });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Provisioned phone devices. Click a row to view details."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={reload} iconName="refresh" loading={loading}>
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
        items={filteredItems}
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
          },
          { id: 'name', header: 'Name', cell: (p) => p.name },
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
              <b>No phones</b>
              <span>Provision a phone via POST /api/v1/phones.</span>
            </SpaceBetween>
          )
        }
      />
    </ContentLayout>
  );
}
