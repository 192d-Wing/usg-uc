import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';
import { DeleteConfirmModal } from '../components/CrudModal';

type Registration = {
  aor: string;
  contact: string;
  expires?: number;
  registered_at?: number;
};

export function Registrations() {
  const [items, setItems] = useState<Registration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Registration[]>([]);

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ registrations: Registration[] }>('/registrations');
      const next = res.registrations ?? [];
      setItems(next);
      setSelected((cur) =>
        cur.filter((s) => next.some((r) => r.aor === s.aor && r.contact === s.contact)),
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const id = globalThis.setInterval(load, 15_000);
    return () => globalThis.clearInterval(id);
  }, []);

  const filtered = filter
    ? items.filter((r) => `${r.aor} ${r.contact}`.toLowerCase().includes(filter.toLowerCase()))
    : items;

  const target = selected[0];
  const openDelete = () => {
    if (!target) return;
    setModalError(null);
    setDeleteOpen(true);
  };
  const confirmDelete = async () => {
    if (!target) return;
    setBusy(true);
    setModalError(null);
    try {
      await api.delete(`/registrations/${encodeURIComponent(target.aor)}`);
      setDeleteOpen(false);
      setSelected([]);
      await load();
    } catch (e) {
      setModalError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${items.length})`}
          description="Live SIP registration bindings. Auto-refreshes every 15s."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={load} iconName="refresh" loading={loading}>
                Refresh
              </Button>
              <Button onClick={openDelete} disabled={!target || busy}>
                Force unregister
              </Button>
            </SpaceBetween>
          }
        >
          Registrations
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading registrations…"
        variant="full-page"
        stickyHeader
        trackBy={(r) => `${r.aor}|${r.contact}`}
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          { id: 'aor', header: 'Address of Record', cell: (r) => r.aor, isRowHeader: true, sortingField: 'aor' },
          { id: 'contact', header: 'Contact', cell: (r) => r.contact },
          {
            id: 'expires',
            header: 'Expires (s)',
            cell: (r) => r.expires ?? '—',
            sortingField: 'expires',
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by AOR or contact"
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
              <b>No active registrations</b>
              <span>No SIP endpoints are currently registered with this SBC.</span>
            </SpaceBetween>
          )
        }
      />

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="registration"
        name={target?.aor ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
