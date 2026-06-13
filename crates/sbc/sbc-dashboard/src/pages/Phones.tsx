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
import { centralApi } from '../centralApi';
import { useSite } from '../SiteContext';
import { DeleteConfirmModal } from '../components/CrudModal';
import { PhoneCreateModal } from '../components/phone-forms/PhoneCreateModal';
import type { Phone } from '../lib/phoneModel';
import { findModelOption, unpackSerializedModel } from '../lib/phoneModel';

function modelLabel(model: unknown): string {
  const { value, genericName } = unpackSerializedModel(model);
  if (value === 'Generic') return genericName || 'Generic';
  return findModelOption(value).label;
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
  const [selected, setSelected] = useState<Phone[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [busy, setBusy] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const { site } = useSite();

  const load = async () => {
    if (!site) {
      setPhones([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const next = await centralApi.list<Phone>(site, 'phones');
      setPhones(next);
      setSelected((cur) => cur.filter((s) => next.some((p) => p.id === s.id)));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    void load();
  }, [site]);

  const filtered = filter
    ? phones.filter((p) => {
        const hay = `${p.mac_address} ${p.name} ${p.ip_address ?? ''} ${modelLabel(p.model)}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : phones;

  const target = selected[0];

  const openCreate = () => setModalMode('create');
  const openEdit = () => {
    if (!target) return;
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const openDelete = () => {
    if (!target) return;
    setDeleteError(null);
    setDeleteOpen(true);
  };

  const confirmDelete = async () => {
    if (!target) return;
    setBusy(true);
    setDeleteError(null);
    if (!site) return;
    try {
      await centralApi.remove(site, 'phones', target.id);
      setDeleteOpen(false);
      setSelected([]);
      await load();
    } catch (e) {
      setDeleteError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const rebootSelected = async () => {
    if (!target) return;
    setBusy(true);
    try {
      await api.post(`/phones/${encodeURIComponent(target.id)}/reboot`, {});
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const linesSummary = (p: Phone) =>
    (p.lines ?? []).map((l) => l.directory_number).filter(Boolean).join(', ') || '—';

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
              <Button onClick={rebootSelected} disabled={!target || busy}>
                Reboot
              </Button>
              <Button onClick={openDelete} disabled={!target || busy}>
                Delete
              </Button>
              <Button onClick={openEdit} disabled={!target || busy}>
                Edit
              </Button>
              <Button variant="primary" onClick={openCreate}>
                Create phone
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
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          {
            id: 'mac',
            header: 'MAC',
            cell: (p) => (
              <Link
                onFollow={(e) => {
                  e.preventDefault();
                  navigate(`/phones/${p.id}`);
                }}
                href={`/phones/${p.id}`}
              >
                {p.mac_address}
              </Link>
            ),
            isRowHeader: true,
            sortingField: 'mac_address',
          },
          { id: 'name', header: 'Name', cell: (p) => p.name, sortingField: 'name' },
          { id: 'model', header: 'Model', cell: (p) => modelLabel(p.model) },
          { id: 'ip', header: 'IP', cell: (p) => p.ip_address ?? '—' },
          { id: 'lines', header: 'Lines', cell: linesSummary },
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
              <span>Click “Create phone” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <PhoneCreateModal
        visible={modalMode !== null}
        mode={modalMode ?? 'create'}
        target={modalMode === 'edit' ? (target ?? null) : null}
        site={site}
        onClose={closeModal}
        onSaved={load}
      />

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="phone"
        name={target?.name ?? target?.mac_address ?? ''}
        busy={busy}
        error={deleteError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
