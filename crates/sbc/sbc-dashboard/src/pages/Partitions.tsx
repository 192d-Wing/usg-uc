import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Textarea from '@cloudscape-design/components/textarea';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type Partition = {
  id: string;
  name?: string;
  description?: string | null;
};

export function Partitions() {
  const [items, setItems] = useState<Partition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Partition[]>([]);

  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createId, setCreateId] = useState('');
  const [createDesc, setCreateDesc] = useState('');
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ partitions: Partition[] }>('/partitions');
      setItems(res.partitions ?? []);
      setSelected((cur) =>
        cur.filter((s) => (res.partitions ?? []).some((p) => p.id === s.id)),
      );
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
    ? items.filter((p) =>
        `${p.id} ${p.name ?? ''} ${p.description ?? ''}`.toLowerCase().includes(filter.toLowerCase()),
      )
    : items;

  const openCreate = () => {
    setCreateName('');
    setCreateId('');
    setCreateDesc('');
    setModalError(null);
    setCreateOpen(true);
  };

  const submitCreate = async () => {
    if (!createName.trim()) {
      setModalError('Name is required.');
      return;
    }
    setBusy(true);
    setModalError(null);
    try {
      await api.post('/partitions', {
        name: createName.trim(),
        id: createId.trim() || undefined,
        description: createDesc.trim() || undefined,
      });
      setCreateOpen(false);
      await load();
    } catch (e) {
      setModalError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

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
      await api.delete(`/partitions/${encodeURIComponent(target.id)}`);
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
          description="Route partitions — groupings used by Calling Search Spaces to scope what numbers a caller can reach."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={load} iconName="refresh" loading={loading}>
                Refresh
              </Button>
              <Button onClick={openDelete} disabled={!target || busy}>
                Delete
              </Button>
              <Button variant="primary" onClick={openCreate}>
                Create partition
              </Button>
            </SpaceBetween>
          }
        >
          Partitions
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading partitions…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (p) => p.name ?? p.id, isRowHeader: true, sortingField: 'name' },
          { id: 'id', header: 'ID', cell: (p) => p.id },
          { id: 'description', header: 'Description', cell: (p) => p.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find partition"
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
              <b>No partitions</b>
              <span>Click “Create partition” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={createOpen}
        title="Create partition"
        submitLabel="Create"
        busy={busy}
        error={modalError}
        onCancel={() => setCreateOpen(false)}
        onSubmit={submitCreate}
      >
        <FormField label="Name" description="Display name for the partition.">
          <Input value={createName} onChange={({ detail }) => setCreateName(detail.value)} />
        </FormField>
        <FormField
          label="ID (optional)"
          description="Defaults to the name if blank. Used in API URLs and CSS references."
        >
          <Input value={createId} onChange={({ detail }) => setCreateId(detail.value)} />
        </FormField>
        <FormField label="Description (optional)">
          <Textarea value={createDesc} onChange={({ detail }) => setCreateDesc(detail.value)} />
        </FormField>
      </FormModal>

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="partition"
        name={target?.name ?? target?.id ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
