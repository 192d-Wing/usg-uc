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

type FormState = {
  id: string;
  name: string;
  description: string;
};

const EMPTY_FORM: FormState = { id: '', name: '', description: '' };

export function Partitions() {
  const [items, setItems] = useState<Partition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Partition[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ partitions: Partition[] }>('/partitions');
      const next = res.partitions ?? [];
      setItems(next);
      setSelected((cur) => cur.filter((s) => next.some((p) => p.id === s.id)));
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

  const target = selected[0];

  const openCreate = () => {
    setForm(EMPTY_FORM);
    setModalError(null);
    setModalMode('create');
  };
  const openEdit = () => {
    if (!target) return;
    setForm({
      id: target.id,
      name: target.name ?? '',
      description: target.description ?? '',
    });
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    if (!form.name.trim()) {
      setModalError('Name is required.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const body: Record<string, unknown> = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
    };
    try {
      if (modalMode === 'create') {
        body.id = form.id.trim() || undefined;
        await api.post('/partitions', body);
      } else if (target) {
        await api.put(`/partitions/${encodeURIComponent(target.id)}`, body);
      }
      closeModal();
      await load();
    } catch (e) {
      setModalError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

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
              <Button onClick={openEdit} disabled={!target || busy}>
                Edit
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
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit partition' : 'Create partition'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="Name" description="Display name for the partition.">
          <Input value={form.name} onChange={({ detail }) => setForm({ ...form, name: detail.value })} />
        </FormField>
        <FormField
          label="ID"
          description={
            modalMode === 'edit'
              ? 'ID is immutable. Delete and recreate to change it.'
              : 'Defaults to the name if blank. Used in API URLs and CSS references.'
          }
        >
          <Input
            value={form.id}
            onChange={({ detail }) => setForm({ ...form, id: detail.value })}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Description (optional)">
          <Textarea
            value={form.description}
            onChange={({ detail }) => setForm({ ...form, description: detail.value })}
          />
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
