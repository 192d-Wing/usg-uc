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

type DirectoryNumber = {
  did: string;
  user?: string;
  partition?: string;
  description?: string;
};

type FormState = {
  did: string;
  user: string;
  partition: string;
  description: string;
};

const EMPTY_FORM: FormState = { did: '', user: '', partition: '', description: '' };

export function Directory() {
  const [items, setItems] = useState<DirectoryNumber[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<DirectoryNumber[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ directory_numbers: DirectoryNumber[] }>('/directory');
      const next = res.directory_numbers ?? [];
      setItems(next);
      setSelected((cur) => cur.filter((s) => next.some((d) => d.did === s.did)));
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
    ? items.filter((d) =>
        `${d.did} ${d.user ?? ''} ${d.partition ?? ''} ${d.description ?? ''}`
          .toLowerCase()
          .includes(filter.toLowerCase()),
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
      did: target.did,
      user: target.user ?? '',
      partition: target.partition ?? '',
      description: target.description ?? '',
    });
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    if (!form.did.trim()) {
      setModalError('Directory number is required.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const body: Record<string, unknown> = {
      did: form.did.trim(),
      user: form.user.trim() || undefined,
      partition: form.partition.trim() || undefined,
      description: form.description.trim() || undefined,
    };
    try {
      if (modalMode === 'create') {
        await api.post('/directory', body);
      } else if (target) {
        await api.put(`/directory/${encodeURIComponent(target.did)}`, body);
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
      await api.delete(`/directory/${encodeURIComponent(target.did)}`);
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
          description="Provisioned directory numbers and their owning users."
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
                Create directory number
              </Button>
            </SpaceBetween>
          }
        >
          Directory Numbers
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading directory numbers…"
        variant="full-page"
        stickyHeader
        trackBy="did"
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          { id: 'did', header: 'Number', cell: (d) => d.did, isRowHeader: true, sortingField: 'did' },
          { id: 'user', header: 'User', cell: (d) => d.user ?? '—' },
          { id: 'partition', header: 'Partition', cell: (d) => d.partition ?? '—' },
          { id: 'description', header: 'Description', cell: (d) => d.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by number / user / partition"
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
              <b>No directory numbers</b>
              <span>Click “Create directory number” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit directory number' : 'Create directory number'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField
          label="Directory number"
          description="E.164 or extension, e.g. +12139160002 or 2001. Immutable after creation."
        >
          <Input
            value={form.did}
            onChange={({ detail }) => setForm({ ...form, did: detail.value })}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="User (optional)" description="Owning SIP user / extension owner.">
          <Input value={form.user} onChange={({ detail }) => setForm({ ...form, user: detail.value })} />
        </FormField>
        <FormField label="Partition (optional)">
          <Input
            value={form.partition}
            onChange={({ detail }) => setForm({ ...form, partition: detail.value })}
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
        resource="directory number"
        name={target?.did ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
