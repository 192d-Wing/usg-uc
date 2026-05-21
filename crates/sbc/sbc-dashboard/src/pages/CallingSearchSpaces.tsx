import { useEffect, useState } from 'react';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Multiselect from '@cloudscape-design/components/multiselect';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type Css = {
  id: string;
  name?: string;
  partitions?: string[];
  partition_count?: number;
};

type PartitionOpt = { id: string; name?: string };

function PartitionBadges({ cssId, partitions }: Readonly<{ cssId: string; partitions?: string[] }>) {
  if (!partitions?.length) {
    return <Box variant="small">none</Box>;
  }
  return (
    <SpaceBetween direction="horizontal" size="xxs">
      {partitions.map((p, i) => (
        <Badge key={`${cssId}-${i}-${p}`}>{`${i + 1}. ${p}`}</Badge>
      ))}
    </SpaceBetween>
  );
}

function renderPartitionsCell(c: Css) {
  return <PartitionBadges cssId={c.id} partitions={c.partitions} />;
}

type Opt = { value: string; label: string };

export function CallingSearchSpaces() {
  const [items, setItems] = useState<Css[]>([]);
  const [partitions, setPartitions] = useState<PartitionOpt[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Css[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [formId, setFormId] = useState('');
  const [formName, setFormName] = useState('');
  const [formPartitions, setFormPartitions] = useState<Opt[]>([]);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [cssRes, partRes] = await Promise.all([
        api.get<{ calling_search_spaces: Css[] }>('/css'),
        api.get<{ partitions: PartitionOpt[] }>('/partitions').catch(() => ({ partitions: [] })),
      ]);
      const next = cssRes.calling_search_spaces ?? [];
      setItems(next);
      setPartitions(partRes.partitions ?? []);
      setSelected((cur) => cur.filter((s) => next.some((c) => c.id === s.id)));
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
    ? items.filter((c) => {
        const hay = `${c.id} ${c.name ?? ''} ${(c.partitions ?? []).join(' ')}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : items;

  const partitionOptions: Opt[] = partitions.map((p) => ({
    value: p.id,
    label: p.name ? `${p.name} (${p.id})` : p.id,
  }));
  const target = selected[0];

  const openCreate = () => {
    setFormId('');
    setFormName('');
    setFormPartitions([]);
    setModalError(null);
    setModalMode('create');
  };
  const openEdit = () => {
    if (!target) return;
    setFormId(target.id);
    setFormName(target.name ?? '');
    setFormPartitions(
      (target.partitions ?? []).map((id) => ({
        value: id,
        label: partitions.find((p) => p.id === id)?.name
          ? `${partitions.find((p) => p.id === id)?.name} (${id})`
          : id,
      })),
    );
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    const id = formId.trim();
    if (!id) {
      setModalError('ID is required.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const body = {
      id,
      name: formName.trim() || id,
      partitions: formPartitions.map((o) => o.value),
    };
    try {
      if (modalMode === 'create') {
        await api.post('/css', body);
      } else {
        await api.put(`/css/${encodeURIComponent(id)}`, body);
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
      await api.delete(`/css/${encodeURIComponent(target.id)}`);
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
          description="Ordered partition lists that determine which numbers a caller can reach. First match wins."
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
                Create CSS
              </Button>
            </SpaceBetween>
          }
        >
          Calling Search Spaces
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading calling search spaces…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (c) => c.name ?? c.id, isRowHeader: true, sortingField: 'name' },
          { id: 'id', header: 'ID', cell: (c) => c.id },
          {
            id: 'partitions',
            header: 'Partitions (in search order)',
            cell: renderPartitionsCell,
          },
          {
            id: 'count',
            header: 'Count',
            cell: (c) => c.partition_count ?? c.partitions?.length ?? 0,
            sortingField: 'partition_count',
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find CSS by name / partition"
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
              <b>No calling search spaces</b>
              <span>Click “Create CSS” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit calling search space' : 'Create calling search space'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="ID" description="Stable identifier; referenced by phone configurations.">
          <Input
            value={formId}
            onChange={({ detail }) => setFormId(detail.value)}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Name (optional)" description="Defaults to the ID.">
          <Input value={formName} onChange={({ detail }) => setFormName(detail.value)} />
        </FormField>
        <FormField
          label="Partitions (in search order)"
          description="First match wins. Order is the order selected."
        >
          <Multiselect
            selectedOptions={formPartitions}
            options={partitionOptions}
            onChange={({ detail }) =>
              setFormPartitions(detail.selectedOptions as Opt[])
            }
            placeholder="Select partitions"
            empty="No partitions available"
            keepOpen
          />
        </FormField>
      </FormModal>

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="calling search space"
        name={target?.name ?? target?.id ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
