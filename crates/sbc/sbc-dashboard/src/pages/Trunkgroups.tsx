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

import { ApiError } from '../api';
import { centralApi } from '../centralApi';
import { useSite } from '../SiteContext';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type Trunk = { id?: string; host?: string; port?: number; transport?: string };

type TrunkGroup = {
  id?: string;
  name?: string;
  description?: string;
  trunks?: Trunk[];
};

export function Trunkgroups() {
  const [items, setItems] = useState<TrunkGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<TrunkGroup[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [formId, setFormId] = useState('');
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const { site } = useSite();

  const load = async () => {
    if (!site) {
      setItems([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const list = await centralApi.list<TrunkGroup>(site, 'trunkgroups');
      setItems(list);
      setSelected((cur) => cur.filter((s) => list.some((g) => groupKey(g) === groupKey(s))));
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
    ? items.filter((g) => {
        const hay = `${g.name ?? ''} ${g.description ?? ''} ${g.id ?? ''}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : items;

  const target = selected[0];

  const openCreate = () => {
    setFormId('');
    setFormName('');
    setFormDesc('');
    setModalError(null);
    setModalMode('create');
  };
  const openEdit = () => {
    if (!target) return;
    setFormId(target.id ?? '');
    setFormName(target.name ?? '');
    setFormDesc(target.description ?? '');
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    if (!formName.trim()) {
      setModalError('Name is required.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const id = modalMode === 'edit' ? (target?.id ?? '') : formId.trim();
    if (!id) {
      setModalError('Trunk group id is required.');
      setBusy(false);
      return;
    }
    if (!site) {
      setModalError('No site selected.');
      setBusy(false);
      return;
    }
    const body: Record<string, unknown> = {
      id,
      name: formName.trim(),
      description: formDesc.trim() || undefined,
      // Preserve existing trunks on update (central validates the full doc).
      trunks: modalMode === 'edit' ? (target?.trunks ?? []) : [],
    };
    try {
      await centralApi.upsert(site, 'trunkgroups', body);
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
    if (!target?.id || !site) return;
    setBusy(true);
    setModalError(null);
    try {
      await centralApi.remove(site, 'trunkgroups', target.id);
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
          description="SIP trunk groups for outbound call routing. Trunks within a group are edited via the API."
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
                Create group
              </Button>
            </SpaceBetween>
          }
        >
          Route Groups
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading trunk groups…"
        variant="full-page"
        stickyHeader
        trackBy={groupKey}
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (g) => g.name ?? '—', isRowHeader: true, sortingField: 'name' },
          { id: 'description', header: 'Description', cell: (g) => g.description ?? '—' },
          {
            id: 'trunks',
            header: 'Trunks',
            cell: (g) =>
              g.trunks?.length
                ? g.trunks
                    .map((t) => `${t.host ?? '?'}:${t.port ?? ''}${t.transport ? `/${t.transport}` : ''}`)
                    .join(', ')
                : '0',
          },
          { id: 'id', header: 'ID', cell: (g) => g.id ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find trunk group"
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
              <b>No trunk groups</b>
              <span>Click “Create group” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit route group' : 'Create route group'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="Name">
          <Input value={formName} onChange={({ detail }) => setFormName(detail.value)} />
        </FormField>
        <FormField
          label="ID (optional)"
          description="A UUID is auto-generated when blank. Cannot be changed after create."
        >
          <Input
            value={formId}
            onChange={({ detail }) => setFormId(detail.value)}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Description (optional)">
          <Textarea value={formDesc} onChange={({ detail }) => setFormDesc(detail.value)} />
        </FormField>
      </FormModal>

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="route group"
        name={target?.name ?? target?.id ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}

function groupKey(g: TrunkGroup): string {
  return g.id ?? g.name ?? '';
}
