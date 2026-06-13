import { useEffect, useState } from 'react';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { ApiError } from '../api';
import { centralApi } from '../centralApi';
import { useSite } from '../SiteContext';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type RouteList = {
  id: string;
  name?: string;
  member_count?: number;
};

export function RouteLists() {
  const [items, setItems] = useState<RouteList[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<RouteList[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [formId, setFormId] = useState('');
  const [formName, setFormName] = useState('');
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
      const next = await centralApi.list<RouteList>(site, 'routelists');
      setItems(next);
      setSelected((cur) => cur.filter((s) => next.some((l) => l.id === s.id)));
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
    ? items.filter((l) => `${l.id} ${l.name ?? ''}`.toLowerCase().includes(filter.toLowerCase()))
    : items;

  const target = selected[0];

  const openCreate = () => {
    setFormId('');
    setFormName('');
    setModalError(null);
    setModalMode('create');
  };
  const openEdit = () => {
    if (!target) return;
    setFormId(target.id);
    setFormName(target.name ?? '');
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
    if (!site) {
      setModalError('No site selected.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const body = { id, name: formName.trim() || id };
    try {
      await centralApi.upsert(site, 'routelists', body);
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
    if (!target || !site) return;
    setBusy(true);
    setModalError(null);
    try {
      await centralApi.remove(site, 'routelists', target.id);
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
          description="Ordered route group lists used by route patterns to direct outbound calls."
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
                Create route list
              </Button>
            </SpaceBetween>
          }
        >
          Route Lists
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading route lists…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          { id: 'name', header: 'Name', cell: (l) => l.name ?? l.id, isRowHeader: true, sortingField: 'name' },
          { id: 'id', header: 'ID', cell: (l) => l.id },
          { id: 'members', header: 'Members', cell: (l) => l.member_count ?? 0, sortingField: 'member_count' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find route list"
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
              <b>No route lists</b>
              <span>Click “Create route list” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit route list' : 'Create route list'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="ID" description="Stable identifier referenced by route patterns.">
          <Input
            value={formId}
            onChange={({ detail }) => setFormId(detail.value)}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Name (optional)" description="Defaults to the ID.">
          <Input value={formName} onChange={({ detail }) => setFormName(detail.value)} />
        </FormField>
      </FormModal>

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="route list"
        name={target?.name ?? target?.id ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
