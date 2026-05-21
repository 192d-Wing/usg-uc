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

import { api, ApiError } from '../api';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type User = {
  id?: string;
  username?: string;
  display_name?: string;
  email?: string;
  sip_uri?: string;
  auth_type?: string;
  enabled?: boolean;
};

type FormState = {
  username: string;
  display_name: string;
  email: string;
  sip_uri: string;
  password: string;
  sip_domain: string;
};

const EMPTY_FORM: FormState = {
  username: '',
  display_name: '',
  email: '',
  sip_uri: '',
  password: '',
  sip_domain: '',
};

export function Users() {
  const [items, setItems] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<User[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ users?: User[]; total?: number }>('/users');
      const next = res.users ?? [];
      setItems(next);
      setSelected((cur) => cur.filter((s) => next.some((u) => userKey(u) === userKey(s))));
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
    ? items.filter((u) => {
        const hay = `${u.username ?? ''} ${u.display_name ?? ''} ${u.email ?? ''} ${u.sip_uri ?? ''}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
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
      username: target.username ?? '',
      display_name: target.display_name ?? '',
      email: target.email ?? '',
      sip_uri: target.sip_uri ?? '',
      password: '',
      sip_domain: '',
    });
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    if (!form.username.trim()) {
      setModalError('Username is required.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const body: Record<string, string> = {
      username: form.username.trim(),
      display_name: form.display_name.trim(),
      email: form.email.trim(),
      sip_uri: form.sip_uri.trim(),
    };
    if (form.password) body.password = form.password;
    if (form.sip_domain.trim()) body.sip_domain = form.sip_domain.trim();
    try {
      if (modalMode === 'create') {
        await api.post('/users', body);
      } else if (target?.id) {
        await api.put(`/users/${encodeURIComponent(target.id)}`, body);
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
    if (!target?.id) return;
    setBusy(true);
    setModalError(null);
    try {
      await api.delete(`/users/${encodeURIComponent(target.id)}`);
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
          description="Registered SIP users and their authentication settings."
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
                Create user
              </Button>
            </SpaceBetween>
          }
        >
          Users
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading users…"
        variant="full-page"
        stickyHeader
        trackBy={userKey}
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          {
            id: 'username',
            header: 'Username',
            cell: (u) => u.username ?? '—',
            isRowHeader: true,
            sortingField: 'username',
          },
          { id: 'display', header: 'Display name', cell: (u) => u.display_name ?? '—' },
          { id: 'sip', header: 'SIP URI', cell: (u) => u.sip_uri ?? '—' },
          { id: 'email', header: 'Email', cell: (u) => u.email ?? '—' },
          { id: 'auth', header: 'Auth', cell: (u) => u.auth_type ?? '—' },
          {
            id: 'enabled',
            header: 'Enabled',
            cell: (u) =>
              u.enabled === false ? (
                <StatusIndicator type="stopped">Disabled</StatusIndicator>
              ) : (
                <StatusIndicator type="success">Enabled</StatusIndicator>
              ),
          },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find user"
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
              <b>No users</b>
              <span>Click “Create user” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit user' : 'Create user'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="Username" description="Used as the SIP auth username.">
          <Input
            value={form.username}
            onChange={({ detail }) => setForm({ ...form, username: detail.value })}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Display name">
          <Input
            value={form.display_name}
            onChange={({ detail }) => setForm({ ...form, display_name: detail.value })}
          />
        </FormField>
        <FormField label="SIP URI" description="Defaults to the username if left blank.">
          <Input
            value={form.sip_uri}
            onChange={({ detail }) => setForm({ ...form, sip_uri: detail.value })}
          />
        </FormField>
        <FormField label="Email">
          <Input
            value={form.email}
            onChange={({ detail }) => setForm({ ...form, email: detail.value })}
          />
        </FormField>
        <FormField
          label={modalMode === 'edit' ? 'New password (leave blank to keep current)' : 'Password'}
          description="Stored as HA1 digest; the plaintext is never persisted."
        >
          <Input
            type="password"
            value={form.password}
            onChange={({ detail }) => setForm({ ...form, password: detail.value })}
          />
        </FormField>
        <FormField label="SIP domain (optional)" description="Auth realm. Defaults to “sbc-local”.">
          <Input
            value={form.sip_domain}
            onChange={({ detail }) => setForm({ ...form, sip_domain: detail.value })}
          />
        </FormField>
      </FormModal>

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="user"
        name={target?.username ?? target?.id ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}

function userKey(u: User): string {
  return u.id ?? u.username ?? '';
}
