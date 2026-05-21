import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Link from '@cloudscape-design/components/link';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';

import { api, ApiError } from '../api';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type PhoneLine = { index?: number; directory_number?: string };

type Phone = {
  id: string;
  mac_address: string;
  name: string;
  model: unknown; // serde-tagged enum from uc-phone-mgmt
  status?: string | Record<string, string>;
  ip_address?: string | null;
  lines?: PhoneLine[];
};

function modelLabel(model: unknown): string {
  if (typeof model === 'string') return model;
  if (model && typeof model === 'object') {
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

type SelectOpt = { value: string; label: string };

// Curated common models. Variant names match the PhoneModel enum in
// crates/uc/uc-phone-mgmt/src/model.rs — serde encodes unit variants as
// bare strings (e.g. "Teo7810"), and the Generic variant as `{ Generic: "..." }`.
const MODEL_OPTIONS: SelectOpt[] = [
  { value: 'PolycomVVX150', label: 'Polycom VVX 150' },
  { value: 'PolycomVVX250', label: 'Polycom VVX 250' },
  { value: 'PolycomVVX350', label: 'Polycom VVX 350' },
  { value: 'PolycomVVX450', label: 'Polycom VVX 450' },
  { value: 'PolycomVVX501', label: 'Polycom VVX 501' },
  { value: 'PolycomVVX601', label: 'Polycom VVX 601' },
  { value: 'PolycomTrio8300', label: 'Polycom Trio 8300' },
  { value: 'PolycomTrio8500', label: 'Polycom Trio 8500' },
  { value: 'PolycomTrio8800', label: 'Polycom Trio 8800' },
  { value: 'Teo7810', label: 'Teo 7810' },
  { value: 'Teo7810TSG', label: 'Teo 7810-TSG' },
  { value: 'Teo4104', label: 'Teo 4104' },
  { value: 'Teo4101', label: 'Teo 4101' },
  { value: 'Generic', label: 'Generic (custom name)' },
];

type FormState = {
  mac_address: string;
  name: string;
  model: SelectOpt;
  generic_name: string;
  ip_address: string;
  lines: string; // comma-separated directory numbers
};

const EMPTY_FORM: FormState = {
  mac_address: '',
  name: '',
  model: MODEL_OPTIONS[0],
  generic_name: '',
  ip_address: '',
  lines: '',
};

function modelToSelect(model: unknown): { opt: SelectOpt; generic: string } {
  if (typeof model === 'string') {
    return {
      opt: MODEL_OPTIONS.find((o) => o.value === model) ?? MODEL_OPTIONS[0],
      generic: '',
    };
  }
  if (model && typeof model === 'object') {
    const entry = Object.entries(model)[0];
    if (entry?.[0] === 'Generic' && typeof entry[1] === 'string') {
      return {
        opt: MODEL_OPTIONS.find((o) => o.value === 'Generic') ?? MODEL_OPTIONS[0],
        generic: entry[1],
      };
    }
  }
  return { opt: MODEL_OPTIONS[0], generic: '' };
}

export function Phones() {
  const navigate = useNavigate();
  const [phones, setPhones] = useState<Phone[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Phone[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ phones: Phone[] }>('/phones');
      const next = res.phones ?? [];
      setPhones(next);
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
    ? phones.filter((p) => {
        const hay =
          `${p.mac_address} ${p.name} ${p.ip_address ?? ''} ${modelLabel(p.model)}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : phones;

  const target = selected[0];

  const openCreate = () => {
    setForm(EMPTY_FORM);
    setModalError(null);
    setModalMode('create');
  };
  const openEdit = () => {
    if (!target) return;
    const { opt, generic } = modelToSelect(target.model);
    setForm({
      mac_address: target.mac_address,
      name: target.name,
      model: opt,
      generic_name: generic,
      ip_address: target.ip_address ?? '',
      lines: (target.lines ?? []).map((l) => l.directory_number ?? '').filter(Boolean).join(', '),
    });
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    if (!form.mac_address.trim()) {
      setModalError('MAC address is required.');
      return;
    }
    if (!form.name.trim()) {
      setModalError('Name is required.');
      return;
    }
    if (form.model.value === 'Generic' && !form.generic_name.trim()) {
      setModalError('Generic model needs a name.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const modelValue =
      form.model.value === 'Generic' ? { Generic: form.generic_name.trim() } : form.model.value;
    const lines: PhoneLine[] = form.lines
      .split(',')
      .map((s, i) => ({ index: i + 1, directory_number: s.trim() }))
      .filter((l) => l.directory_number);
    const body: Record<string, unknown> = {
      mac_address: form.mac_address.trim(),
      name: form.name.trim(),
      model: modelValue,
      ip_address: form.ip_address.trim() || null,
      lines,
    };
    try {
      if (modalMode === 'create') {
        await api.post('/phones', body);
      } else if (target?.id) {
        body.id = target.id;
        await api.put(`/phones/${encodeURIComponent(target.id)}`, body);
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
      await api.delete(`/phones/${encodeURIComponent(target.id)}`);
      setDeleteOpen(false);
      setSelected([]);
      await load();
    } catch (e) {
      setModalError(e instanceof ApiError ? e.message : String(e));
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
          {
            id: 'lines',
            header: 'Lines',
            cell: (p) =>
              (p.lines ?? []).map((l) => l.directory_number).filter(Boolean).join(', ') || '—',
          },
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

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit phone' : 'Create phone'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="MAC address" description="e.g. 00:04:8d:00:d3:69. Used as the provisioning key.">
          <Input
            value={form.mac_address}
            onChange={({ detail }) => setForm({ ...form, mac_address: detail.value })}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Name" description="Human-readable label for operators.">
          <Input value={form.name} onChange={({ detail }) => setForm({ ...form, name: detail.value })} />
        </FormField>
        <FormField label="Model">
          <Select
            selectedOption={form.model}
            options={MODEL_OPTIONS}
            onChange={({ detail }) =>
              setForm({ ...form, model: detail.selectedOption as SelectOpt })
            }
          />
        </FormField>
        {form.model.value === 'Generic' ? (
          <FormField label="Generic model name" description="Free-form vendor/model identifier.">
            <Input
              value={form.generic_name}
              onChange={({ detail }) => setForm({ ...form, generic_name: detail.value })}
            />
          </FormField>
        ) : null}
        <FormField label="IP address (optional)" description="Auto-populated when the phone registers.">
          <Input
            value={form.ip_address}
            onChange={({ detail }) => setForm({ ...form, ip_address: detail.value })}
          />
        </FormField>
        <FormField
          label="Lines (comma-separated directory numbers)"
          description="e.g. 2001, 2002. Order maps to line index 1, 2, …"
        >
          <Input
            value={form.lines}
            onChange={({ detail }) => setForm({ ...form, lines: detail.value })}
          />
        </FormField>
      </FormModal>

      <DeleteConfirmModal
        visible={deleteOpen}
        resource="phone"
        name={target?.name ?? target?.mac_address ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
