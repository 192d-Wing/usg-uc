import { useEffect, useState } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Textarea from '@cloudscape-design/components/textarea';
import TextFilter from '@cloudscape-design/components/text-filter';

import { ApiError } from '../api';
import { centralApi } from '../centralApi';
import { useSite } from '../SiteContext';
import { DeleteConfirmModal, FormModal } from '../components/CrudModal';

type RoutePattern = {
  id: string;
  pattern: string;
  partition_id?: string | null;
  route_list_id?: string | null;
  route_group_id?: string | null;
  description?: string | null;
  priority?: number;
  blocked?: boolean;
  pattern_type?: string;
};

type PartitionOpt = { id: string; name?: string };
type RouteListOpt = { id: string; name?: string };
type TrunkGroupOpt = { id: string; name?: string };

type SelectOpt = { value: string; label: string };

const PATTERN_TYPE_OPTIONS: SelectOpt[] = [
  { value: 'prefix', label: 'Prefix (matches digits starting with pattern)' },
  { value: 'exact', label: 'Exact (full string match)' },
  { value: 'wildcard', label: 'Wildcard (X / [0-9] etc.)' },
  { value: 'any', label: 'Any (catch-all)' },
];

function BlockedIndicator({ blocked }: Readonly<{ blocked?: boolean }>) {
  return blocked ? (
    <StatusIndicator type="stopped">Blocked</StatusIndicator>
  ) : (
    <StatusIndicator type="success">Active</StatusIndicator>
  );
}

function TargetCell({ pattern }: Readonly<{ pattern: RoutePattern }>) {
  if (pattern.route_list_id) {
    return (
      <Box>
        <Box variant="small">list</Box>
        {pattern.route_list_id}
      </Box>
    );
  }
  if (pattern.route_group_id) {
    return (
      <Box>
        <Box variant="small">group</Box>
        {pattern.route_group_id}
      </Box>
    );
  }
  return <span>—</span>;
}

function renderTargetCell(p: RoutePattern) {
  return <TargetCell pattern={p} />;
}

function renderBlockedCell(p: RoutePattern) {
  return <BlockedIndicator blocked={p.blocked} />;
}

type FormState = {
  id: string;
  pattern: string;
  pattern_type: SelectOpt;
  partition: SelectOpt | null;
  target_kind: 'route_list' | 'route_group';
  route_list: SelectOpt | null;
  route_group: SelectOpt | null;
  description: string;
  priority: string;
};

const EMPTY_FORM: FormState = {
  id: '',
  pattern: '',
  pattern_type: PATTERN_TYPE_OPTIONS[0],
  partition: null,
  target_kind: 'route_list',
  route_list: null,
  route_group: null,
  description: '',
  priority: '0',
};

const TARGET_KIND_OPTIONS: SelectOpt[] = [
  { value: 'route_list', label: 'Route list' },
  { value: 'route_group', label: 'Route group (trunk group)' },
];

export function RoutePatterns() {
  const [items, setItems] = useState<RoutePattern[]>([]);
  const [partitions, setPartitions] = useState<PartitionOpt[]>([]);
  const [routeLists, setRouteLists] = useState<RouteListOpt[]>([]);
  const [trunkGroups, setTrunkGroups] = useState<TrunkGroupOpt[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<RoutePattern[]>([]);

  const [modalMode, setModalMode] = useState<'create' | 'edit' | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const { site } = useSite();

  const load = async () => {
    if (!site) {
      setItems([]);
      setPartitions([]);
      setRouteLists([]);
      setTrunkGroups([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [next, parts, rls, tgs] = await Promise.all([
        centralApi.list<RoutePattern>(site, 'routepatterns'),
        centralApi.list<PartitionOpt>(site, 'partitions').catch(() => []),
        centralApi.list<RouteListOpt>(site, 'routelists').catch(() => []),
        centralApi.list<TrunkGroupOpt>(site, 'trunkgroups').catch(() => []),
      ]);
      setItems(next);
      setPartitions(parts);
      setRouteLists(rls);
      setTrunkGroups(tgs);
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
    ? items.filter((p) => {
        const hay =
          `${p.pattern} ${p.partition_id ?? ''} ${p.route_list_id ?? ''} ${p.route_group_id ?? ''} ${p.description ?? ''}`.toLowerCase();
        return hay.includes(filter.toLowerCase());
      })
    : items;

  const partitionOpts: SelectOpt[] = partitions.map((p) => ({
    value: p.id,
    label: p.name ? `${p.name} (${p.id})` : p.id,
  }));
  const rlOpts: SelectOpt[] = routeLists.map((l) => ({
    value: l.id,
    label: l.name ? `${l.name} (${l.id})` : l.id,
  }));
  const tgOpts: SelectOpt[] = trunkGroups.map((g) => ({
    value: g.id,
    label: g.name ? `${g.name} (${g.id})` : g.id,
  }));

  const target = selected[0];

  const optByValue = (opts: SelectOpt[], v?: string | null) =>
    (v && opts.find((o) => o.value === v)) || null;

  const openCreate = () => {
    setForm(EMPTY_FORM);
    setModalError(null);
    setModalMode('create');
  };
  const openEdit = () => {
    if (!target) return;
    setForm({
      id: target.id,
      pattern: target.pattern,
      pattern_type:
        PATTERN_TYPE_OPTIONS.find((o) => o.value === (target.pattern_type ?? 'prefix')) ??
        PATTERN_TYPE_OPTIONS[0],
      partition: optByValue(partitionOpts, target.partition_id),
      target_kind: target.route_group_id ? 'route_group' : 'route_list',
      route_list: optByValue(rlOpts, target.route_list_id),
      route_group: optByValue(tgOpts, target.route_group_id),
      description: target.description ?? '',
      priority: String(target.priority ?? 0),
    });
    setModalError(null);
    setModalMode('edit');
  };
  const closeModal = () => setModalMode(null);

  const submit = async () => {
    if (!form.id.trim()) {
      setModalError('ID is required.');
      return;
    }
    if (!form.pattern.trim()) {
      setModalError('Pattern is required.');
      return;
    }
    if (!form.partition) {
      setModalError('Partition is required.');
      return;
    }
    const priorityNum = Number.parseInt(form.priority || '0', 10);
    if (Number.isNaN(priorityNum)) {
      setModalError('Priority must be a number.');
      return;
    }
    setBusy(true);
    setModalError(null);
    const body: Record<string, unknown> = {
      id: form.id.trim(),
      pattern: form.pattern.trim(),
      pattern_type: form.pattern_type.value,
      partition_id: form.partition.value,
      priority: priorityNum,
      description: form.description.trim() || undefined,
    };
    if (form.target_kind === 'route_list' && form.route_list) {
      body.route_list_id = form.route_list.value;
    } else if (form.target_kind === 'route_group' && form.route_group) {
      body.route_group_id = form.route_group.value;
    }
    if (!site) {
      setModalError('No site selected.');
      setBusy(false);
      return;
    }
    try {
      await centralApi.upsert(site, 'routepatterns', body);
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
      await centralApi.remove(site, 'routepatterns', target.id);
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
          description="Dial patterns mapped to a route list or group. See docs/route-patterns.md for syntax."
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
                Create route pattern
              </Button>
            </SpaceBetween>
          }
        >
          Route Patterns
        </Header>
      }
    >
      <Table
        items={filtered}
        loading={loading}
        loadingText="Loading route patterns…"
        variant="full-page"
        stickyHeader
        trackBy="id"
        selectionType="single"
        selectedItems={selected}
        onSelectionChange={({ detail }) => setSelected(detail.selectedItems)}
        columnDefinitions={[
          {
            id: 'pattern',
            header: 'Pattern',
            cell: (p) => p.pattern,
            isRowHeader: true,
            sortingField: 'pattern',
          },
          { id: 'partition', header: 'Partition', cell: (p) => p.partition_id ?? '—' },
          { id: 'target', header: 'Target', cell: renderTargetCell },
          { id: 'priority', header: 'Priority', cell: (p) => p.priority ?? 0, sortingField: 'priority' },
          { id: 'status', header: 'Status', cell: renderBlockedCell },
          { id: 'description', header: 'Description', cell: (p) => p.description ?? '—' },
        ]}
        filter={
          <TextFilter
            filteringPlaceholder="Find by pattern / partition / target"
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
              <b>No route patterns</b>
              <span>Click “Create route pattern” to add one.</span>
            </SpaceBetween>
          )
        }
      />

      <FormModal
        visible={modalMode !== null}
        title={modalMode === 'edit' ? 'Edit route pattern' : 'Create route pattern'}
        submitLabel={modalMode === 'edit' ? 'Save' : 'Create'}
        busy={busy}
        error={modalError}
        onCancel={closeModal}
        onSubmit={submit}
      >
        <FormField label="ID" description="Stable identifier for the pattern.">
          <Input
            value={form.id}
            onChange={({ detail }) => setForm({ ...form, id: detail.value })}
            disabled={modalMode === 'edit'}
          />
        </FormField>
        <FormField label="Pattern" description="e.g. 9, 1NXXNXXXXXX, or X. — depends on type.">
          <Input
            value={form.pattern}
            onChange={({ detail }) => setForm({ ...form, pattern: detail.value })}
          />
        </FormField>
        <FormField label="Pattern type">
          <Select
            selectedOption={form.pattern_type}
            options={PATTERN_TYPE_OPTIONS}
            onChange={({ detail }) =>
              setForm({ ...form, pattern_type: detail.selectedOption as SelectOpt })
            }
          />
        </FormField>
        <FormField label="Partition" description="The partition this pattern is reachable from.">
          <Select
            selectedOption={form.partition}
            options={partitionOpts}
            onChange={({ detail }) =>
              setForm({ ...form, partition: detail.selectedOption as SelectOpt })
            }
            placeholder="Pick a partition"
            empty="No partitions defined"
          />
        </FormField>
        <FormField label="Target type">
          <Select
            selectedOption={TARGET_KIND_OPTIONS.find((o) => o.value === form.target_kind) ?? null}
            options={TARGET_KIND_OPTIONS}
            onChange={({ detail }) =>
              setForm({
                ...form,
                target_kind: (detail.selectedOption.value ?? 'route_list') as
                  | 'route_list'
                  | 'route_group',
              })
            }
          />
        </FormField>
        {form.target_kind === 'route_list' ? (
          <FormField label="Route list">
            <Select
              selectedOption={form.route_list}
              options={rlOpts}
              onChange={({ detail }) =>
                setForm({ ...form, route_list: detail.selectedOption as SelectOpt })
              }
              placeholder="Pick a route list"
              empty="No route lists defined"
            />
          </FormField>
        ) : (
          <FormField label="Route group">
            <Select
              selectedOption={form.route_group}
              options={tgOpts}
              onChange={({ detail }) =>
                setForm({ ...form, route_group: detail.selectedOption as SelectOpt })
              }
              placeholder="Pick a route group"
              empty="No trunk groups defined"
            />
          </FormField>
        )}
        <FormField label="Priority" description="Higher priority patterns are tried first.">
          <Input
            type="number"
            value={form.priority}
            onChange={({ detail }) => setForm({ ...form, priority: detail.value })}
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
        resource="route pattern"
        name={target?.pattern ?? target?.id ?? ''}
        busy={busy}
        error={modalError}
        onCancel={() => setDeleteOpen(false)}
        onConfirm={confirmDelete}
      />
    </ContentLayout>
  );
}
