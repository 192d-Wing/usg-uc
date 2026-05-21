import AttributeEditor from '@cloudscape-design/components/attribute-editor';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';

import type { SoftkeyAction, SoftkeyConfig } from '../../../lib/phoneModel';
import { emptySoftkey } from '../../../lib/phoneModel';

const ACTION_OPTIONS = [
  { value: 'SpeedDial', label: 'Speed dial' },
  { value: 'Blf', label: 'BLF monitor' },
  { value: 'Park', label: 'Park call' },
  { value: 'Transfer', label: 'Transfer' },
  { value: 'Conference', label: 'Conference' },
  { value: 'Dnd', label: 'Do not disturb' },
  { value: 'Intercom', label: 'Intercom' },
  { value: 'Custom', label: 'Custom…' },
];

type ActionRepr = { kind: string; custom: string };

function actionToRepr(action: SoftkeyAction): ActionRepr {
  if (typeof action === 'string') return { kind: action, custom: '' };
  return { kind: 'Custom', custom: action.Custom };
}

function reprToAction(repr: ActionRepr): SoftkeyAction {
  if (repr.kind === 'Custom') return { Custom: repr.custom };
  return repr.kind as SoftkeyAction;
}

export function SoftkeysEditor({
  items,
  onChange,
  addButtonText = 'Add softkey',
  emptyText = 'No softkeys configured.',
  limit,
}: Readonly<{
  items: SoftkeyConfig[];
  onChange: (next: SoftkeyConfig[]) => void;
  addButtonText?: string;
  emptyText?: string;
  limit?: number;
}>) {
  const reindex = (arr: SoftkeyConfig[]) => arr.map((it, i) => ({ ...it, index: i + 1 }));

  return (
    <AttributeEditor<SoftkeyConfig>
      items={items}
      onAddButtonClick={() => {
        if (limit !== undefined && items.length >= limit) return;
        onChange([...items, emptySoftkey(items.length + 1)]);
      }}
      onRemoveButtonClick={({ detail }) => {
        onChange(reindex(items.filter((_, i) => i !== detail.itemIndex)));
      }}
      addButtonText={addButtonText}
      removeButtonText="Remove"
      empty={emptyText}
      isItemRemovable={() => true}
      definition={[
        {
          label: 'Key',
          control: (item) => <Input value={String(item.index)} disabled />,
        },
        {
          label: 'Label',
          control: (item, idx) => (
            <Input
              value={item.label}
              onChange={({ detail }) => {
                const next = [...items];
                next[idx] = { ...item, label: detail.value };
                onChange(next);
              }}
            />
          ),
        },
        {
          label: 'Action',
          control: (item, idx) => {
            const repr = actionToRepr(item.action);
            const selected = ACTION_OPTIONS.find((o) => o.value === repr.kind) ?? ACTION_OPTIONS[0];
            return (
              <Select
                selectedOption={selected}
                options={ACTION_OPTIONS}
                onChange={({ detail }) => {
                  const nextKind = (detail.selectedOption?.value ?? 'SpeedDial') as string;
                  const next = [...items];
                  next[idx] = {
                    ...item,
                    action: reprToAction({ kind: nextKind, custom: repr.custom }),
                  };
                  onChange(next);
                }}
              />
            );
          },
        },
        {
          label: 'Value',
          control: (item, idx) => {
            const repr = actionToRepr(item.action);
            const isCustom = repr.kind === 'Custom';
            return (
              <Input
                value={isCustom ? repr.custom : (item.value ?? '')}
                placeholder={isCustom ? 'Custom action name' : 'Optional target (URI, number)'}
                onChange={({ detail }) => {
                  const next = [...items];
                  if (isCustom) {
                    next[idx] = { ...item, action: { Custom: detail.value } };
                  } else {
                    next[idx] = { ...item, value: detail.value || null };
                  }
                  onChange(next);
                }}
              />
            );
          },
        },
      ]}
    />
  );
}
