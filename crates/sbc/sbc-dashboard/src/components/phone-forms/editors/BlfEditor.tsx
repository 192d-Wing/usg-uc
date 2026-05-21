import AttributeEditor from '@cloudscape-design/components/attribute-editor';
import Input from '@cloudscape-design/components/input';

import type { BlfEntry } from '../../../lib/phoneModel';
import { emptyBlf } from '../../../lib/phoneModel';

export function BlfEditor({
  items,
  onChange,
  limit,
}: Readonly<{
  items: BlfEntry[];
  onChange: (next: BlfEntry[]) => void;
  limit?: number;
}>) {
  const reindex = (arr: BlfEntry[]) => arr.map((it, i) => ({ ...it, index: i + 1 }));

  return (
    <AttributeEditor<BlfEntry>
      items={items}
      onAddButtonClick={() => {
        if (limit !== undefined && items.length >= limit) return;
        onChange([...items, emptyBlf(items.length + 1)]);
      }}
      onRemoveButtonClick={({ detail }) => {
        onChange(reindex(items.filter((_, i) => i !== detail.itemIndex)));
      }}
      addButtonText="Add BLF entry"
      removeButtonText="Remove"
      empty="No busy-lamp monitors configured."
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
              placeholder="e.g. CEO"
              onChange={({ detail }) => {
                const next = [...items];
                next[idx] = { ...item, label: detail.value };
                onChange(next);
              }}
            />
          ),
        },
        {
          label: 'Monitored URI / extension',
          control: (item, idx) => (
            <Input
              value={item.address}
              placeholder="e.g. 2050 or sip:2050@example"
              onChange={({ detail }) => {
                const next = [...items];
                next[idx] = { ...item, address: detail.value };
                onChange(next);
              }}
            />
          ),
        },
      ]}
    />
  );
}
