import AttributeEditor from '@cloudscape-design/components/attribute-editor';
import Input from '@cloudscape-design/components/input';

import type { SpeedDial } from '../../../lib/phoneModel';
import { emptySpeedDial } from '../../../lib/phoneModel';

export function SpeedDialsEditor({
  items,
  onChange,
  limit,
}: Readonly<{
  items: SpeedDial[];
  onChange: (next: SpeedDial[]) => void;
  limit?: number;
}>) {
  const reindex = (arr: SpeedDial[]) => arr.map((it, i) => ({ ...it, index: i + 1 }));

  return (
    <AttributeEditor<SpeedDial>
      items={items}
      onAddButtonClick={() => {
        if (limit !== undefined && items.length >= limit) return;
        onChange([...items, emptySpeedDial(items.length + 1)]);
      }}
      onRemoveButtonClick={({ detail }) => {
        onChange(reindex(items.filter((_, i) => i !== detail.itemIndex)));
      }}
      addButtonText="Add speed dial"
      removeButtonText="Remove"
      empty="No speed dials configured."
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
              placeholder="e.g. Front desk"
              onChange={({ detail }) => {
                const next = [...items];
                next[idx] = { ...item, label: detail.value };
                onChange(next);
              }}
            />
          ),
        },
        {
          label: 'Number',
          control: (item, idx) => (
            <Input
              value={item.number}
              placeholder="e.g. 2100"
              onChange={({ detail }) => {
                const next = [...items];
                next[idx] = { ...item, number: detail.value };
                onChange(next);
              }}
            />
          ),
        },
      ]}
    />
  );
}
