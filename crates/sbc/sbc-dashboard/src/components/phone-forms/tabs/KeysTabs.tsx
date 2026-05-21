import type { Phone } from '../../../lib/phoneModel';
import { BlfEditor } from '../editors/BlfEditor';
import { SoftkeysEditor } from '../editors/SoftkeysEditor';
import { SpeedDialsEditor } from '../editors/SpeedDialsEditor';

type Props = Readonly<{ form: Phone; onChange: (next: Phone) => void }>;

export function BlfTab({ form, onChange }: Props) {
  return (
    <BlfEditor
      items={form.blf_entries}
      onChange={(blf_entries) => onChange({ ...form, blf_entries })}
    />
  );
}

export function SpeedDialsTab({ form, onChange }: Props) {
  return (
    <SpeedDialsEditor
      items={form.speed_dials}
      onChange={(speed_dials) => onChange({ ...form, speed_dials })}
    />
  );
}

export function SoftkeysTab({ form, onChange }: Props) {
  return (
    <SoftkeysEditor
      items={form.softkeys}
      onChange={(softkeys) => onChange({ ...form, softkeys })}
    />
  );
}

export function LineKeysTab({
  form,
  onChange,
  limit,
}: Readonly<Props & { limit: number }>) {
  return (
    <SoftkeysEditor
      items={form.softkeys}
      onChange={(softkeys) => onChange({ ...form, softkeys })}
      addButtonText="Add line key"
      emptyText="No programmable line keys configured."
      limit={limit}
    />
  );
}
