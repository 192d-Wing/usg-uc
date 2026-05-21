import ColumnLayout from '@cloudscape-design/components/column-layout';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';

import type { ModelOption, ModelValue, Phone } from '../../../lib/phoneModel';
import { GROUPED_MODEL_OPTIONS, findModelOption, packModel } from '../../../lib/phoneModel';

export function IdentityTab({
  form,
  onChange,
  model,
  genericName,
  onModelChange,
  modelLocked,
}: Readonly<{
  form: Phone;
  onChange: (next: Phone) => void;
  model: ModelOption;
  genericName: string;
  onModelChange: (next: ModelValue, genericName: string) => void;
  modelLocked: boolean;
}>) {
  const update = (patch: Partial<Phone>) => onChange({ ...form, ...patch });

  const selectedOpt = { value: model.value, label: model.label };

  return (
    <SpaceBetween size="m">
      <ColumnLayout columns={2}>
        <FormField
          label="MAC address"
          description="Colon-separated, lowercase. Provisioning key."
        >
          <Input
            value={form.mac_address}
            placeholder="00:04:8d:00:d3:69"
            disabled={modelLocked}
            onChange={({ detail }) => update({ mac_address: detail.value })}
          />
        </FormField>
        <FormField label="Name" description="Human-readable label.">
          <Input
            value={form.name}
            onChange={({ detail }) => update({ name: detail.value })}
          />
        </FormField>
        <FormField
          label="Model"
          description={
            modelLocked
              ? 'Locked after creation — changing model would orphan vendor-specific config.'
              : undefined
          }
        >
          <Select
            selectedOption={selectedOpt}
            options={GROUPED_MODEL_OPTIONS}
            disabled={modelLocked}
            onChange={({ detail }) => {
              const v = (detail.selectedOption?.value ?? 'PolycomVVX450') as ModelValue;
              const opt = findModelOption(v);
              onModelChange(v, genericName);
              update({ model: packModel(v, genericName) });
              // Trim lines if new model has lower line cap
              if (form.lines.length > opt.maxLines) {
                update({ lines: form.lines.slice(0, opt.maxLines) });
              }
            }}
          />
        </FormField>
        {model.value === 'Generic' ? (
          <FormField label="Generic model name" description="Free-form vendor/model identifier.">
            <Input
              value={genericName}
              onChange={({ detail }) => {
                onModelChange('Generic', detail.value);
                update({ model: packModel('Generic', detail.value) });
              }}
            />
          </FormField>
        ) : (
          <div />
        )}
        <FormField label="IP address (optional)" description="Auto-populated when the phone registers.">
          <Input
            value={form.ip_address ?? ''}
            onChange={({ detail }) => update({ ip_address: detail.value || null })}
          />
        </FormField>
        <FormField label="Description (optional)">
          <Input
            value={form.description ?? ''}
            onChange={({ detail }) => update({ description: detail.value || null })}
          />
        </FormField>
        <FormField label="Owner user ID (optional)">
          <Input
            value={form.owner_id ?? ''}
            onChange={({ detail }) => update({ owner_id: detail.value || null })}
          />
        </FormField>
        <FormField label="Device pool (optional)">
          <Input
            value={form.device_pool ?? ''}
            onChange={({ detail }) => update({ device_pool: detail.value || null })}
          />
        </FormField>
        <FormField label="Calling search space (optional)">
          <Input
            value={form.calling_search_space ?? ''}
            onChange={({ detail }) =>
              update({ calling_search_space: detail.value || null })
            }
          />
        </FormField>
        <FormField label="Target firmware (optional)">
          <Input
            value={form.target_firmware ?? ''}
            onChange={({ detail }) => update({ target_firmware: detail.value || null })}
          />
        </FormField>
      </ColumnLayout>
    </SpaceBetween>
  );
}
