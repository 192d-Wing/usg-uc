import { useEffect, useMemo, useState } from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Tabs from '@cloudscape-design/components/tabs';

import { ApiError } from '../../api';
import { centralApi } from '../../centralApi';
import type { ModelValue, Phone, SerializedModel } from '../../lib/phoneModel';
import {
  emptyPhone,
  findModelOption,
  packModel,
  unpackSerializedModel,
} from '../../lib/phoneModel';
import { tabsForFamily } from './vendorTabs';

type Mode = 'create' | 'edit';

const DEFAULT_MODEL: ModelValue = 'PolycomVVX450';

function initialState(mode: Mode, target: Phone | null): {
  form: Phone;
  modelValue: ModelValue;
  genericName: string;
} {
  if (mode === 'edit' && target) {
    const { value, genericName } = unpackSerializedModel(target.model);
    return { form: target, modelValue: value, genericName };
  }
  const initialModel: SerializedModel = DEFAULT_MODEL;
  return {
    form: emptyPhone(initialModel),
    modelValue: DEFAULT_MODEL,
    genericName: '',
  };
}

export function PhoneCreateModal({
  visible,
  mode,
  target,
  site,
  onClose,
  onSaved,
}: Readonly<{
  visible: boolean;
  mode: Mode;
  target: Phone | null;
  /** Active site whose shard the phone is written to. */
  site: string | null;
  onClose: () => void;
  onSaved: () => void | Promise<void>;
}>) {
  const seed = useMemo(() => initialState(mode, target), [mode, target]);
  const [form, setForm] = useState<Phone>(seed.form);
  const [modelValue, setModelValue] = useState<ModelValue>(seed.modelValue);
  const [genericName, setGenericName] = useState<string>(seed.genericName);
  const [activeTabId, setActiveTabId] = useState<string>('identity');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset internal state whenever the modal is reopened.
  useEffect(() => {
    if (visible) {
      setForm(seed.form);
      setModelValue(seed.modelValue);
      setGenericName(seed.genericName);
      setActiveTabId('identity');
      setError(null);
    }
  }, [visible, seed]);

  const modelOpt = findModelOption(modelValue);

  const onModelChange = (next: ModelValue, gen: string) => {
    setModelValue(next);
    setGenericName(gen);
  };

  const validate = (): string | null => {
    if (!form.mac_address.trim()) return 'MAC address is required.';
    if (!form.name.trim()) return 'Name is required.';
    if (modelValue === 'Generic' && !genericName.trim()) {
      return 'Generic model needs a name.';
    }
    for (const line of form.lines) {
      if (!line.directory_number.trim()) {
        return `Line ${line.index}: directory number is required.`;
      }
    }
    if (form.lines.length > modelOpt.maxLines) {
      return `${modelOpt.label} supports at most ${modelOpt.maxLines} lines.`;
    }
    return null;
  };

  const submit = async () => {
    const v = validate();
    if (v) {
      setError(v);
      return;
    }
    if (!site) {
      setError('No site selected.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // Central requires the id in the body; mint one for new phones (the
      // old per-site API generated it server-side).
      const id = mode === 'edit' && target?.id ? target.id : form.id || crypto.randomUUID();
      const body: Phone = {
        ...form,
        id,
        mac_address: form.mac_address.trim().toLowerCase(),
        name: form.name.trim(),
        model: packModel(modelValue, genericName),
      };
      // Central upsert covers create and update.
      await centralApi.upsert(site, 'phones', body);
      await onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const tabs = tabsForFamily({
    form,
    onChange: setForm,
    model: modelOpt,
    genericName,
    onModelChange,
    modelLocked: mode === 'edit',
  });

  return (
    <Modal
      visible={visible}
      onDismiss={() => (busy ? undefined : onClose())}
      header={mode === 'edit' ? `Edit phone — ${target?.name ?? ''}` : 'Create phone'}
      size="max"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={submit} loading={busy}>
              {mode === 'edit' ? 'Save' : 'Create'}
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="m">
        {error ? <Alert type="error">{error}</Alert> : null}
        <Tabs
          activeTabId={activeTabId}
          onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
          tabs={tabs}
        />
      </SpaceBetween>
    </Modal>
  );
}
