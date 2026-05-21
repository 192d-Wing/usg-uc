import AttributeEditor from '@cloudscape-design/components/attribute-editor';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Toggle from '@cloudscape-design/components/toggle';

import type { HeadsetMode, Phone } from '../../../lib/phoneModel';

type Props = Readonly<{ form: Phone; onChange: (next: Phone) => void }>;

const HEADSET_OPTIONS: { value: HeadsetMode; label: string }[] = [
  { value: 'Wired', label: 'Wired' },
  { value: 'Usb', label: 'USB' },
  { value: 'Bluetooth', label: 'Bluetooth' },
  { value: 'Dect', label: 'DECT' },
];

const numOrNull = (s: string) => {
  const n = Number(s);
  return s === '' || Number.isNaN(n) ? null : n;
};

export function FeaturesTab({ form, onChange }: Props) {
  const f = form.features;
  const setF = (patch: Partial<typeof f>) =>
    onChange({ ...form, features: { ...f, ...patch } });
  return (
    <ColumnLayout columns={2}>
      <Toggle checked={f.auto_answer} onChange={({ detail }) => setF({ auto_answer: detail.checked })}>
        Auto-answer (for paging)
      </Toggle>
      <Toggle checked={f.dnd} onChange={({ detail }) => setF({ dnd: detail.checked })}>
        Do not disturb
      </Toggle>
      <Toggle checked={f.intercom} onChange={({ detail }) => setF({ intercom: detail.checked })}>
        Intercom
      </Toggle>
      <Toggle
        checked={f.call_recording}
        onChange={({ detail }) => setF({ call_recording: detail.checked })}
      >
        Call recording
      </Toggle>
      <Toggle
        checked={f.hotdesking}
        onChange={({ detail }) => setF({ hotdesking: detail.checked })}
      >
        Hotdesking / extension mobility
      </Toggle>
    </ColumnLayout>
  );
}

export function NetworkTab({ form, onChange }: Props) {
  const n = form.network;
  const setN = (patch: Partial<typeof n>) =>
    onChange({ ...form, network: { ...n, ...patch } });
  return (
    <SpaceBetween size="m">
      <ColumnLayout columns={2}>
        <FormField label="Voice VLAN ID" description="802.1Q VLAN for voice traffic.">
          <Input
            type="number"
            value={n.vlan_id === null ? '' : String(n.vlan_id)}
            onChange={({ detail }) => setN({ vlan_id: numOrNull(detail.value) })}
          />
        </FormField>
        <FormField label="QoS DSCP" description="0-63. Common: 46 (EF).">
          <Input
            type="number"
            value={n.qos_dscp === null ? '' : String(n.qos_dscp)}
            onChange={({ detail }) => setN({ qos_dscp: numOrNull(detail.value) })}
          />
        </FormField>
      </ColumnLayout>
      <ColumnLayout columns={3}>
        <Toggle
          checked={n.cdp_enabled}
          onChange={({ detail }) => setN({ cdp_enabled: detail.checked })}
        >
          CDP
        </Toggle>
        <Toggle
          checked={n.lldp_enabled}
          onChange={({ detail }) => setN({ lldp_enabled: detail.checked })}
        >
          LLDP-MED
        </Toggle>
        <Toggle
          checked={n.dot1x_enabled}
          onChange={({ detail }) => setN({ dot1x_enabled: detail.checked })}
        >
          802.1X
        </Toggle>
      </ColumnLayout>
    </SpaceBetween>
  );
}

export function DisplayTab({ form, onChange }: Props) {
  const d = form.display;
  const setD = (patch: Partial<typeof d>) =>
    onChange({ ...form, display: { ...d, ...patch } });
  return (
    <SpaceBetween size="m">
      <ColumnLayout columns={2}>
        <FormField label="Language" description="e.g. en, es, fr.">
          <Input
            value={d.language ?? ''}
            onChange={({ detail }) => setD({ language: detail.value || null })}
          />
        </FormField>
        <FormField label="Timezone" description="IANA, e.g. America/New_York.">
          <Input
            value={d.timezone ?? ''}
            onChange={({ detail }) => setD({ timezone: detail.value || null })}
          />
        </FormField>
        <FormField label="Brightness (0-100)">
          <Input
            type="number"
            value={d.brightness === null ? '' : String(d.brightness)}
            onChange={({ detail }) => setD({ brightness: numOrNull(detail.value) })}
          />
        </FormField>
        <FormField label="Ringtone">
          <Input
            value={d.ringtone ?? ''}
            onChange={({ detail }) => setD({ ringtone: detail.value || null })}
          />
        </FormField>
        <FormField label="NTP server">
          <Input
            value={d.ntp_server ?? ''}
            onChange={({ detail }) => setD({ ntp_server: detail.value || null })}
          />
        </FormField>
        <Toggle
          checked={d.time_24hr}
          onChange={({ detail }) => setD({ time_24hr: detail.checked })}
        >
          24-hour time
        </Toggle>
      </ColumnLayout>
    </SpaceBetween>
  );
}

export function AudioTab({ form, onChange }: Props) {
  const a = form.audio;
  const setA = (patch: Partial<typeof a>) =>
    onChange({ ...form, audio: { ...a, ...patch } });
  const headsetOpt = HEADSET_OPTIONS.find((o) => o.value === a.headset_mode) ?? HEADSET_OPTIONS[0];
  return (
    <SpaceBetween size="m">
      <FormField label="Headset mode">
        <Select
          selectedOption={headsetOpt}
          options={HEADSET_OPTIONS}
          onChange={({ detail }) =>
            setA({ headset_mode: (detail.selectedOption?.value ?? 'Wired') as HeadsetMode })
          }
        />
      </FormField>
      <ColumnLayout columns={2}>
        <Toggle
          checked={a.noise_reduction}
          onChange={({ detail }) => setA({ noise_reduction: detail.checked })}
        >
          Noise reduction
        </Toggle>
        <Toggle
          checked={a.echo_cancellation}
          onChange={({ detail }) => setA({ echo_cancellation: detail.checked })}
        >
          Acoustic echo cancellation
        </Toggle>
      </ColumnLayout>
    </SpaceBetween>
  );
}

export function DirectoryTab({ form, onChange }: Props) {
  const d = form.directory;
  const setD = (patch: Partial<typeof d>) =>
    onChange({ ...form, directory: { ...d, ...patch } });
  return (
    <SpaceBetween size="m">
      <Toggle checked={d.enabled} onChange={({ detail }) => setD({ enabled: detail.checked })}>
        Enable LDAP corporate directory
      </Toggle>
      {d.enabled ? (
        <ColumnLayout columns={2}>
          <FormField label="LDAP server">
            <Input
              value={d.ldap_server ?? ''}
              onChange={({ detail }) => setD({ ldap_server: detail.value || null })}
            />
          </FormField>
          <FormField label="LDAP port">
            <Input
              type="number"
              value={d.ldap_port === null ? '' : String(d.ldap_port)}
              onChange={({ detail }) => setD({ ldap_port: numOrNull(detail.value) })}
            />
          </FormField>
          <FormField label="Base DN">
            <Input
              value={d.ldap_base_dn ?? ''}
              onChange={({ detail }) => setD({ ldap_base_dn: detail.value || null })}
            />
          </FormField>
          <FormField label="Bind DN (username)">
            <Input
              value={d.ldap_bind_dn ?? ''}
              onChange={({ detail }) => setD({ ldap_bind_dn: detail.value || null })}
            />
          </FormField>
          <FormField label="Bind password">
            <Input
              type="password"
              value={d.ldap_password ?? ''}
              onChange={({ detail }) => setD({ ldap_password: detail.value || null })}
            />
          </FormField>
          <Toggle checked={d.ldap_tls} onChange={({ detail }) => setD({ ldap_tls: detail.checked })}>
            Use TLS / LDAPS
          </Toggle>
        </ColumnLayout>
      ) : null}
    </SpaceBetween>
  );
}

export function PagingTab({ form, onChange }: Props) {
  const p = form.paging;
  const setP = (patch: Partial<typeof p>) =>
    onChange({ ...form, paging: { ...p, ...patch } });
  return (
    <SpaceBetween size="m">
      <Toggle checked={p.enabled} onChange={({ detail }) => setP({ enabled: detail.checked })}>
        Enable paging / intercom
      </Toggle>
      {p.enabled ? (
        <SpaceBetween size="m">
          <FormField label="Multicast address" description="e.g. 224.0.1.116:5000.">
            <Input
              value={p.multicast_address ?? ''}
              onChange={({ detail }) =>
                setP({ multicast_address: detail.value || null })
              }
            />
          </FormField>
          <FormField label="Paging groups" description="One SIP URI per row.">
            <AttributeEditor<{ uri: string }>
              items={p.groups.map((uri) => ({ uri }))}
              onAddButtonClick={() => setP({ groups: [...p.groups, ''] })}
              onRemoveButtonClick={({ detail }) =>
                setP({ groups: p.groups.filter((_, i) => i !== detail.itemIndex) })
              }
              addButtonText="Add group"
              removeButtonText="Remove"
              empty="No paging groups."
              definition={[
                {
                  label: 'Group URI',
                  control: (item, idx) => (
                    <Input
                      value={item.uri}
                      placeholder="sip:page-allcall@example"
                      onChange={({ detail }) => {
                        const next = [...p.groups];
                        next[idx] = detail.value;
                        setP({ groups: next });
                      }}
                    />
                  ),
                },
              ]}
            />
          </FormField>
        </SpaceBetween>
      ) : null}
    </SpaceBetween>
  );
}

export function EmergencyTab({ form, onChange }: Props) {
  const e = form.emergency;
  const setE = (patch: Partial<typeof e>) =>
    onChange({ ...form, emergency: { ...e, ...patch } });
  return (
    <ColumnLayout columns={2}>
      <FormField label="Emergency number" description="e.g. 911.">
        <Input
          value={e.emergency_number ?? ''}
          onChange={({ detail }) => setE({ emergency_number: detail.value || null })}
        />
      </FormField>
      <FormField label="Location ID" description="E911 location identifier.">
        <Input
          value={e.location_id ?? ''}
          onChange={({ detail }) => setE({ location_id: detail.value || null })}
        />
      </FormField>
      <FormField label="ELIN" description="Emergency Location Identification Number.">
        <Input
          value={e.elin ?? ''}
          onChange={({ detail }) => setE({ elin: detail.value || null })}
        />
      </FormField>
    </ColumnLayout>
  );
}
