// Mirrors the PhoneModel enum from crates/uc/uc-phone-mgmt/src/model.rs.
// serde encodes unit variants as bare strings (e.g. "PolycomVVX450") and the
// Generic variant as { Generic: "..." }. Keep this file in sync when Rust
// gains new models.

export type PhoneFamily =
  | 'polycom_vvx'
  | 'polycom_trio'
  | 'poly_edge'
  | 'cisco_mpp'
  | 'cisco_9800'
  | 'teo'
  | 'generic';

export type ModelValue =
  // Polycom VVX
  | 'PolycomVVX150'
  | 'PolycomVVX250'
  | 'PolycomVVX350'
  | 'PolycomVVX450'
  | 'PolycomVVX501'
  | 'PolycomVVX601'
  // Polycom Trio
  | 'PolycomTrio8300'
  | 'PolycomTrio8500'
  | 'PolycomTrio8800'
  // Poly Edge
  | 'PolyEdgeE100'
  | 'PolyEdgeE220'
  | 'PolyEdgeE300'
  | 'PolyEdgeE320'
  | 'PolyEdgeE350'
  | 'PolyEdgeE400'
  | 'PolyEdgeE450'
  | 'PolyEdgeE500'
  | 'PolyEdgeE550'
  | 'PolyEdgeB10'
  | 'PolyEdgeB20'
  | 'PolyEdgeB30'
  // Cisco MPP
  | 'CiscoMPP6821'
  | 'CiscoMPP6841'
  | 'CiscoMPP6851'
  | 'CiscoMPP6861'
  | 'CiscoMPP6871'
  | 'CiscoMPP7811'
  | 'CiscoMPP7821'
  | 'CiscoMPP7841'
  | 'CiscoMPP7861'
  | 'CiscoMPP8811'
  | 'CiscoMPP8841'
  | 'CiscoMPP8851'
  | 'CiscoMPP8861'
  // Cisco 9800
  | 'Cisco9841'
  | 'Cisco9851'
  | 'Cisco9861'
  | 'Cisco9871'
  // Teo
  | 'Teo7810'
  | 'Teo7810TSG'
  | 'Teo4104'
  | 'Teo4101'
  // Generic — represented as { Generic: name } on the wire
  | 'Generic';

export type SerializedModel = ModelValue | { Generic: string };

export type ModelOption = {
  value: ModelValue;
  label: string;
  family: PhoneFamily;
  maxLines: number;
};

export const MODEL_OPTIONS: readonly ModelOption[] = [
  // Polycom VVX
  { value: 'PolycomVVX150', label: 'Polycom VVX 150', family: 'polycom_vvx', maxLines: 2 },
  { value: 'PolycomVVX250', label: 'Polycom VVX 250', family: 'polycom_vvx', maxLines: 4 },
  { value: 'PolycomVVX350', label: 'Polycom VVX 350', family: 'polycom_vvx', maxLines: 6 },
  { value: 'PolycomVVX450', label: 'Polycom VVX 450', family: 'polycom_vvx', maxLines: 12 },
  { value: 'PolycomVVX501', label: 'Polycom VVX 501', family: 'polycom_vvx', maxLines: 12 },
  { value: 'PolycomVVX601', label: 'Polycom VVX 601', family: 'polycom_vvx', maxLines: 16 },
  // Polycom Trio
  { value: 'PolycomTrio8300', label: 'Polycom Trio 8300', family: 'polycom_trio', maxLines: 1 },
  { value: 'PolycomTrio8500', label: 'Polycom Trio 8500', family: 'polycom_trio', maxLines: 1 },
  { value: 'PolycomTrio8800', label: 'Polycom Trio 8800', family: 'polycom_trio', maxLines: 1 },
  // Poly Edge
  { value: 'PolyEdgeE100', label: 'Poly Edge E100', family: 'poly_edge', maxLines: 2 },
  { value: 'PolyEdgeE220', label: 'Poly Edge E220', family: 'poly_edge', maxLines: 4 },
  { value: 'PolyEdgeE300', label: 'Poly Edge E300', family: 'poly_edge', maxLines: 8 },
  { value: 'PolyEdgeE320', label: 'Poly Edge E320', family: 'poly_edge', maxLines: 8 },
  { value: 'PolyEdgeE350', label: 'Poly Edge E350', family: 'poly_edge', maxLines: 8 },
  { value: 'PolyEdgeE400', label: 'Poly Edge E400', family: 'poly_edge', maxLines: 12 },
  { value: 'PolyEdgeE450', label: 'Poly Edge E450', family: 'poly_edge', maxLines: 16 },
  { value: 'PolyEdgeE500', label: 'Poly Edge E500', family: 'poly_edge', maxLines: 24 },
  { value: 'PolyEdgeE550', label: 'Poly Edge E550', family: 'poly_edge', maxLines: 34 },
  { value: 'PolyEdgeB10', label: 'Poly Edge B10 (expansion)', family: 'poly_edge', maxLines: 0 },
  { value: 'PolyEdgeB20', label: 'Poly Edge B20 (expansion)', family: 'poly_edge', maxLines: 0 },
  { value: 'PolyEdgeB30', label: 'Poly Edge B30 (expansion)', family: 'poly_edge', maxLines: 0 },
  // Cisco MPP
  { value: 'CiscoMPP6821', label: 'Cisco MPP 6821', family: 'cisco_mpp', maxLines: 2 },
  { value: 'CiscoMPP6841', label: 'Cisco MPP 6841', family: 'cisco_mpp', maxLines: 4 },
  { value: 'CiscoMPP6851', label: 'Cisco MPP 6851', family: 'cisco_mpp', maxLines: 4 },
  { value: 'CiscoMPP6861', label: 'Cisco MPP 6861', family: 'cisco_mpp', maxLines: 4 },
  { value: 'CiscoMPP6871', label: 'Cisco MPP 6871', family: 'cisco_mpp', maxLines: 6 },
  { value: 'CiscoMPP7811', label: 'Cisco MPP 7811', family: 'cisco_mpp', maxLines: 1 },
  { value: 'CiscoMPP7821', label: 'Cisco MPP 7821', family: 'cisco_mpp', maxLines: 2 },
  { value: 'CiscoMPP7841', label: 'Cisco MPP 7841', family: 'cisco_mpp', maxLines: 4 },
  { value: 'CiscoMPP7861', label: 'Cisco MPP 7861', family: 'cisco_mpp', maxLines: 4 },
  { value: 'CiscoMPP8811', label: 'Cisco MPP 8811', family: 'cisco_mpp', maxLines: 5 },
  { value: 'CiscoMPP8841', label: 'Cisco MPP 8841', family: 'cisco_mpp', maxLines: 5 },
  { value: 'CiscoMPP8851', label: 'Cisco MPP 8851', family: 'cisco_mpp', maxLines: 5 },
  { value: 'CiscoMPP8861', label: 'Cisco MPP 8861', family: 'cisco_mpp', maxLines: 5 },
  // Cisco 9800
  { value: 'Cisco9841', label: 'Cisco 9841', family: 'cisco_9800', maxLines: 4 },
  { value: 'Cisco9851', label: 'Cisco 9851', family: 'cisco_9800', maxLines: 6 },
  { value: 'Cisco9861', label: 'Cisco 9861', family: 'cisco_9800', maxLines: 10 },
  { value: 'Cisco9871', label: 'Cisco 9871', family: 'cisco_9800', maxLines: 12 },
  // Teo
  { value: 'Teo7810', label: 'Teo 7810', family: 'teo', maxLines: 10 },
  { value: 'Teo7810TSG', label: 'Teo 7810-TSG', family: 'teo', maxLines: 10 },
  { value: 'Teo4104', label: 'Teo 4104', family: 'teo', maxLines: 16 },
  { value: 'Teo4101', label: 'Teo 4101', family: 'teo', maxLines: 1 },
  // Generic
  { value: 'Generic', label: 'Generic (custom name)', family: 'generic', maxLines: 4 },
];

const MODEL_INDEX: Record<ModelValue, ModelOption> = MODEL_OPTIONS.reduce(
  (acc, opt) => {
    acc[opt.value] = opt;
    return acc;
  },
  {} as Record<ModelValue, ModelOption>,
);

export function findModelOption(value: ModelValue): ModelOption {
  return MODEL_INDEX[value] ?? MODEL_INDEX.Generic;
}

export const FAMILY_LABELS: Record<PhoneFamily, string> = {
  polycom_vvx: 'Polycom VVX',
  polycom_trio: 'Polycom Trio',
  poly_edge: 'Poly Edge',
  cisco_mpp: 'Cisco MPP',
  cisco_9800: 'Cisco 9800',
  teo: 'Teo / Tone Commander',
  generic: 'Generic',
};

const FAMILY_ORDER: readonly PhoneFamily[] = [
  'polycom_vvx',
  'polycom_trio',
  'poly_edge',
  'cisco_mpp',
  'cisco_9800',
  'teo',
  'generic',
];

// Cloudscape Select supports option groups via `options: [{ label, options: [...] }]`.
// We pre-build the grouped list once.
export const GROUPED_MODEL_OPTIONS = FAMILY_ORDER.map((family) => ({
  label: FAMILY_LABELS[family],
  options: MODEL_OPTIONS.filter((o) => o.family === family).map(({ value, label }) => ({
    value,
    label,
  })),
}));

// Inspect a serialized PhoneModel (string or {Generic: name}) and return the
// in-UI {value, genericName} pair.
export function unpackSerializedModel(model: unknown): {
  value: ModelValue;
  genericName: string;
} {
  if (typeof model === 'string' && model in MODEL_INDEX) {
    return { value: model as ModelValue, genericName: '' };
  }
  if (model && typeof model === 'object') {
    const entry = Object.entries(model as Record<string, unknown>)[0];
    if (entry?.[0] === 'Generic' && typeof entry[1] === 'string') {
      return { value: 'Generic', genericName: entry[1] };
    }
  }
  return { value: 'PolycomVVX450', genericName: '' };
}

// Build the on-the-wire model payload from the UI form pair.
export function packModel(value: ModelValue, genericName: string): SerializedModel {
  if (value === 'Generic') return { Generic: genericName.trim() };
  return value;
}

export function familyOf(value: ModelValue): PhoneFamily {
  return findModelOption(value).family;
}

export function maxLinesOf(value: ModelValue): number {
  return findModelOption(value).maxLines;
}

// ----- Phone struct mirror (matches uc-phone-mgmt::Phone) -----

export type PhoneLine = {
  index: number;
  directory_number: string;
  display_name: string;
  user_id: string | null;
  sip_username: string;
  sip_password: string;
  sip_server: string;
  sip_port: number;
  transport: string; // "udp" | "tcp" | "tls"
  voicemail_uri: string | null;
  call_forward: CallForward | null;
};

export type CallForward = {
  all: string | null;
  busy: string | null;
  no_answer: string | null;
  no_answer_timeout: number;
};

export type SpeedDial = {
  index: number;
  label: string;
  number: string;
};

export type BlfEntry = {
  index: number;
  label: string;
  address: string;
};

export type SoftkeyAction =
  | 'SpeedDial'
  | 'Blf'
  | 'Park'
  | 'Transfer'
  | 'Conference'
  | 'Dnd'
  | 'Intercom'
  | { Custom: string };

export type SoftkeyConfig = {
  index: number;
  label: string;
  action: SoftkeyAction;
  value: string | null;
};

export type PhoneFeatures = {
  auto_answer: boolean;
  dnd: boolean;
  intercom: boolean;
  call_recording: boolean;
  hotdesking: boolean;
};

export type NetworkConfig = {
  vlan_id: number | null;
  cdp_enabled: boolean;
  lldp_enabled: boolean;
  dot1x_enabled: boolean;
  qos_dscp: number | null;
};

export type DisplayConfig = {
  language: string | null;
  brightness: number | null;
  ringtone: string | null;
  time_24hr: boolean;
  timezone: string | null;
  ntp_server: string | null;
};

export type HeadsetMode = 'Wired' | 'Usb' | 'Bluetooth' | 'Dect';

export type AudioConfig = {
  headset_mode: HeadsetMode;
  noise_reduction: boolean;
  echo_cancellation: boolean;
};

export type DirectoryConfig = {
  enabled: boolean;
  ldap_server: string | null;
  ldap_port: number | null;
  ldap_base_dn: string | null;
  ldap_bind_dn: string | null;
  ldap_password: string | null;
  ldap_tls: boolean;
};

export type PagingConfig = {
  enabled: boolean;
  groups: string[];
  multicast_address: string | null;
};

export type EmergencyConfig = {
  emergency_number: string | null;
  location_id: string | null;
  elin: string | null;
};

export type PhoneStatus =
  | 'Unprovisioned'
  | 'Provisioning'
  | 'Registered'
  | 'Offline'
  | { Error: string };

export type Phone = {
  id: string;
  mac_address: string;
  model: SerializedModel;
  firmware_version: string | null;
  target_firmware: string | null;
  name: string;
  description: string | null;
  owner_id: string | null;
  lines: PhoneLine[];
  device_pool: string | null;
  calling_search_space: string | null;
  status: PhoneStatus;
  ip_address: string | null;
  registered_at: number | null;
  last_seen: number | null;
  config_version: number;
  speed_dials: SpeedDial[];
  blf_entries: BlfEntry[];
  softkeys: SoftkeyConfig[];
  features: PhoneFeatures;
  network: NetworkConfig;
  display: DisplayConfig;
  audio: AudioConfig;
  directory: DirectoryConfig;
  paging: PagingConfig;
  emergency: EmergencyConfig;
};

// Mirrors Rust `Phone::new` defaults — id stays "" until create returns the
// server-assigned UUID, mac/model/name come from the form.
export function emptyPhone(model: SerializedModel): Phone {
  return {
    id: '',
    mac_address: '',
    model,
    firmware_version: null,
    target_firmware: null,
    name: '',
    description: null,
    owner_id: null,
    lines: [],
    device_pool: null,
    calling_search_space: null,
    status: 'Unprovisioned',
    ip_address: null,
    registered_at: null,
    last_seen: null,
    config_version: 1,
    speed_dials: [],
    blf_entries: [],
    softkeys: [],
    features: {
      auto_answer: false,
      dnd: false,
      intercom: false,
      call_recording: false,
      hotdesking: false,
    },
    network: {
      vlan_id: null,
      cdp_enabled: false,
      lldp_enabled: false,
      dot1x_enabled: false,
      qos_dscp: null,
    },
    display: {
      language: null,
      brightness: null,
      ringtone: null,
      time_24hr: true,
      timezone: null,
      ntp_server: null,
    },
    audio: {
      headset_mode: 'Wired',
      noise_reduction: false,
      echo_cancellation: true,
    },
    directory: {
      enabled: false,
      ldap_server: null,
      ldap_port: null,
      ldap_base_dn: null,
      ldap_bind_dn: null,
      ldap_password: null,
      ldap_tls: false,
    },
    paging: {
      enabled: false,
      groups: [],
      multicast_address: null,
    },
    emergency: {
      emergency_number: null,
      location_id: null,
      elin: null,
    },
  };
}

export function emptyLine(index: number): PhoneLine {
  return {
    index,
    directory_number: '',
    display_name: '',
    user_id: null,
    sip_username: '',
    sip_password: '',
    sip_server: '',
    sip_port: 5060,
    transport: 'udp',
    voicemail_uri: null,
    call_forward: null,
  };
}

export function emptyCallForward(): CallForward {
  return { all: null, busy: null, no_answer: null, no_answer_timeout: 20 };
}

export function emptySpeedDial(index: number): SpeedDial {
  return { index, label: '', number: '' };
}

export function emptyBlf(index: number): BlfEntry {
  return { index, label: '', address: '' };
}

export function emptySoftkey(index: number): SoftkeyConfig {
  return { index, label: '', action: 'SpeedDial', value: null };
}
