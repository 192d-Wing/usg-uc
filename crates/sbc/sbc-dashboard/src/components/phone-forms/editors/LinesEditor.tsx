import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Toggle from '@cloudscape-design/components/toggle';

import type { CallForward, PhoneLine } from '../../../lib/phoneModel';
import { emptyCallForward, emptyLine } from '../../../lib/phoneModel';

const TRANSPORT_OPTIONS = [
  { value: 'udp', label: 'UDP' },
  { value: 'tcp', label: 'TCP' },
  { value: 'tls', label: 'TLS' },
];

export function LinesEditor({
  items,
  onChange,
  limit,
  showCallForward = true,
}: Readonly<{
  items: PhoneLine[];
  onChange: (next: PhoneLine[]) => void;
  limit: number;
  showCallForward?: boolean;
}>) {
  const updateLine = (idx: number, patch: Partial<PhoneLine>) => {
    const next = [...items];
    next[idx] = { ...next[idx], ...patch };
    onChange(next);
  };

  const updateCfwd = (idx: number, patch: Partial<CallForward>) => {
    const next = [...items];
    const cur = next[idx].call_forward ?? emptyCallForward();
    next[idx] = { ...next[idx], call_forward: { ...cur, ...patch } };
    onChange(next);
  };

  const addLine = () => {
    if (items.length >= limit) return;
    onChange([...items, emptyLine(items.length + 1)]);
  };

  const removeLine = (idx: number) => {
    const next = items
      .filter((_, i) => i !== idx)
      .map((it, i) => ({ ...it, index: i + 1 }));
    onChange(next);
  };

  return (
    <SpaceBetween size="m">
      {items.length === 0 ? (
        <Box color="text-status-inactive">No lines configured.</Box>
      ) : null}
      {items.map((line, idx) => {
        const transportOpt =
          TRANSPORT_OPTIONS.find((t) => t.value === line.transport) ?? TRANSPORT_OPTIONS[0];
        const cf = line.call_forward ?? emptyCallForward();
        const cfEnabled = line.call_forward !== null;
        return (
          <Container
            key={`line-${idx}`}
            header={
              <Header
                variant="h3"
                actions={
                  <Button onClick={() => removeLine(idx)} iconName="remove">
                    Remove
                  </Button>
                }
              >
                Line {line.index}
                {line.directory_number ? ` — ${line.directory_number}` : ''}
              </Header>
            }
          >
            <SpaceBetween size="s">
              <ColumnLayout columns={2}>
                <FormField label="Directory number" description="Extension or DID.">
                  <Input
                    value={line.directory_number}
                    onChange={({ detail }) => updateLine(idx, { directory_number: detail.value })}
                  />
                </FormField>
                <FormField label="Display name" description="Shown on the phone screen.">
                  <Input
                    value={line.display_name}
                    onChange={({ detail }) => updateLine(idx, { display_name: detail.value })}
                  />
                </FormField>
                <FormField label="SIP username (auth ID)">
                  <Input
                    value={line.sip_username}
                    onChange={({ detail }) => updateLine(idx, { sip_username: detail.value })}
                  />
                </FormField>
                <FormField label="SIP password">
                  <Input
                    type="password"
                    value={line.sip_password}
                    onChange={({ detail }) => updateLine(idx, { sip_password: detail.value })}
                  />
                </FormField>
                <FormField label="SIP server / registrar">
                  <Input
                    value={line.sip_server}
                    placeholder="e.g. sbc.example.com"
                    onChange={({ detail }) => updateLine(idx, { sip_server: detail.value })}
                  />
                </FormField>
                <FormField label="SIP port">
                  <Input
                    type="number"
                    value={String(line.sip_port)}
                    onChange={({ detail }) =>
                      updateLine(idx, { sip_port: Number(detail.value) || 5060 })
                    }
                  />
                </FormField>
                <FormField label="Transport">
                  <Select
                    selectedOption={transportOpt}
                    options={TRANSPORT_OPTIONS}
                    onChange={({ detail }) =>
                      updateLine(idx, {
                        transport: (detail.selectedOption?.value ?? 'udp') as string,
                      })
                    }
                  />
                </FormField>
                <FormField label="Voicemail URI (optional)" description="MWI subscription target.">
                  <Input
                    value={line.voicemail_uri ?? ''}
                    placeholder="e.g. sip:vm@example"
                    onChange={({ detail }) =>
                      updateLine(idx, { voicemail_uri: detail.value || null })
                    }
                  />
                </FormField>
                <FormField label="Owner user ID (optional)">
                  <Input
                    value={line.user_id ?? ''}
                    onChange={({ detail }) => updateLine(idx, { user_id: detail.value || null })}
                  />
                </FormField>
              </ColumnLayout>
              {showCallForward ? (
                <ExpandableSection
                  headerText="Call forwarding"
                  variant="footer"
                  defaultExpanded={cfEnabled}
                >
                  <SpaceBetween size="s">
                    <Toggle
                      checked={cfEnabled}
                      onChange={({ detail }) =>
                        updateLine(idx, {
                          call_forward: detail.checked ? emptyCallForward() : null,
                        })
                      }
                    >
                      Enable call forwarding
                    </Toggle>
                    {cfEnabled ? (
                      <ColumnLayout columns={2}>
                        <FormField label="Forward all calls to">
                          <Input
                            value={cf.all ?? ''}
                            placeholder="e.g. 2200"
                            onChange={({ detail }) =>
                              updateCfwd(idx, { all: detail.value || null })
                            }
                          />
                        </FormField>
                        <FormField label="Forward on busy to">
                          <Input
                            value={cf.busy ?? ''}
                            onChange={({ detail }) =>
                              updateCfwd(idx, { busy: detail.value || null })
                            }
                          />
                        </FormField>
                        <FormField label="Forward on no-answer to">
                          <Input
                            value={cf.no_answer ?? ''}
                            onChange={({ detail }) =>
                              updateCfwd(idx, { no_answer: detail.value || null })
                            }
                          />
                        </FormField>
                        <FormField label="No-answer timeout (seconds)">
                          <Input
                            type="number"
                            value={String(cf.no_answer_timeout)}
                            onChange={({ detail }) =>
                              updateCfwd(idx, { no_answer_timeout: Number(detail.value) || 20 })
                            }
                          />
                        </FormField>
                      </ColumnLayout>
                    ) : null}
                  </SpaceBetween>
                </ExpandableSection>
              ) : null}
            </SpaceBetween>
          </Container>
        );
      })}
      <Box>
        <Button
          onClick={addLine}
          iconName="add-plus"
          disabled={items.length >= limit}
        >
          {items.length >= limit ? `Max ${limit} lines` : 'Add line'}
        </Button>
      </Box>
    </SpaceBetween>
  );
}
