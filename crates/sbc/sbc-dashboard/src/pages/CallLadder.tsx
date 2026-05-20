import { useState } from 'react';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Container from '@cloudscape-design/components/container';
import ContentLayout from '@cloudscape-design/components/content-layout';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import { api, ApiError } from '../api';

type Message = {
  timestamp?: number | string;
  from?: string;
  to?: string;
  method?: string;
  status?: string;
  direction?: string;
  summary?: string;
};

type Ladder = {
  call_id: string;
  participants: string[];
  messages: Message[];
};

export function CallLadder() {
  const [callId, setCallId] = useState('');
  const [ladder, setLadder] = useState<Ladder | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lookup = async () => {
    const id = callId.trim();
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<Ladder>(`/calls/${encodeURIComponent(id)}/ladder`);
      setLadder(res);
    } catch (e) {
      setLadder(null);
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="SIP message ladder diagram for a specific call. Enter the call_id from a CDR or active call."
        >
          Call Ladder
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Lookup</Header>}>
          <SpaceBetween size="s">
            <FormField label="Call ID" description="Opaque identifier exposed by /api/v1/calls and CDRs.">
              <Input
                value={callId}
                onChange={({ detail }) => setCallId(detail.value)}
                onKeyDown={(e) => {
                  if (e.detail.key === 'Enter') void lookup();
                }}
                placeholder="e.g. 8c4f1a-0b9d-b07c-abcd"
              />
            </FormField>
            <Box>
              <Button variant="primary" onClick={lookup} loading={loading} disabled={!callId.trim()}>
                Fetch ladder
              </Button>
            </Box>
          </SpaceBetween>
        </Container>

        {error ? <Alert type="error" header="Lookup failed">{error}</Alert> : null}

        {ladder ? (
          <SpaceBetween size="l">
            <Container header={<Header variant="h2">Call</Header>}>
              <ColumnLayout columns={2} variant="text-grid">
                <div>
                  <Box variant="awsui-key-label">Call ID</Box>
                  <Box>{ladder.call_id}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Participants</Box>
                  <Box>{ladder.participants?.join(' ↔ ') || '—'}</Box>
                </div>
              </ColumnLayout>
            </Container>

            <Container
              header={
                <Header variant="h2" counter={`(${ladder.messages?.length ?? 0})`}>
                  Messages
                </Header>
              }
            >
              <Table
                items={ladder.messages ?? []}
                trackBy={(m) => `${m.timestamp ?? ''}|${m.method ?? ''}|${m.from ?? ''}|${m.to ?? ''}`}
                columnDefinitions={[
                  { id: 'ts', header: 'Time', cell: (m) => String(m.timestamp ?? '—') },
                  { id: 'dir', header: 'Direction', cell: (m) => m.direction ?? '—' },
                  { id: 'from', header: 'From', cell: (m) => m.from ?? '—' },
                  { id: 'to', header: 'To', cell: (m) => m.to ?? '—' },
                  { id: 'method', header: 'Method / Status', cell: (m) => m.method ?? m.status ?? '—' },
                  { id: 'summary', header: 'Summary', cell: (m) => m.summary ?? '' },
                ]}
                empty={
                  <SpaceBetween size="xxs" alignItems="center">
                    <StatusIndicator type="in-progress">No messages captured</StatusIndicator>
                    <Box variant="p">
                      Ladder storage is not yet wired up server-side; the endpoint returns an empty messages array.
                    </Box>
                  </SpaceBetween>
                }
              />
            </Container>
          </SpaceBetween>
        ) : null}
      </SpaceBetween>
    </ContentLayout>
  );
}
