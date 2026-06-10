import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import BreadcrumbGroup from '@cloudscape-design/components/breadcrumb-group';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Flashbar, { type FlashbarProps } from '@cloudscape-design/components/flashbar';
import Header from '@cloudscape-design/components/header';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import { api, ApiError } from '../api';

type Line = {
  index?: number;
  directory_number?: string;
  display_name?: string;
  sip_username?: string;
  sip_server?: string;
  sip_port?: number;
  transport?: string;
};

type Phone = Record<string, unknown> & {
  id: string;
  mac_address: string;
  name: string;
  status?: unknown;
  lines?: Line[];
};

function valueText(v: unknown): string {
  if (v == null) return '—';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

export function PhoneDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [phone, setPhone] = useState<Phone | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [flashItems, setFlashItems] = useState<FlashbarProps.MessageDefinition[]>([]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    api
      .get<Phone>(`/phones/${encodeURIComponent(id)}`)
      .then((p) => {
        if (cancelled) return;
        // Tolerate the {error: ...} response shape from the existing API.
        if ('error' in p && !p.mac_address) {
          setError(String(p.error));
        } else {
          setPhone(p);
        }
      })
      .catch((e) => !cancelled && setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [id]);

  const reboot = async () => {
    if (!id) return;
    setRebooting(true);
    try {
      await api.post(`/phones/${encodeURIComponent(id)}/reboot`, {});
      setFlashItems([
        {
          id: 'reboot-ok',
          type: 'success',
          content: `Reboot request sent to ${phone?.name ?? id}.`,
          dismissible: true,
          onDismiss: () => setFlashItems([]),
        },
      ]);
    } catch (e) {
      setFlashItems([
        {
          id: 'reboot-err',
          type: 'error',
          header: 'Reboot failed',
          content: e instanceof ApiError ? e.message : String(e),
          dismissible: true,
          onDismiss: () => setFlashItems([]),
        },
      ]);
    } finally {
      setRebooting(false);
      setConfirmReboot(false);
    }
  };

  return (
    <ContentLayout
      header={
        <SpaceBetween size="m">
          <BreadcrumbGroup
            items={[
              { text: 'Phones', href: '/phones' },
              { text: phone?.name ?? id ?? '', href: `/phones/${id}` },
            ]}
            onFollow={(e) => {
              e.preventDefault();
              navigate(e.detail.href);
            }}
          />
          <Header
            variant="h1"
            description={phone?.mac_address}
            actions={
              <Button
                onClick={() => setConfirmReboot(true)}
                loading={rebooting}
                disabled={!id || loading}
              >
                Reboot phone
              </Button>
            }
          >
            {phone?.name ?? 'Phone'}
          </Header>
        </SpaceBetween>
      }
    >
      <Modal
        visible={confirmReboot}
        onDismiss={() => setConfirmReboot(false)}
        header="Reboot phone"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setConfirmReboot(false)} disabled={rebooting}>
                Cancel
              </Button>
              <Button variant="primary" onClick={() => void reboot()} loading={rebooting}>
                Reboot
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        Reboot {phone?.name ?? id}? Any active calls on this phone will be dropped.
      </Modal>

      <SpaceBetween size="l">
        {flashItems.length ? <Flashbar items={flashItems} /> : null}
        {error ? <StatusIndicator type="error">{error}</StatusIndicator> : null}
        {loading ? <StatusIndicator type="loading">Loading…</StatusIndicator> : null}

        {phone ? (
          <>
            <Container header={<Header variant="h2">Identity</Header>}>
              <ColumnLayout columns={3} variant="text-grid">
                <div>
                  <Box variant="awsui-key-label">MAC address</Box>
                  <Box>{phone.mac_address}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Model</Box>
                  <Box>{valueText(phone.model)}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Status</Box>
                  <Box>{valueText(phone.status)}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">IP address</Box>
                  <Box>{valueText(phone.ip_address)}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Firmware</Box>
                  <Box>{valueText(phone.firmware_version)}</Box>
                </div>
                <div>
                  <Box variant="awsui-key-label">Owner</Box>
                  <Box>{valueText(phone.owner_id)}</Box>
                </div>
              </ColumnLayout>
            </Container>

            <Container header={<Header variant="h2" counter={`(${phone.lines?.length ?? 0})`}>Lines</Header>}>
              <Table
                items={phone.lines ?? []}
                trackBy={(l) => String(l.index ?? l.directory_number ?? '')}
                columnDefinitions={[
                  { id: 'index', header: '#', cell: (l) => l.index ?? '—' },
                  { id: 'dn', header: 'Extension', cell: (l) => l.directory_number ?? '—' },
                  { id: 'display', header: 'Display name', cell: (l) => l.display_name ?? '—' },
                  { id: 'user', header: 'SIP user', cell: (l) => l.sip_username ?? '—' },
                  {
                    id: 'server',
                    header: 'SIP server',
                    cell: (l) => `${l.sip_server ?? '—'}:${l.sip_port ?? ''} ${l.transport ?? ''}`,
                  },
                ]}
                empty={<Box>No lines configured.</Box>}
              />
            </Container>
          </>
        ) : null}
      </SpaceBetween>
    </ContentLayout>
  );
}
