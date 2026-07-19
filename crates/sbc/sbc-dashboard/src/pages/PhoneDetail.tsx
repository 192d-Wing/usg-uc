import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import BreadcrumbGroup from '@cloudscape-design/components/breadcrumb-group';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';

import { api, ApiError } from '../api';
import { centralApi } from '../centralApi';
import { useSite } from '../SiteContext';

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
  const { site } = useSite();
  const navigate = useNavigate();
  const [phone, setPhone] = useState<Phone | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id || !site) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    centralApi
      .get<Phone>(site, 'phones', id)
      .then((p) => {
        if (cancelled) return;
        setPhone(p);
      })
      .catch((e) => !cancelled && setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [id, site]);

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
                onClick={() =>
                  id && api.post(`/phones/${encodeURIComponent(id)}/reboot`, {}).catch((e) => setError(String(e)))
                }
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
      <SpaceBetween size="l">
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
