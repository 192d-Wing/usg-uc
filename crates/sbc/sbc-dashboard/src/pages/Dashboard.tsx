import { useEffect, useState } from 'react';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import SpaceBetween from '@cloudscape-design/components/space-between';

import { api, ApiError } from '../api';

type Health = { status?: string; uptime_seconds?: number };
type Stats = {
  active_calls?: number;
  total_calls?: number;
  registrations?: number;
  trunks_up?: number;
};

function formatUptime(seconds: number | undefined): string {
  if (seconds == null) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function Kpi({ label, value }: Readonly<{ label: string; value: string | number }>) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="h1" fontWeight="bold">
        {value}
      </Box>
    </div>
  );
}

export function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [regCount, setRegCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        type RegResp = { registrations: unknown[]; total?: number };
        const [h, s, r] = await Promise.all([
          api.get<Health>('/system/health').catch((): Health => ({})),
          api.get<Stats>('/system/stats').catch((): Stats => ({})),
          api.get<RegResp>('/registrations').catch((): RegResp => ({ registrations: [] })),
        ]);
        if (cancelled) return;
        setHealth(h);
        setStats(s);
        setRegCount(r.total ?? r.registrations.length);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof ApiError ? e.message : String(e));
      }
    };
    void load();
    const id = globalThis.setInterval(load, 10_000);
    return () => {
      cancelled = true;
      globalThis.clearInterval(id);
    };
  }, []);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="USG Session Border Controller status at a glance. Auto-refreshes every 10 seconds."
        >
          Dashboard
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">System</Header>}>
          <ColumnLayout columns={3} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Health</Box>
              {health?.status ? (
                <StatusIndicator
                  type={health.status.toLowerCase() === 'ok' ? 'success' : 'warning'}
                >
                  {health.status}
                </StatusIndicator>
              ) : (
                <StatusIndicator type="loading">Loading…</StatusIndicator>
              )}
            </div>
            <Kpi label="Uptime" value={formatUptime(health?.uptime_seconds)} />
            <Kpi label="Trunks up" value={stats?.trunks_up ?? '—'} />
          </ColumnLayout>
        </Container>

        <Container header={<Header variant="h2">Call activity</Header>}>
          <ColumnLayout columns={3} variant="text-grid">
            <Kpi label="Active calls" value={stats?.active_calls ?? '—'} />
            <Kpi label="Total calls" value={stats?.total_calls ?? '—'} />
            <Kpi label="Registrations" value={regCount ?? '—'} />
          </ColumnLayout>
        </Container>

        {error ? (
          <StatusIndicator type="error">{error}</StatusIndicator>
        ) : null}
      </SpaceBetween>
    </ContentLayout>
  );
}
