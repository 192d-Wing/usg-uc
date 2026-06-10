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
type RegResp = { registrations: unknown[]; total?: number };

function formatUptime(seconds: number | undefined): string {
  if (seconds == null) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function reasonText(reason: unknown): string {
  return reason instanceof ApiError ? reason.message : String(reason);
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

function HealthIndicator({
  health,
  failed,
}: Readonly<{ health: Health | null; failed: boolean }>) {
  if (failed) {
    return <StatusIndicator type="error">Unavailable</StatusIndicator>;
  }
  if (health?.status) {
    return (
      <StatusIndicator type={health.status.toLowerCase() === 'ok' ? 'success' : 'warning'}>
        {health.status}
      </StatusIndicator>
    );
  }
  return <StatusIndicator type="loading">Loading…</StatusIndicator>;
}

export function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [regCount, setRegCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      // allSettled (not all + per-fetch catch) so failures are observable:
      // each tile keeps whatever data it has, and failed fetches surface in
      // the error banner instead of an eternal "Loading…" state.
      const [h, s, r] = await Promise.allSettled([
        api.get<Health>('/system/health'),
        api.get<Stats>('/system/stats'),
        api.get<RegResp>('/registrations'),
      ]);
      if (cancelled) return;

      const failures: string[] = [];
      if (h.status === 'fulfilled') {
        setHealth(h.value);
        setHealthFailed(false);
      } else {
        setHealthFailed(true);
        failures.push(`health: ${reasonText(h.reason)}`);
      }
      if (s.status === 'fulfilled') {
        setStats(s.value);
      } else {
        failures.push(`stats: ${reasonText(s.reason)}`);
      }
      if (r.status === 'fulfilled') {
        setRegCount(r.value.total ?? r.value.registrations.length);
      } else {
        failures.push(`registrations: ${reasonText(r.reason)}`);
      }
      setError(failures.length ? failures.join(' · ') : null);
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
              <HealthIndicator health={health} failed={healthFailed} />
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
