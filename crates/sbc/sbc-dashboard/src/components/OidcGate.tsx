// Single sign-on gate: the whole dashboard requires an OIDC operator token
// (the dashboard now authenticates once for both the central config API and
// the per-site runtime API). If no valid token is cached, redirect to the
// IdP; the /callback route brings the operator back.

import { useEffect } from 'react';
import type { ReactNode } from 'react';
import Box from '@cloudscape-design/components/box';
import Spinner from '@cloudscape-design/components/spinner';

import { isAuthenticated, login } from '../auth/oidc';

export function OidcGate({ children }: { children: ReactNode }) {
  const authed = isAuthenticated();
  useEffect(() => {
    if (!authed) void login(globalThis.location.pathname);
  }, [authed]);

  if (!authed) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" /> Redirecting to sign-in…
      </Box>
    );
  }
  return <>{children}</>;
}
