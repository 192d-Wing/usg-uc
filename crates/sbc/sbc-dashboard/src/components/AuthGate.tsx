// Authentication gate: checks the session on mount, renders the login form
// until the daemon accepts credentials, and drops back to login whenever any
// API call returns 401 (session expiry, daemon restart).
//
// The session itself lives in an HttpOnly cookie set by POST /auth/login —
// nothing is stored in localStorage or readable from JS.

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Header from '@cloudscape-design/components/header';
import Input from '@cloudscape-design/components/input';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';

import { api, ApiError, UNAUTHORIZED_EVENT } from '../api';

type AuthStatus = 'checking' | 'unauthenticated' | 'authenticated';

export function AuthGate({ children }: { readonly children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('checking');

  useEffect(() => {
    let cancelled = false;
    api
      .get('/auth/session')
      .then(() => {
        if (!cancelled) setStatus('authenticated');
      })
      .catch(() => {
        if (!cancelled) setStatus('unauthenticated');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onUnauthorized = () => setStatus('unauthenticated');
    globalThis.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => globalThis.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const onLoggedIn = useCallback(() => setStatus('authenticated'), []);

  if (status === 'checking') {
    return (
      <Box textAlign="center" padding={{ top: 'xxxl' }}>
        <Spinner size="large" />
      </Box>
    );
  }
  if (status === 'unauthenticated') {
    return <LoginForm onLoggedIn={onLoggedIn} />;
  }
  return <>{children}</>;
}

function LoginForm({ onLoggedIn }: { readonly onLoggedIn: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.post('/auth/login', { username, password });
      onLoggedIn();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setError('Invalid username or password.');
      } else {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box margin={{ top: 'xxxl' }} padding="xl">
      <div style={{ maxWidth: 420, margin: '0 auto' }}>
        <Container header={<Header variant="h1">USG SBC — Sign in</Header>}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <Form
              actions={
                <Button variant="primary" loading={busy} formAction="submit">
                  Sign in
                </Button>
              }
            >
              <SpaceBetween size="m">
                {error && <Alert type="error">{error}</Alert>}
                <FormField label="Username">
                  <Input
                    value={username}
                    onChange={({ detail }) => setUsername(detail.value)}
                    autoFocus
                    autoComplete="username"
                  />
                </FormField>
                <FormField label="Password">
                  <Input
                    type="password"
                    value={password}
                    onChange={({ detail }) => setPassword(detail.value)}
                    autoComplete="current-password"
                  />
                </FormField>
              </SpaceBetween>
            </Form>
          </form>
        </Container>
      </div>
    </Box>
  );
}
