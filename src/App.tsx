import { useCallback, useEffect, useState } from 'react';
import { Dashboard } from './Dashboard';
import { SignIn } from './SignIn';
import {
  AUTH_DISABLED,
  beginLogin,
  consumeCallback,
  describeAuthError,
  fetchSession,
  logout,
  onAuthRequired,
  type Provider,
  type Session,
} from './lib/auth';

type AuthState =
  | { status: 'checking' }
  | { status: 'anonymous'; error: string | null }
  | { status: 'authenticated'; session: Session | null };

export function App() {
  const [auth, setAuth] = useState<AuthState>(
    AUTH_DISABLED ? { status: 'authenticated', session: null } : { status: 'checking' },
  );
  const [pending, setPending] = useState<Provider | null>(null);

  useEffect(() => {
    if (AUTH_DISABLED) return;

    let cancelled = false;

    void (async () => {
      const callback = await consumeCallback();
      const session = await fetchSession().catch(() => null);
      if (cancelled) return;

      setAuth(
        session
          ? { status: 'authenticated', session }
          : { status: 'anonymous', error: describeAuthError(callback.error) },
      );
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (AUTH_DISABLED) return undefined;
    return onAuthRequired(() => {
      setAuth((current) =>
        current.status === 'authenticated' ? { status: 'anonymous', error: null } : current,
      );
    });
  }, []);

  const handleSignIn = useCallback((provider: Provider) => {
    setPending(provider);
    void beginLogin(provider).catch(() => {
      setPending(null);
      setAuth({ status: 'anonymous', error: describeAuthError('network_error') });
    });
  }, []);

  const handleSignOut = useCallback(() => {
    void logout().then(() => {
      setAuth({ status: 'anonymous', error: null });
    });
  }, []);

  if (auth.status === 'checking') {
    return (
      <div className="app">
        <div className="state">Checking access…</div>
      </div>
    );
  }

  if (auth.status === 'anonymous') {
    return <SignIn error={auth.error} pending={pending} onSignIn={handleSignIn} />;
  }

  return <Dashboard session={auth.session} onSignOut={handleSignOut} />;
}
