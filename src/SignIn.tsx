import type { ReactElement } from 'react';
import { PROVIDER_LABELS, type Provider } from './lib/auth';

type SignInProps = {
  error: string | null;
  pending: Provider | null;
  onSignIn: (provider: Provider) => void;
};

function AppleMark() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M11.18 8.53c.02 2.1 1.84 2.8 1.86 2.81-.01.05-.29 1-.96 1.98-.58.85-1.18 1.69-2.13 1.71-.93.02-1.23-.55-2.3-.55-1.06 0-1.4.53-2.28.57-.91.03-1.61-.92-2.2-1.76-1.2-1.74-2.11-4.9-.88-7.04.61-1.06 1.7-1.73 2.88-1.75.9-.02 1.74.6 2.29.6.55 0 1.58-.75 2.66-.64.45.02 1.71.18 2.53 1.37-.07.04-1.51.88-1.49 2.63M9.44 3.34c.48-.59.81-1.4.72-2.21-.7.03-1.54.46-2.04 1.05-.45.52-.84 1.35-.74 2.15.78.06 1.58-.4 2.06-.99"
      />
    </svg>
  );
}

function GoogleMark() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M8.16 6.79v2.79h3.88c-.17 1.02-1.19 2.99-3.88 2.99-2.33 0-4.24-1.94-4.24-4.32s1.91-4.32 4.24-4.32c1.33 0 2.22.57 2.73 1.06l1.86-1.8C11.55 1.99 10 1.28 8.16 1.28A6.71 6.71 0 0 0 1.44 8a6.71 6.71 0 0 0 6.72 6.72c3.88 0 6.45-2.73 6.45-6.57 0-.44-.05-.78-.11-1.11z"
      />
    </svg>
  );
}

function GitHubMark() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8"
      />
    </svg>
  );
}

const PROVIDER_BUTTONS: { provider: Provider; Mark: () => ReactElement }[] = [
  { provider: 'apple', Mark: AppleMark },
  { provider: 'google', Mark: GoogleMark },
  { provider: 'github', Mark: GitHubMark },
];

export function SignIn({ error, pending, onSignIn }: SignInProps) {
  return (
    <main className="signin">
      <div className="signin-inner">
        <p className="signin-eyebrow">qwts governed fleet</p>
        <h1 className="signin-brand">Playbook Dashboard</h1>
        <p className="signin-lede">
          Security counts, repository properties, and CI status for the governed fleet. Sign in with
          any Apple, Google, or GitHub account to view it.
        </p>

        <div className="signin-actions">
          {PROVIDER_BUTTONS.map(({ provider, Mark }) => {
            const label = PROVIDER_LABELS[provider];
            return (
              <button
                key={provider}
                type="button"
                className="auth-button"
                data-variant={provider}
                disabled={pending !== null}
                onClick={() => onSignIn(provider)}
              >
                <Mark />
                {pending === provider ? `Contacting ${label}…` : `Continue with ${label}`}
              </button>
            );
          })}
        </div>

        {error ? (
          <p className="signin-error" role="alert">
            {error}
          </p>
        ) : null}

        <p className="signin-disclosure">
          Sign-ins are recorded: which provider, the account&rsquo;s stable ID with it, and when.
        </p>
      </div>
    </main>
  );
}
