/**
 * The privileged panel: open pull requests, and a review submitted as you.
 *
 * Two things this deliberately does not do. It does not render approval as a
 * single click — an armed action states the repository, the number, the verb,
 * and the seven characters of the commit it binds to, because a governance
 * dashboard that makes approving frictionless has replaced a review with a
 * button. And it never claims success it did not observe: an unaccounted-for
 * submit says so and sends you to GitHub, rather than resolving the ambiguity
 * in the reassuring direction.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { Session } from './lib/auth';
import {
  describeReviewError,
  fetchActorRepos,
  fetchOpenPulls,
  newIdempotencyKey,
  PrivilegedError,
  REVIEW_LABELS,
  submitReview,
  type ActorRepo,
  type PullSummary,
  type ReviewEvent,
} from './lib/review';

type ReviewProps = {
  session: Session;
  /** The session can no longer act — hand back to the sign-in screen. */
  onReauthRequired: () => void;
};

type Armed = {
  pull: PullSummary;
  event: ReviewEvent;
  body: string;
  /** Minted when the action is armed, so a second click reuses it. */
  idempotencyKey: string;
};

type Notice = { tone: 'ok' | 'warn' | 'danger'; message: string };

const EVENTS: ReviewEvent[] = ['APPROVE', 'REQUEST_CHANGES', 'COMMENT'];

function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

/** The panel an allowlisted admin sees when their session cannot act. */
function CannotAct({ session }: { session: Session }) {
  return (
    <section className="section">
      <header>
        <h2>Review</h2>
        <p className="lede">
          {session.provider === 'github'
            ? 'Your GitHub authorization has lapsed. Sign out and back in with GitHub to act.'
            : 'Privileged actions run as your GitHub account. This session signed in with ' +
              `${session.provider === 'apple' ? 'Apple' : 'Google'}, so it can read but not act.`}
        </p>
      </header>
    </section>
  );
}

export function Review({ session, onReauthRequired }: ReviewProps) {
  const [repos, setRepos] = useState<ActorRepo[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [pulls, setPulls] = useState<PullSummary[] | null>(null);
  const [armed, setArmed] = useState<Armed | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!session.privileged) return undefined;

    let cancelled = false;
    void (async () => {
      try {
        const found = await fetchActorRepos();
        if (cancelled) return;
        setRepos(found);
        setSelected((current) => current ?? found[0]?.fullName ?? null);
      } catch (caught) {
        if (cancelled) return;
        setRepos([]);
        setError(
          caught instanceof PrivilegedError ? caught.message : describeReviewError(null),
        );
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [session.privileged]);

  // Same discipline as the snapshot loader in Dashboard: only the most
  // recently started request may write state. Without it, switching
  // repositories mid-flight lets the older response land second — and the
  // selector then names repository B above repository A's pull requests,
  // which is exactly the mix-up an armed action must never be built from.
  const pullsRequest = useRef(0);

  const loadPulls = useCallback(async (fullName: string) => {
    const seq = ++pullsRequest.current;
    setPulls(null);
    setError(null);
    try {
      const found = await fetchOpenPulls(fullName);
      if (seq !== pullsRequest.current) return;
      setPulls(found);
    } catch (caught) {
      if (seq !== pullsRequest.current) return;
      setPulls([]);
      setError(caught instanceof PrivilegedError ? caught.message : describeReviewError(null));
    }
  }, []);

  useEffect(() => {
    if (!selected) return;
    void loadPulls(selected);
  }, [selected, loadPulls]);

  const arm = useCallback((pull: PullSummary, event: ReviewEvent) => {
    setNotice(null);
    setArmed({ pull, event, body: '', idempotencyKey: newIdempotencyKey() });
  }, []);

  const confirm = useCallback(async () => {
    if (!armed || !selected || busy) return;
    setBusy(true);
    setNotice(null);

    const outcome = await submitReview({
      repo: selected,
      number: armed.pull.number,
      headSha: armed.pull.headSha,
      event: armed.event,
      body: armed.body.trim(),
      idempotencyKey: armed.idempotencyKey,
    });

    setBusy(false);

    if (outcome.status === 'reauth') {
      onReauthRequired();
      return;
    }
    if (outcome.status === 'head_moved') {
      // Not an error to dismiss: the pull request on screen is stale, so the
      // armed action is withdrawn and the list refetched.
      setArmed(null);
      setNotice({
        tone: 'warn',
        message:
          `#${armed.pull.number} moved to ${shortSha(outcome.headSha)} while it was on screen. ` +
          'Nothing was submitted — review the new commit.',
      });
      void loadPulls(selected);
      return;
    }
    if (outcome.status === 'error') {
      setNotice({ tone: 'danger', message: outcome.message });
      return;
    }

    setArmed(null);
    setNotice({
      tone: 'ok',
      message: outcome.replay
        ? `${REVIEW_LABELS[armed.event]} was already submitted on #${armed.pull.number} — nothing was submitted twice.`
        : `${REVIEW_LABELS[armed.event]} submitted on #${armed.pull.number} at ${shortSha(armed.pull.headSha)}, as ${session.login ?? 'you'}.`,
    });
    void loadPulls(selected);
  }, [armed, selected, busy, loadPulls, onReauthRequired, session.login]);

  if (!session.admin) return null;
  if (!session.privileged) return <CannotAct session={session} />;

  return (
    <section className="section">
      <header>
        <h2>Review</h2>
        <p className="lede">
          Open pull requests in repositories this dashboard's GitHub App is installed on. Actions
          are performed as {session.login ?? 'your account'} and recorded before they are sent.
        </p>
      </header>

      <div className="review-controls">
        <label className="review-field">
          <span>Repository</span>
          <select
            value={selected ?? ''}
            disabled={!repos?.length}
            onChange={(event) => {
              setArmed(null);
              setNotice(null);
              setSelected(event.target.value);
            }}
          >
            {(repos ?? []).map((repo) => (
              <option key={repo.fullName} value={repo.fullName}>
                {repo.fullName}
                {repo.private ? ' (private)' : ''}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="signout"
          disabled={!selected || pulls === null}
          onClick={() => selected && void loadPulls(selected)}
        >
          Refresh
        </button>
      </div>

      {notice ? (
        <p className="review-notice" data-tone={notice.tone} role="status">
          {notice.message}
        </p>
      ) : null}

      {error ? (
        <p className="review-notice" data-tone="danger" role="alert">
          {error}
        </p>
      ) : null}

      {repos !== null && repos.length === 0 ? (
        <div className="state">
          No repositories. The GitHub App is not installed anywhere this account can reach.
        </div>
      ) : null}

      {armed ? (
        <div className="review-confirm" role="group" aria-label="Confirm review">
          <p>
            <strong>{REVIEW_LABELS[armed.event]}</strong> {selected} #{armed.pull.number} at{' '}
            <code>{shortSha(armed.pull.headSha)}</code>, as {session.login ?? 'you'}.
          </p>
          <p className="muted">{armed.pull.title}</p>
          <label className="review-field">
            <span>
              Comment{armed.event === 'APPROVE' ? ' (optional)' : ''}
            </span>
            <textarea
              rows={3}
              maxLength={2000}
              value={armed.body}
              onChange={(event) => setArmed({ ...armed, body: event.target.value })}
            />
          </label>
          <div className="review-actions">
            <button
              type="button"
              className="auth-button"
              data-variant="github"
              disabled={busy || (armed.event !== 'APPROVE' && !armed.body.trim())}
              onClick={() => void confirm()}
            >
              {busy ? 'Submitting…' : `Confirm ${REVIEW_LABELS[armed.event].toLowerCase()}`}
            </button>
            <button
              type="button"
              className="signout"
              disabled={busy}
              onClick={() => setArmed(null)}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>PR</th>
              <th>Title</th>
              <th>Author</th>
              <th>Head</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {pulls === null ? (
              <tr>
                <td colSpan={5} className="muted">
                  Loading…
                </td>
              </tr>
            ) : pulls.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  No open pull requests.
                </td>
              </tr>
            ) : (
              pulls.map((pull) => (
                <tr key={pull.number}>
                  <td>
                    {pull.htmlUrl ? (
                      <a className="repo-link" href={pull.htmlUrl} rel="noreferrer">
                        #{pull.number}
                      </a>
                    ) : (
                      <span className="repo-link">#{pull.number}</span>
                    )}
                  </td>
                  <td>
                    {pull.title}
                    {pull.draft ? (
                      <span className="badge" data-tone="muted">
                        draft
                      </span>
                    ) : null}
                  </td>
                  <td className="muted">{pull.author ?? '—'}</td>
                  <td className="muted">
                    <code>{shortSha(pull.headSha)}</code>
                  </td>
                  <td>
                    <div className="review-actions">
                      {EVENTS.map((event) => (
                        <button
                          key={event}
                          type="button"
                          className="signout"
                          disabled={busy}
                          onClick={() => arm(pull, event)}
                        >
                          {REVIEW_LABELS[event]}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
