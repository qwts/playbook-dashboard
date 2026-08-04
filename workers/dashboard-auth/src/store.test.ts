import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Database, PreparedStatement, SqlValue } from './d1.ts';
import {
  beginAudit,
  deleteActorTokenIfUnchanged,
  deleteSupersededActorTokens,
  reapExpiredActorTokens,
  recordSignIn,
} from './store.ts';

/**
 * The sign-in record is deliberately opaque — provider, subject, timestamps,
 * a counter — so these tests assert on the statement itself: which columns it
 * names and which values it binds. A record that quietly grew a login or email
 * column again would pass any behavioural test and fail these.
 */

type Executed = { sql: string; args: SqlValue[] };

function capturingDb(): { db: Database; executed: Executed[] } {
  const executed: Executed[] = [];

  const db: Database = {
    prepare(sql: string): PreparedStatement {
      let args: SqlValue[] = [];
      const statement: PreparedStatement = {
        bind(...values: SqlValue[]) {
          args = values;
          return statement;
        },
        async first<T>(): Promise<T | null> {
          executed.push({ sql, args });
          return null;
        },
        async run() {
          executed.push({ sql, args });
          return { meta: { changes: 1 } };
        },
        async all<T>() {
          executed.push({ sql, args });
          return { results: [] as T[] };
        },
      };
      return statement;
    },
  };

  return { db, executed };
}

test('a sign-in record is provider, subject, timestamps, and a counter — nothing else', async () => {
  const { db, executed } = capturingDb();
  const now = 1_754_000_000;

  await recordSignIn(db, { provider: 'github', subject: '12345' }, now);

  assert.equal(executed.length, 1);
  const [statement] = executed;
  assert.ok(statement);

  assert.match(statement.sql, /INSERT INTO identities/);
  assert.doesNotMatch(statement.sql, /login|email|COALESCE/i, 'no plaintext PII columns');
  assert.deepEqual(statement.args, ['github', '12345', now, now]);
});

test('a repeat sign-in updates the row it already wrote', async () => {
  const { db, executed } = capturingDb();

  await recordSignIn(db, { provider: 'apple', subject: 'abc.def' }, 1);

  const [statement] = executed;
  assert.ok(statement);
  assert.match(statement.sql, /ON CONFLICT\(provider, subject\)/);
  assert.match(statement.sql, /sign_in_count \+ 1/);
  assert.match(statement.sql, /last_seen_at\s*=\s*excluded\.last_seen_at/);
});

test('the reaper deletes only rows whose refresh expiry has actually passed', async () => {
  const { db, executed } = capturingDb();
  const now = 1_754_000_000;

  await reapExpiredActorTokens(db, now);

  const [statement] = executed;
  assert.ok(statement);
  assert.match(
    statement.sql,
    /DELETE FROM actor_tokens\s+WHERE refresh_expires_at IS NOT NULL AND refresh_expires_at < \?/,
    'a NULL expiry means the token still works, and must survive the reap',
  );
  assert.deepEqual(statement.args, [now]);
});

test('the audit reservation counts and inserts in one atomic statement', async () => {
  const { db, executed } = capturingDb();
  const now = 1_754_000_000;

  const result = await beginAudit(
    db,
    {
      id: 'key-1',
      identity: { provider: 'github', subject: '12345' },
      login: 'chris',
      action: 'pull_request_review',
      repo: 'qwts/playbook-dashboard',
      target: '7',
      headSha: 'a'.repeat(40),
      verb: 'APPROVE',
    },
    now,
    { since: now - 60, limit: 10 },
  );

  assert.deepEqual(result, { status: 'recorded' });
  assert.equal(executed.length, 1, 'one statement — a separate count is a race window');
  const [statement] = executed;
  assert.ok(statement);
  assert.match(
    statement.sql,
    /WHERE \(SELECT COUNT\(\*\) FROM audit_log\s+WHERE provider = \? AND subject = \? AND started_at >= \?\) < \?/,
  );
  assert.deepEqual(statement.args.slice(10), ['github', '12345', now - 60, 10]);
});

test('a conditional delete names the ciphertext it read, so a racing winner survives', async () => {
  const { db, executed } = capturingDb();

  await deleteActorTokenIfUnchanged(db, 'session-1', 'sealed-blob');

  const [statement] = executed;
  assert.ok(statement);
  assert.match(statement.sql, /WHERE sid = \? AND secret = \?/);
  assert.deepEqual(statement.args, ['session-1', 'sealed-blob']);
});

test('a fresh sign-in evicts other sessions for the same identity, never its own', async () => {
  const { db, executed } = capturingDb();

  await deleteSupersededActorTokens(db, { provider: 'github', subject: '12345' }, 'fresh-sid');

  const [statement] = executed;
  assert.ok(statement);
  assert.match(statement.sql, /provider = \? AND subject = \? AND sid <> \?/);
  assert.deepEqual(statement.args, ['github', '12345', 'fresh-sid']);
});
