import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Database, PreparedStatement, SqlValue } from './d1.ts';
import { recordSignIn } from './store.ts';

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
