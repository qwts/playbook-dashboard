/**
 * The slice of D1 this Worker uses, declared structurally.
 *
 * `D1Database` is an ambient type from `@cloudflare/workers-types`, and
 * `tsconfig.test.json` drops those types so tests can run under node. Naming
 * the surface here keeps `Env` typecheckable under both, and doubles as the
 * list of database capabilities this Worker is allowed to reach for.
 */

export type SqlValue = string | number | null;

export type PreparedStatement = {
  bind(...values: SqlValue[]): PreparedStatement;
  first<T>(): Promise<T | null>;
  run(): Promise<{ meta: { changes?: number } }>;
  all<T>(): Promise<{ results: T[] }>;
};

export type Database = {
  prepare(query: string): PreparedStatement;
};
