/**
 * Node-side entry to the redaction contract.
 *
 * The contract itself lives in `src/lib/snapshot-schema.ts` so the browser can
 * run the same definition against a fetched snapshot that `npm run validate`
 * runs against the artifact before it ships. This file exists so tools keep a
 * stable import path — it must never grow a second copy of a rule.
 *
 * Node 24 resolves the `.ts` import through built-in type stripping, the same
 * way the repo's TypeScript tests already run.
 */

export {
  CAPS,
  SNAPSHOT,
  STALE_MS,
  validateSnapshot,
} from '../src/lib/snapshot-schema.ts';
