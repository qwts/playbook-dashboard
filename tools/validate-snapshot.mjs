#!/usr/bin/env node

/**
 * Refuse to publish an artifact that is not what the contract says it is.
 *
 * Runs in `npm run ci` and between collect and build in the Pages workflow.
 * Nothing else inspects the snapshot between generating it and serving it.
 *
 * **This one fails closed, unlike the other gates.** The stale and degraded
 * gates deploy first and then redden the run, because a legible degraded
 * dashboard beats an outage. That trade does not hold here: a snapshot failing
 * this check may contain something the redaction contract forbids, and
 * publishing it to find out is the whole failure. A non-zero exit here fails
 * the collect job, so build and deploy never run and the previously published
 * artifact stays exactly where it is.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { validateSnapshot } from './snapshot-schema.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_PATH = path.join(ROOT, 'public', 'data', 'snapshot.json');

function main(argv) {
  // `--fresh` additionally requires the snapshot to be recent. Only a run that
  // just collected may ask for it: the committed fixture is a real published
  // artifact and must satisfy every structural rule, but it is deliberately
  // old — being the fallback is its job.
  const requireFresh = argv.includes('--fresh');
  const target = argv.find((arg) => !arg.startsWith('--')) ?? DEFAULT_PATH;

  let snapshot;
  try {
    snapshot = JSON.parse(readFileSync(target, 'utf8'));
  } catch (error) {
    // The path and the parser's complaint, never the file's contents.
    process.stderr.write(`snapshot at ${target} could not be read as JSON\n`);
    process.stderr.write(`${error instanceof Error ? error.message : 'unknown error'}\n`);
    return 1;
  }

  const violations = validateSnapshot(snapshot, { requireFresh });
  if (violations.length === 0) {
    process.stderr.write(
      `snapshot upholds the redaction contract (${snapshot.repos?.length ?? 0} repos` +
        `${requireFresh ? ', freshly collected' : ''})\n`,
    );
    return 0;
  }

  // Field paths and reasons only. A violation message never quotes the value:
  // the thing that failed validation is exactly the thing not to put in a log
  // that is public on this repository.
  process.stderr.write(`snapshot violates the redaction contract in ${violations.length} place(s):\n`);
  for (const violation of violations) process.stderr.write(`  - ${violation}\n`);
  process.stderr.write('\nRefusing to publish. See tools/snapshot-schema.mjs and DESIGN.md.\n');
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}

export { main };
