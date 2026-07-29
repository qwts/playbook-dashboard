/**
 * The redaction contract, executable.
 *
 * The rule used to live in a comment at the top of `collect.mjs`, and a comment
 * cannot fail a build. `Snapshot` in `src/types/snapshot.ts` describes the
 * intended shape, but it is a compile-time type over a file written at runtime
 * and fetched by a browser — `tsc` never sees the bytes that ship.
 *
 * The consequence was that the published surface could only grow. Any change
 * adding a field to a collector return value published that field silently, on
 * the next hourly cron, with no step at which anyone saw that the artifact now
 * contained something it did not contain before.
 *
 * **The assertion that matters is the closed key set at every level.** Checking
 * that known fields are well-formed catches malformed data; only rejecting
 * unknown keys catches *new* data, and new data is how a leak arrives. A field
 * added here is a deliberate act with a diff attached.
 *
 * Counts and booleans only — never alert titles, file paths, CVEs, secret
 * material, or private vulnerability report bodies.
 */

import {
  ALLOWED_URL_ORIGIN,
  MAX_DELTA_LENGTH,
  MAX_WORKFLOW_NAME_LENGTH,
  sanitizeGithubUrl,
} from './collect.mjs';

/** Matches `isSnapshotStale` in src/lib/aggregate.ts. */
export const STALE_MS = 24 * 60 * 60 * 1000;

/**
 * Length caps on every string that reaches the page.
 *
 * The manifest is untrusted input and so is a cached snapshot, so unbounded
 * free text reaching a public page is a blast radius worth bounding regardless
 * of who authored it. `delta` and `workflowName` share their caps with the
 * collector's own checks rather than restating them.
 */
export const CAPS = {
  account: 39,
  manifestRepo: 128,
  manifestPath: 256,
  name: 100,
  delta: MAX_DELTA_LENGTH,
  visibility: 32,
  workflowName: MAX_WORKFLOW_NAME_LENGTH,
  conclusion: 32,
  status: 32,
};

const STATUSES = new Set(['active', 'onboarding', 'retired']);

/** Written as escapes: a literal control byte in source is invisible in review. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/u;

// --- leaf checks ---------------------------------------------------------
// Each returns null when the value is acceptable, or a reason.

const isCount = (value) =>
  value === null || (Number.isInteger(value) && value >= 0)
    ? null
    : 'must be null or a non-negative integer';

const isFlag = (value) =>
  value === null || typeof value === 'boolean' ? null : 'must be null or a boolean';

const isBool = (value) => (typeof value === 'boolean' ? null : 'must be a boolean');

function isText(cap, { nullable = false } = {}) {
  return (value) => {
    if (value === null) return nullable ? null : 'must not be null';
    if (typeof value !== 'string') return 'must be a string';
    if (value.length > cap) return `exceeds the ${cap}-character cap (${value.length})`;
    // A control character in published text is either corruption or an attempt
    // to forge structure in whatever reads it next.
    if (CONTROL_CHARS.test(value)) return 'contains control characters';
    return null;
  };
}

/**
 * A URL field is validated by the collector's own function, not a second copy
 * of the rule. Two definitions of "is this safe to put in an href" drift, and
 * the drift is invisible until one of them is wrong.
 */
const isUrl = (value) => {
  if (value === null) return null;
  if (sanitizeGithubUrl(value) !== value) {
    return `must be null or a normalized ${ALLOWED_URL_ORIGIN} URL`;
  }
  return null;
};

/** Honest clock drift between GitHub's runners and whoever validates next. */
const CLOCK_SKEW_MS = 60_000;

/**
 * Every timestamp, not just `generatedAt`, is refused a future value. A future
 * `ci.updatedAt` reads as maximally current for as long as the skew lasts —
 * the same direction that suppresses the staleness warning, one field down.
 * `now` arrives through the rule context so there is exactly one clock per
 * validation, not a `Date.now()` in every rule that needs one.
 */
const isTimestamp = (value, { now }) => {
  if (value === null) return null;
  if (typeof value !== 'string') return 'must be a string';
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) return 'is not a parseable timestamp';
  if (ts > now + CLOCK_SKEW_MS) return 'is in the future';
  return null;
};

// --- the contract --------------------------------------------------------

const CI = {
  workflowName: isText(CAPS.workflowName, { nullable: true }),
  conclusion: isText(CAPS.conclusion, { nullable: true }),
  status: isText(CAPS.status, { nullable: true }),
  updatedAt: isTimestamp,
  htmlUrl: isUrl,
};

const SECURITY_FLOOR = {
  secretScanning: isFlag,
  pushProtection: isFlag,
  dependabotAlerts: isFlag,
  privateVulnerabilityReporting: isFlag,
  codeqlConfigured: isFlag,
  defaultBranchRuleset: isFlag,
};

const SECURITY = {
  dependabotOpen: isCount,
  codeScanningOpen: isCount,
  secretScanningOpen: isCount,
};

const REPO = {
  name: isText(CAPS.name),
  // Only `public` may be published at all. The field is retained so a stale or
  // hand-edited snapshot can still be filtered at render time, but a snapshot
  // that ships anything else has already failed the publication gate.
  visibility: (value) => (value === 'public' ? null : "must be exactly 'public' to be published"),
  status: (value) => (STATUSES.has(value) ? null : `must be one of ${[...STATUSES].join(', ')}`),
  sharedCi: isBool,
  codexSyncEnabled: isFlag,
  delta: isText(CAPS.delta),
  htmlUrl: isUrl,
  securityFloor: SECURITY_FLOOR,
  security: SECURITY,
  ci: CI,
};

export const SNAPSHOT = {
  schemaVersion: (value) => (value === 1 ? null : 'must be exactly 1'),
  generatedAt: (value, ctx) =>
    typeof value === 'string' ? isTimestamp(value, ctx) : 'must be a timestamp string',
  source: {
    account: isText(CAPS.account),
    manifestRepo: isText(CAPS.manifestRepo),
    manifestPath: isText(CAPS.manifestPath),
  },
  withheld: isCount,
  unreadable: isCount,
  collection: {
    denied: (value) => (Number.isInteger(value) && value >= 0 ? null : 'must be a count'),
    rateLimited: (value) => (Number.isInteger(value) && value >= 0 ? null : 'must be a count'),
    failed: (value) => (Number.isInteger(value) && value >= 0 ? null : 'must be a count'),
  },
  repos: null, // handled explicitly: an array of REPO
};

// --- walking -------------------------------------------------------------

function checkShape(value, shape, path, violations, ctx) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    violations.push(`${path} must be an object`);
    return;
  }

  // The whole point. Anything not named in the contract is a field nobody
  // decided to publish, and it is rejected before its contents are considered.
  //
  // `Object.hasOwn`, not `in`: `in` walks the prototype chain, so a field
  // named `toString` or `constructor` — an ordinary own key under JSON.parse —
  // would match `Object.prototype`, pass the closed-key-set check, and ship
  // with its value never validated. Prototype-named keys are exactly the ones
  // an attacker reaches for.
  for (const key of Object.keys(value)) {
    if (!Object.hasOwn(shape, key)) violations.push(`${path}.${key} is not in the published schema`);
  }

  for (const [key, rule] of Object.entries(shape)) {
    if (rule === null) continue;
    if (!Object.hasOwn(value, key)) {
      violations.push(`${path}.${key} is missing`);
      continue;
    }
    if (typeof rule === 'function') {
      const reason = rule(value[key], ctx);
      if (reason) violations.push(`${path}.${key} ${reason}`);
    } else {
      checkShape(value[key], rule, `${path}.${key}`, violations, ctx);
    }
  }
}

/**
 * Every way the artifact fails the contract, as a list. Empty means it ships.
 *
 * Reports all violations rather than the first, because a snapshot that gained
 * three fields should say so once, not across three runs an hour apart.
 *
 * `requireFresh` is off by default: the committed fixture is a published
 * artifact and must satisfy every structural rule, but it is deliberately old —
 * it is the fallback deployed when collection fails. Staleness is a property of
 * a run, not of the contract.
 */
export function validateSnapshot(snapshot, { now = Date.now(), requireFresh = false } = {}) {
  const violations = [];
  // One clock for the whole validation. The future check lives in
  // `isTimestamp` — every timestamp field gets it through this context —
  // so this function only owns the check that needs the flag: staleness.
  const ctx = { now };
  checkShape(snapshot, SNAPSHOT, 'snapshot', violations, ctx);

  if (!Array.isArray(snapshot?.repos)) {
    violations.push('snapshot.repos must be an array');
  } else {
    snapshot.repos.forEach((repo, index) => {
      checkShape(repo, REPO, `snapshot.repos[${index}]`, violations, ctx);
    });

    const names = snapshot.repos.map((repo) => repo?.name);
    if (new Set(names).size !== names.length) {
      violations.push('snapshot.repos contains duplicate names');
    }
  }

  const ts = Date.parse(snapshot?.generatedAt);
  if (Number.isFinite(ts) && requireFresh && now - ts > STALE_MS) {
    violations.push('snapshot.generatedAt is older than the staleness threshold');
  }

  return violations;
}
