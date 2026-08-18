/**
 * The redaction contract, executable — and shared.
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
 * This module lives in `src/lib` with zero Node dependencies so the same
 * definition runs at both ends of the pipe: `tools/validate-snapshot.mjs`
 * refuses to publish an artifact that violates it, and `Dashboard.tsx` refuses
 * to render one. The browser treats the snapshot as untrusted input — a stale
 * cache, a hand-edited file, or a served artifact that predates the contract
 * all fail closed here instead of partially rendering.
 *
 * Counts and booleans only — never alert titles, file paths, CVEs, secret
 * material, or private vulnerability report bodies.
 */

/** Longest manifest `delta` string that may reach the published page. */
export const MAX_DELTA_LENGTH = 200;

/**
 * Longest workflow name that may reach the published page. The collector's
 * truncation imports this — one number, defined where it is enforced last, so
 * the truncation applied at collect time cannot drift from the cap the page
 * validates against.
 */
export const MAX_WORKFLOW_NAME_LENGTH = 128;

/** The only origin the published dashboard will ever emit a link to. */
export const ALLOWED_URL_ORIGIN = 'https://github.com';

/**
 * A URL reaches the snapshot only if it is `https:` at exactly
 * `https://github.com`. Everything else becomes `null`, and the UI renders
 * unlinked text.
 *
 * Validated where the value enters, rather than at render time. React escapes
 * text content but does not sanitize `href` schemes, so a `javascript:` URL in
 * an `href` is script execution on click. In practice these values come from
 * the GitHub API and are fine — but nothing enforced that, and the property
 * lived entirely in an upstream service's behaviour.
 *
 * Rejects embedded credentials: `https://user:pass@github.com` has an origin of
 * exactly `https://github.com`, so an origin check alone passes it through while
 * the rendered href still carries the credentials — a phishing shape.
 */
export function sanitizeGithubUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value === '') return null;

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== 'https:') return null;
  if (url.origin !== ALLOWED_URL_ORIGIN) return null;
  if (url.username || url.password) return null;

  // The parsed, normalized form — not the input string.
  return url.href;
}

/** Matches `isSnapshotStale` in src/lib/aggregate.ts, which imports it. */
export const STALE_MS = 24 * 60 * 60 * 1000;

/**
 * The Actions security pillars, in canonical order.
 *
 * This constant is the order — payload key order is never read. The renderer
 * iterates it (the `FloorBits` fixed-array pattern), the validator's shape is
 * derived from it, and the collector writes keys in the same order for diff
 * legibility only. A cached, hand-edited, or re-serialized artifact cannot
 * reorder the badges, and findings render in pillar order, never severity
 * order — a severity-ordered list is a ranking, and pillars do not get one.
 *
 * Phase 2 appends `injection` and `runners` here, nowhere else.
 */
export const PILLARS = ['pinning', 'permissions', 'triggers'] as const;

export type PillarName = (typeof PILLARS)[number];

/**
 * The closed reason vocabulary, per pillar, each code bound to the only
 * status it may accompany.
 *
 * Reason codes name the *class* of problem, never the instance: no workflow
 * file, job, line, or count travels in the artifact. The prose a reader sees
 * is a UI-owned literal keyed by these codes — nothing from the snapshot is
 * rendered as text. The severity binding is validated: a `warn` wearing a
 * fail-class code (or vice versa) is an artifact smuggling a claim the
 * detector did not make.
 */
export const PILLAR_REASONS: Record<PillarName, Record<string, 'warn' | 'fail'>> = {
  pinning: {
    'unpinned-third-party': 'fail',
    'unpinned-first-party': 'warn',
  },
  permissions: {
    'write-all': 'fail',
    'no-permissions-block': 'warn',
  },
  triggers: {
    'secrets-in-privileged-trigger': 'fail',
    'privileged-trigger-checkout': 'fail',
    'privileged-trigger': 'warn',
  },
};

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
  /**
   * One cap for the qualification family — check name, provider, model,
   * prompt version, fixture-suite id, level id. The longest real value today
   * is a `sha256:`-prefixed suite id at 23 characters; 80 bounds a hostile
   * artifact without ever truncating a legitimate one.
   */
  qualification: 80,
} as const;

/**
 * Bounds on the qualification subtree, defined here — where they are enforced
 * last — and imported by the collector, the `workflowName` pattern. A snapshot
 * exceeding them is refused whole rather than truncated: unlike a string cap,
 * a row cap that silently drops rows would present a partial history as the
 * whole one.
 */
export const MAX_QUALIFICATION_RUNS = 30;
export const MAX_RESULTS_PER_RUN = 20;
export const MAX_LEVELS_PER_RESULT = 8;
export const MAX_FIXTURES_PER_RESULT = 24;
export const MAX_CRITERIA_PER_FIXTURE = 8;

/**
 * How one fixture graded, verbatim from the ACA self-test contract: `ok` — the
 * judge matched the expectation; `miss` — it did not; `skipped` — a higher
 * level was never reached. Skipped is not graded and never counts either way.
 */
export const QUALIFICATION_FIXTURE_STATUSES = ['ok', 'miss', 'skipped'] as const;

/** The ACA verdict vocabulary — closed, because a verdict is a claim, not text. */
export const QUALIFICATION_VERDICTS = ['pass', 'fail', 'warn'] as const;

/**
 * The grammar for every judge- or artifact-controlled qualification token:
 * check names, prompt versions, fixture-suite ids (`sha256:…`), levels,
 * fixture names, assessments, criteria codes, providers, models.
 *
 * These fields cross a boundary the threat model treats as model-controlled,
 * and the generic text sanitizer (cap + control characters) still admits
 * prose, file paths, and short secret material. An identifier grammar — no
 * whitespace, no slashes, bounded — is what these values all are when the
 * suite is behaving, so anything outside it is refused rather than published.
 * Defined once here, imported by the collector: one definition at both ends
 * of the pipe.
 */
export const QUALIFICATION_IDENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;

/**
 * How one run's artifacts were resolved, bound to `results` the way a pillar
 * reason is bound to its status: `read` is the only state that may carry rows,
 * and both absence states must say which they are — `expired` is GitHub's
 * 30-day retention doing its documented job, `unreadable` is this run failing
 * to learn something it set out to learn. Collapsing them would let a failed
 * read wear retention's alibi.
 */
export const QUALIFICATION_ARTIFACT_STATES = ['read', 'expired', 'unreadable'] as const;

/** The graded-ladder vocabulary, verbatim from the ACA self-test contract. */
export const QUALIFICATION_LEVEL_STATUSES = ['passed', 'failed', 'skipped'] as const;

const STATUSES = new Set(['active', 'onboarding', 'retired']);

/** Written as escapes: a literal control byte in source is invisible in review. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/u;

type Ctx = { now: number; clockSkewMs: number; maxViolations: number };

/** Returns null when the value is acceptable, or a reason. */
type Rule = (value: unknown, ctx: Ctx) => string | null;

/** `null` marks a key handled explicitly outside the generic walk. */
type Shape = { [key: string]: Rule | Shape | null };

// --- leaf checks ---------------------------------------------------------

const isCount: Rule = (value) =>
  value === null || (Number.isInteger(value) && (value as number) >= 0)
    ? null
    : 'must be null or a non-negative integer';

const isFlag: Rule = (value) =>
  value === null || typeof value === 'boolean' ? null : 'must be null or a boolean';

const isCodeqlSetup: Rule = (value) => {
  if (value === null) return null;
  if (typeof value !== 'string') return 'must be null or a string';
  const valid = new Set(['default', 'advanced', 'none']);
  return valid.has(value) ? null : `must be one of ${[...valid].join(', ')}`;
};

const isBool: Rule = (value) => (typeof value === 'boolean' ? null : 'must be a boolean');

const PILLAR_STATUSES = new Set(['pass', 'warn', 'fail', 'none']);

/**
 * One pillar's `{ status, reason }`, checked as a unit because the pairing is
 * the contract: a reasonless `warn`/`fail` is unactionable, and a reasoned
 * `pass` is a key smuggling data. `none` and `null` carry no reason either —
 * absence and unknown explain themselves.
 *
 * The reason must come from this pillar's own closed vocabulary, and its bound
 * severity must equal the status it accompanies. Anything else is an artifact
 * asserting a claim the detector did not make, and it is refused whole.
 */
function isPillar(pillar: PillarName): Rule {
  return (value) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return 'must be an object';
    }
    for (const key of Object.keys(value)) {
      if (key !== 'status' && key !== 'reason') return 'has a key not in the published schema';
    }
    const { status, reason } = value as { status?: unknown; reason?: unknown };
    if (!Object.hasOwn(value, 'status')) return 'is missing status';
    if (!Object.hasOwn(value, 'reason')) return 'is missing reason';
    if (status !== null && !(typeof status === 'string' && PILLAR_STATUSES.has(status))) {
      return `status must be null or one of ${[...PILLAR_STATUSES].join(', ')}`;
    }
    if (status === 'warn' || status === 'fail') {
      if (typeof reason !== 'string') return 'reason must accompany a warn or fail status';
      const severity = PILLAR_REASONS[pillar][reason];
      if (severity === undefined) return 'reason is not in the published vocabulary';
      if (severity !== status) return 'reason does not match its status severity';
      return null;
    }
    if (reason !== null) return 'reason must be null unless status is warn or fail';
    return null;
  };
}

function isText(cap: number, { nullable = false } = {}): Rule {
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
 * A URL field is checked by the same `sanitizeGithubUrl` the collector applies
 * where the value enters the artifact — the one definition above, not a second
 * copy of the rule. Two definitions of "is this safe to put in an href" drift,
 * and the drift is invisible until one of them is wrong.
 */
const isUrl: Rule = (value) => {
  if (value === null) return null;
  if (sanitizeGithubUrl(value) !== value) {
    return `must be null or a normalized ${ALLOWED_URL_ORIGIN} URL`;
  }
  return null;
};

/**
 * Honest clock drift between GitHub's runners and whoever validates next.
 *
 * The default suits a validator running seconds after collection. A browser
 * validating on someone's laptop is a different clock: end-user machines drift
 * by minutes, and rejecting a genuinely fresh snapshot because the *reader's*
 * clock is behind would take the dashboard down for exactly the people it
 * cannot warn. Callers that far from the runner pass a wider skew.
 */
const CLOCK_SKEW_MS = 60_000;

/**
 * Every timestamp, not just `generatedAt`, is refused a future value. A future
 * `ci.updatedAt` reads as maximally current for as long as the skew lasts —
 * the same direction that suppresses the staleness warning, one field down.
 * `now` arrives through the rule context so there is exactly one clock per
 * validation, not a `Date.now()` in every rule that needs one.
 */
const isTimestamp: Rule = (value, { now, clockSkewMs }) => {
  if (value === null) return null;
  if (typeof value !== 'string') return 'must be a string';
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) return 'is not a parseable timestamp';
  if (ts > now + clockSkewMs) return 'is in the future';
  return null;
};

// --- the contract --------------------------------------------------------

const CI: Shape = {
  workflowName: isText(CAPS.workflowName, { nullable: true }),
  conclusion: isText(CAPS.conclusion, { nullable: true }),
  status: isText(CAPS.status, { nullable: true }),
  updatedAt: isTimestamp,
  htmlUrl: isUrl,
};

const SECURITY_FLOOR: Shape = {
  secretScanning: isFlag,
  pushProtection: isFlag,
  dependabotAlerts: isFlag,
  privateVulnerabilityReporting: isFlag,
  codeqlSetup: isCodeqlSetup,
  codeqlLastAnalysisAt: isTimestamp,
  defaultBranchRuleset: isFlag,
};

const SECURITY: Shape = {
  dependabotOpen: isCount,
  codeScanningOpen: isCount,
  secretScanningOpen: isCount,
};

/**
 * Derived from `PILLARS` so the shape cannot drift from the canonical order,
 * plus `workflowCount`. The cross-field rules — `none` requires a known-zero
 * count, and a known-zero count requires `none` everywhere — span sibling
 * keys, so they live in `checkActionsPosture` below rather than in the
 * generic walk.
 */
const ACTIONS_POSTURE: Shape = Object.fromEntries<Rule>([
  ['workflowCount', isCount] as [string, Rule],
  ...PILLARS.map((pillar): [string, Rule] => [pillar, isPillar(pillar)]),
]);

/**
 * The whole `actionsPosture` subtree: structure via the generic walk, then the
 * consistency the walk cannot see.
 *
 * `none` is repo-wide by construction — `workflowCount === 0` sets every
 * pillar to `none`, and a repo with workflows can never carry one. An artifact
 * violating that pairing is claiming an absence it also denies, in whichever
 * direction, and both directions are refused: `none` beside a non-zero (or
 * unknown) count dresses an unread pillar as owner-chosen absence, and a
 * zero count beside an assessed status claims findings about files it also
 * says do not exist.
 */
function checkActionsPosture(value: unknown, path: string, violations: string[], ctx: Ctx): void {
  checkShape(value, ACTIONS_POSTURE, path, violations, ctx);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return;

  const posture = value as Record<string, { status?: unknown } | null | undefined>;
  const workflowCount = (value as { workflowCount?: unknown }).workflowCount;
  for (const pillar of PILLARS) {
    const status = posture[pillar]?.status;
    if (status === 'none' && workflowCount !== 0) {
      report(violations, ctx, `${path}.${pillar} status 'none' requires workflowCount 0`);
    }
    if (workflowCount === 0 && status !== 'none' && status !== undefined) {
      report(violations, ctx, `${path}.${pillar} status must be 'none' when workflowCount is 0`);
    }
    // A null count means the listing itself failed, so nothing was assessed —
    // the collector can only emit all-null beside it. An artifact carrying an
    // assessed verdict next to an unknown count is claiming to have read
    // files it could not enumerate; refused whole rather than trusted in the
    // flattering direction.
    if (workflowCount === null && status !== null && status !== undefined) {
      report(violations, ctx, `${path}.${pillar} status must be null when workflowCount is null`);
    }
  }
}

/** A qualification token: the identifier grammar, or null where allowed. */
const isQualIdent = (nullable = true): Rule => (value) => {
  if (value === null) return nullable ? null : 'must not be null';
  if (typeof value !== 'string' || !QUALIFICATION_IDENT.test(value)) {
    return 'must match the qualification identifier grammar';
  }
  return null;
};

const VERDICTS = new Set<string>(QUALIFICATION_VERDICTS);

const isQualVerdict: Rule = (value) => {
  if (value === null) return null;
  return typeof value === 'string' && VERDICTS.has(value)
    ? null
    : `must be null or one of ${[...VERDICTS].join(', ')}`;
};

/** An abbreviated commit id, or null. Anything not hex is not a sha. */
const isQualSha: Rule = (value) => {
  if (value === null) return null;
  if (typeof value !== 'string' || !/^[0-9a-f]{7,12}$/.test(value)) {
    return 'must be null or 7-12 lowercase hex characters';
  }
  return null;
};

const isRunId: Rule = (value) =>
  Number.isInteger(value) && (value as number) > 0 ? null : 'must be a positive integer';

/** One check's verdict inside one run. Structured facts, never judge prose. */
const QUALIFICATION_RESULT: Shape = {
  check: isQualIdent(false),
  promptVersion: isQualIdent(),
  fixtureSuite: isQualIdent(),
  requiredLevel: isQualIdent(),
  achievedLevel: isQualIdent(),
  qualified: isBool,
  levels: null, // handled explicitly: a bounded array of { id, status }
  fixtures: null, // handled explicitly: a bounded array, or null when detail was refused
};

const FIXTURE_STATUSES = new Set<string>(QUALIFICATION_FIXTURE_STATUSES);

/**
 * One fixture's grading: what the exam expected, what the judge decided, and
 * the criteria codes it flagged. `expected` is always an object; `actual` is
 * null when the judged claim is unavailable — a skipped rung, or an artifact
 * that omitted the judged tokens; `status` is what says whether grading
 * happened. Names, vocabulary tokens, and bounded code lists only — the
 * judge's `note` prose has no key here, so a snapshot carrying one fails the
 * closed-key walk.
 */
const QUALIFICATION_FIXTURE: Shape = {
  name: isQualIdent(false),
  level: isQualIdent(),
  status: (value) =>
    typeof value === 'string' && FIXTURE_STATUSES.has(value)
      ? null
      : `must be one of ${[...FIXTURE_STATUSES].join(', ')}`,
  expected: {
    assessment: isQualIdent(),
    verdict: isQualVerdict,
  },
  actual: null, // handled explicitly: null or { assessment, verdict, criteria }
};

const QUALIFICATION_FIXTURE_ACTUAL: Shape = {
  assessment: isQualIdent(),
  verdict: isQualVerdict,
  criteria: null, // handled explicitly: a bounded array of codes
};

function checkFixtures(value: unknown, path: string, violations: string[], ctx: Ctx): void {
  // `null` is detail refused at collect time; `undefined` is a snapshot
  // published before the field existed (a cached artifact the browser still
  // validates). Both render as detail unavailable — the verdict stands alone.
  if (value === null || value === undefined) return;
  if (!Array.isArray(value) || value.length > MAX_FIXTURES_PER_RESULT) {
    report(violations, ctx, `${path} must be null or an array of at most ${MAX_FIXTURES_PER_RESULT}`);
    return;
  }
  for (const [index, fixture] of value.entries()) {
    if (full(violations, ctx)) return;
    const fixturePath = `${path}[${index}]`;
    checkShape(fixture, QUALIFICATION_FIXTURE, fixturePath, violations, ctx);
    if (fixture === null || typeof fixture !== 'object' || Array.isArray(fixture)) continue;
    const actual = (fixture as { actual?: unknown }).actual;
    if (actual === null) continue;
    checkShape(actual, QUALIFICATION_FIXTURE_ACTUAL, `${fixturePath}.actual`, violations, ctx);
    if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) continue;
    const criteria = (actual as { criteria?: unknown }).criteria;
    if (!Array.isArray(criteria) || criteria.length > MAX_CRITERIA_PER_FIXTURE) {
      report(
        violations,
        ctx,
        `${fixturePath}.actual.criteria must be an array of at most ${MAX_CRITERIA_PER_FIXTURE}`,
      );
      continue;
    }
    for (const [ci, code] of criteria.entries()) {
      const reason = isQualIdent(false)(code, ctx);
      if (reason) report(violations, ctx, `${fixturePath}.actual.criteria[${ci}] ${reason}`);
    }
  }
}

const QUALIFICATION_RUN: Shape = {
  runId: isRunId,
  url: isUrl,
  createdAt: (value, ctx) =>
    typeof value === 'string' ? isTimestamp(value, ctx) : 'must be a timestamp string',
  headSha: isQualSha,
  conclusion: isText(CAPS.conclusion, { nullable: true }),
  provider: isQualIdent(),
  model: isQualIdent(),
  artifacts: null, // handled explicitly: paired with results
  results: null, // handled explicitly: an array of QUALIFICATION_RESULT, or null
};

const ARTIFACT_STATES = new Set<string>(QUALIFICATION_ARTIFACT_STATES);
const LEVEL_STATUSES = new Set<string>(QUALIFICATION_LEVEL_STATUSES);

/**
 * The `qualifications` subtree: the ACA calibrate lane's route-qualification
 * history. Nullable at the top — the committed fixture states `null` because
 * the fallback cannot know the matrix — and closed everywhere below, the same
 * posture as every other subtree.
 *
 * The pairing rule is the load-bearing part: `results` is an array iff
 * `artifacts` is `'read'`, and `null` under both absence states. An artifact
 * state claiming rows it also says it could not read — or rows beside a state
 * disclaiming them — is refused whole.
 */
function checkQualifications(value: unknown, path: string, violations: string[], ctx: Ctx): void {
  if (value === null) return;
  checkShape(
    value,
    { source: { repo: isText(CAPS.manifestRepo), workflow: isText(CAPS.manifestPath) }, runs: null },
    path,
    violations,
    ctx,
  );
  const runs = (value as { runs?: unknown } | null)?.runs;
  if (!Array.isArray(runs)) {
    report(violations, ctx, `${path}.runs must be an array`);
    return;
  }
  if (runs.length > MAX_QUALIFICATION_RUNS) {
    report(violations, ctx, `${path}.runs exceeds the ${MAX_QUALIFICATION_RUNS}-run bound`);
    return;
  }
  for (const [index, run] of runs.entries()) {
    if (full(violations, ctx)) return;
    const runPath = `${path}.runs[${index}]`;
    checkShape(run, QUALIFICATION_RUN, runPath, violations, ctx);
    if (run === null || typeof run !== 'object' || Array.isArray(run)) continue;

    const { artifacts, results } = run as { artifacts?: unknown; results?: unknown };
    if (typeof artifacts !== 'string' || !ARTIFACT_STATES.has(artifacts)) {
      report(violations, ctx, `${runPath}.artifacts must be one of ${[...ARTIFACT_STATES].join(', ')}`);
      continue;
    }
    if (artifacts !== 'read') {
      if (results !== null) report(violations, ctx, `${runPath}.results must be null unless artifacts is 'read'`);
      continue;
    }
    if (!Array.isArray(results) || results.length === 0) {
      report(violations, ctx, `${runPath}.results must be a non-empty array when artifacts is 'read'`);
      continue;
    }
    if (results.length > MAX_RESULTS_PER_RUN) {
      report(violations, ctx, `${runPath}.results exceeds the ${MAX_RESULTS_PER_RUN}-result bound`);
      continue;
    }
    for (const [ri, result] of results.entries()) {
      if (full(violations, ctx)) return;
      const resultPath = `${runPath}.results[${ri}]`;
      checkShape(result, QUALIFICATION_RESULT, resultPath, violations, ctx);
      checkFixtures(
        (result as { fixtures?: unknown } | null)?.fixtures,
        `${resultPath}.fixtures`,
        violations,
        ctx,
      );
      const levels = (result as { levels?: unknown } | null)?.levels;
      if (!Array.isArray(levels) || levels.length > MAX_LEVELS_PER_RESULT) {
        report(violations, ctx, `${resultPath}.levels must be an array of at most ${MAX_LEVELS_PER_RESULT}`);
        continue;
      }
      for (const [li, level] of levels.entries()) {
        checkShape(
          level,
          {
            id: isQualIdent(false),
            status: (v) =>
              typeof v === 'string' && LEVEL_STATUSES.has(v)
                ? null
                : `must be one of ${[...LEVEL_STATUSES].join(', ')}`,
          },
          `${resultPath}.levels[${li}]`,
          violations,
          ctx,
        );
      }
    }
  }
}

const REPO: Shape = {
  name: isText(CAPS.name),
  // Only `public` may be published at all. The field is retained so a stale or
  // hand-edited snapshot can still be filtered at render time, but a snapshot
  // that ships anything else has already failed the publication gate.
  visibility: (value) => (value === 'public' ? null : "must be exactly 'public' to be published"),
  status: (value) => (STATUSES.has(value as string) ? null : `must be one of ${[...STATUSES].join(', ')}`),
  sharedCi: isBool,
  codexSyncEnabled: isFlag,
  delta: isText(CAPS.delta),
  htmlUrl: isUrl,
  securityFloor: SECURITY_FLOOR,
  security: SECURITY,
  ci: CI,
  actionsPosture: null, // handled explicitly: cross-field rules the walk cannot see
};

export const SNAPSHOT: Shape = {
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
    denied: (value) => (Number.isInteger(value) && (value as number) >= 0 ? null : 'must be a count'),
    rateLimited: (value) => (Number.isInteger(value) && (value as number) >= 0 ? null : 'must be a count'),
    failed: (value) => (Number.isInteger(value) && (value as number) >= 0 ? null : 'must be a count'),
  },
  repos: null, // handled explicitly: an array of REPO
  qualifications: null, // handled explicitly: nullable subtree with pairing rules
};

// --- walking -------------------------------------------------------------

/**
 * Records a violation unless the cap is already reached. Nothing is
 * constructed or stored past the cap, so a hostile artifact — say, a hundred
 * thousand empty repo objects, each missing every field — costs the capped
 * caller a bounded amount of memory instead of a string per defect.
 */
function report(violations: string[], ctx: Ctx, message: string): void {
  if (violations.length < ctx.maxViolations) violations.push(message);
}

function full(violations: string[], ctx: Ctx): boolean {
  return violations.length >= ctx.maxViolations;
}

function checkShape(value: unknown, shape: Shape, path: string, violations: string[], ctx: Ctx): void {
  if (full(violations, ctx)) return;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    report(violations, ctx, `${path} must be an object`);
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
    if (full(violations, ctx)) return;
    if (!Object.hasOwn(shape, key)) report(violations, ctx, `${path}.${key} is not in the published schema`);
  }

  for (const [key, rule] of Object.entries(shape)) {
    if (full(violations, ctx)) return;
    if (rule === null) continue;
    if (!Object.hasOwn(value, key)) {
      report(violations, ctx, `${path}.${key} is missing`);
      continue;
    }
    const field = (value as Record<string, unknown>)[key];
    if (typeof rule === 'function') {
      const reason = rule(field, ctx);
      if (reason) report(violations, ctx, `${path}.${key} ${reason}`);
    } else {
      checkShape(field, rule, `${path}.${key}`, violations, ctx);
    }
  }
}

export type ValidateOptions = {
  now?: number;
  requireFresh?: boolean;
  /** See `CLOCK_SKEW_MS`: browsers pass a wider allowance than CI validators. */
  clockSkewMs?: number;
  /**
   * Stop recording past this many violations. The default reports everything,
   * which is right for a CI validator describing a trusted collector's output
   * — a snapshot that gained three fields should say so once, not across three
   * runs an hour apart. A browser validating a fetched artifact only needs to
   * know *whether* it conforms, and materializing a violation per defect of a
   * hostile payload is an allocation the reader's tab pays for.
   */
  maxViolations?: number;
};

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
export function validateSnapshot(
  snapshot: unknown,
  {
    now = Date.now(),
    requireFresh = false,
    clockSkewMs = CLOCK_SKEW_MS,
    maxViolations = Infinity,
  }: ValidateOptions = {},
): string[] {
  const violations: string[] = [];
  // One clock for the whole validation. The future check lives in
  // `isTimestamp` — every timestamp field gets it through this context —
  // so this function only owns the check that needs the flag: staleness.
  const ctx: Ctx = { now, clockSkewMs, maxViolations };
  checkShape(snapshot, SNAPSHOT, 'snapshot', violations, ctx);

  const snap = snapshot as { repos?: unknown; generatedAt?: unknown } | null | undefined;

  if (!Array.isArray(snap?.repos)) {
    report(violations, ctx, 'snapshot.repos must be an array');
  } else {
    for (const [index, repo] of snap.repos.entries()) {
      if (full(violations, ctx)) break;
      checkShape(repo, REPO, `snapshot.repos[${index}]`, violations, ctx);
      // Marked `null` in REPO, so the walk neither requires nor descends it —
      // presence and everything below it are this call's job.
      checkActionsPosture(
        (repo as { actionsPosture?: unknown } | null)?.actionsPosture,
        `snapshot.repos[${index}].actionsPosture`,
        violations,
        ctx,
      );
    }

    const names = snap.repos.map((repo: unknown) => (repo as { name?: unknown } | null)?.name);
    if (new Set(names).size !== names.length) {
      report(violations, ctx, 'snapshot.repos contains duplicate names');
    }
  }

  // Marked `null` in SNAPSHOT: nullable at the top, pairing rules below.
  if (snapshot !== null && typeof snapshot === 'object' && !Array.isArray(snapshot)) {
    if (!Object.hasOwn(snapshot, 'qualifications')) {
      report(violations, ctx, 'snapshot.qualifications is missing');
    } else {
      checkQualifications(
        (snapshot as { qualifications?: unknown }).qualifications,
        'snapshot.qualifications',
        violations,
        ctx,
      );
    }
  }

  const ts = typeof snap?.generatedAt === 'string' ? Date.parse(snap.generatedAt) : NaN;
  if (Number.isFinite(ts) && requireFresh && now - ts > STALE_MS) {
    report(violations, ctx, 'snapshot.generatedAt is older than the staleness threshold');
  }

  return violations;
}
