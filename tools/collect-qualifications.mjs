/**
 * Judge-qualification collection — the ACA calibrate lane, read only.
 *
 * `qwts/agentic-code-analysis` gates CI on LLM judge verdicts, and a
 * qualification (its ACA-0012) is a tuple: check + prompt version + fixture
 * suite + provider + model. Each `calibrate.yml` dispatch uploads one
 * `qualification-<check>` artifact per selected check containing the
 * `--self-test --json` output. Those artifacts expire after 30 days, and until
 * this module existed the only record of which routes are qualified — and of
 * when an exam change invalidated one — was raw run logs.
 *
 * Everything read here is public (public repo, public Actions runs), but the
 * redaction contract applies unchanged: publication is a decision made in the
 * schema, not inherited from the source being public. Structured fields and
 * closed vocabularies only — the artifact's judge-written fixture notes are
 * prose and never reach the snapshot.
 *
 * Fail-closed is per section, not per run: any failure to list, download, or
 * parse collapses to `null` (the whole section) or `artifacts: 'unreadable'`
 * (one run). A null section is loud in the collect log and renders on the
 * page as unknown — deliberately not a `degradedReasons` entry, because the
 * committed fallback fixture must state null without reading as degraded. A
 * snapshot may state what this run read; it may not present a failed read as
 * an empty but healthy matrix.
 */

import { inflateRawSync } from 'node:zlib';
import {
  CAPS,
  MAX_CRITERIA_PER_FIXTURE,
  MAX_FIXTURES_PER_RESULT,
  MAX_LEVELS_PER_RESULT,
  MAX_QUALIFICATION_RUNS,
  MAX_RESULTS_PER_RUN,
  QUALIFICATION_FIXTURE_STATUSES,
  sanitizeGithubUrl,
} from '../src/lib/snapshot-schema.ts';

// The bounds live in the schema — where they are enforced last — and are
// re-exported here so the tests exercise collector and contract against the
// same numbers.
export {
  MAX_CRITERIA_PER_FIXTURE,
  MAX_FIXTURES_PER_RESULT,
  MAX_LEVELS_PER_RESULT,
  MAX_QUALIFICATION_RUNS,
  MAX_RESULTS_PER_RUN,
};

/** Where qualifications come from — the only repo and workflow ever read. */
export const QUALIFICATIONS_SOURCE = Object.freeze({
  repo: 'qwts/agentic-code-analysis',
  workflow: 'calibrate.yml',
});
/**
 * Per-entry byte bound, compressed and uncompressed. A real artifact is ~1 KB
 * of JSON; the bound exists because the zip crosses a trust boundary and an
 * inflate bomb costs the collector's memory, not the reader's.
 */
export const MAX_ARTIFACT_BYTES = 512 * 1024;
/** Entries examined per artifact zip. */
export const MAX_ZIP_ENTRIES = 20;

/** Written as escapes: a literal control byte in source is invisible in review. */
const CONTROL_CHARS = new RegExp('[\\u0000-\\u001F\\u007F]', 'u');

/**
 * The one shape a qualification string may take on the page: capped, no
 * control characters, else `null`. Nothing from an artifact is published
 * verbatim without passing through here.
 */
export function qualText(value) {
  if (typeof value !== 'string' || value === '') return null;
  if (value.length > CAPS.qualification) return null;
  if (CONTROL_CHARS.test(value)) return null;
  return value;
}

/** A commit id, abbreviated. Anything not hex is not a sha and becomes null. */
export function qualSha(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{7,40}$/.test(value)) return null;
  return value.slice(0, 12);
}

/**
 * Minimal read-only zip extraction: central directory walk, stored and
 * deflated entries only. Node has no built-in zip reader and a dependency is
 * a heavier trust decision than sixty lines — this parses exactly the subset
 * `actions/upload-artifact` produces and refuses everything else.
 *
 * Bounds are enforced before allocation: entry counts, compressed and
 * declared-uncompressed sizes, and the inflated result is re-checked because
 * the declared size is the attacker's claim, not a measurement.
 *
 * Returns a Map of entry name → Buffer, or null when the buffer is not a zip
 * this parser is willing to read. Never throws.
 */
export function unzip(buffer) {
  try {
    if (!Buffer.isBuffer(buffer) || buffer.length < 22) return null;
    // End-of-central-directory: scan back past a possible comment.
    let eocd = -1;
    const scanFloor = Math.max(0, buffer.length - 22 - 0xffff);
    for (let i = buffer.length - 22; i >= scanFloor; i -= 1) {
      if (buffer.readUInt32LE(i) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;
    const entryCount = buffer.readUInt16LE(eocd + 10);
    const cdOffset = buffer.readUInt32LE(eocd + 16);
    if (entryCount > MAX_ZIP_ENTRIES) return null;

    const entries = new Map();
    let offset = cdOffset;
    for (let i = 0; i < entryCount; i += 1) {
      if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) return null;
      const method = buffer.readUInt16LE(offset + 10);
      const compressedSize = buffer.readUInt32LE(offset + 20);
      const declaredSize = buffer.readUInt32LE(offset + 24);
      const nameLength = buffer.readUInt16LE(offset + 28);
      const extraLength = buffer.readUInt16LE(offset + 30);
      const commentLength = buffer.readUInt16LE(offset + 32);
      const localOffset = buffer.readUInt32LE(offset + 42);
      const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);
      offset += 46 + nameLength + extraLength + commentLength;

      if (compressedSize > MAX_ARTIFACT_BYTES || declaredSize > MAX_ARTIFACT_BYTES) return null;
      if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) return null;
      const localName = buffer.readUInt16LE(localOffset + 26);
      const localExtra = buffer.readUInt16LE(localOffset + 28);
      const dataStart = localOffset + 30 + localName + localExtra;
      if (dataStart + compressedSize > buffer.length) return null;
      const raw = buffer.subarray(dataStart, dataStart + compressedSize);

      let data;
      if (method === 0) {
        data = raw;
      } else if (method === 8) {
        data = inflateRawSync(raw, { maxOutputLength: MAX_ARTIFACT_BYTES });
      } else {
        return null;
      }
      if (data.length > MAX_ARTIFACT_BYTES) return null;
      entries.set(name, data);
    }
    return entries;
  } catch {
    return null;
  }
}

const LEVEL_STATUSES = new Set(['passed', 'failed', 'skipped']);
const FIXTURE_STATUSES = new Set(QUALIFICATION_FIXTURE_STATUSES);

/**
 * The per-fixture grading, or null when any entry is malformed or over-bound —
 * the detail is refused whole rather than published as a partial ladder, while
 * the result's verdict stands on its own. The judge's `note` prose is the one
 * field deliberately never read.
 */
export function parseFixtures(raw) {
  if (raw === undefined) return null;
  if (!Array.isArray(raw) || raw.length > MAX_FIXTURES_PER_RESULT) return null;
  const fixtures = [];
  for (const entry of raw) {
    const name = qualText(entry?.name);
    const status = FIXTURE_STATUSES.has(entry?.status) ? entry.status : null;
    if (name === null || status === null) return null;
    let actual = null;
    if (entry.actual !== undefined && entry.actual !== null) {
      const rawCriteria = Array.isArray(entry.actual.criteria) ? entry.actual.criteria : [];
      if (rawCriteria.length > MAX_CRITERIA_PER_FIXTURE) return null;
      const criteria = rawCriteria.map((code) => qualText(code));
      if (criteria.some((code) => code === null)) return null;
      actual = {
        assessment: qualText(entry.actual.assessment),
        verdict: qualText(entry.actual.verdict),
        criteria,
      };
    }
    fixtures.push({
      name,
      level: qualText(entry.level),
      status,
      expected: {
        assessment: qualText(entry.expected?.assessment),
        verdict: qualText(entry.expected?.verdict),
      },
      actual,
    });
  }
  return fixtures;
}

/**
 * One `--self-test --json` payload → one published result row, or null when
 * the payload does not carry a recognizable verdict.
 *
 * Structured facts only. `levels` is the graded ladder with a closed status
 * vocabulary; per-fixture detail — and above all the judge's free-text notes —
 * stays in the artifact. A check without a graded manifest reports bare
 * pass/fail (`requiredLevel: null`), which the page must render as ungraded
 * rather than reading absence as level-zero.
 */
export function parseSelfTest(raw) {
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return null;
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null;

  const check = qualText(body.check);
  if (check === null) return null;

  // The verdict must be an actual boolean. Defaulting a missing or malformed
  // verdict to `false` would publish a failed qualification for a payload
  // that carried no verdict at all — a claim the artifact never made.
  const graded = Object.hasOwn(body, 'qualified');
  const verdict = graded ? body.qualified : body.passed;
  if (typeof verdict !== 'boolean') return null;
  const qualified = verdict;

  const levels = [];
  if (Array.isArray(body.levels)) {
    for (const level of body.levels.slice(0, MAX_LEVELS_PER_RESULT)) {
      const id = qualText(level?.id);
      const status = LEVEL_STATUSES.has(level?.status) ? level.status : null;
      if (id === null || status === null) return null;
      levels.push({ id, status });
    }
  }

  return {
    check,
    provider: qualText(body.provider),
    model: qualText(body.model),
    promptVersion: qualText(body.promptVersion),
    fixtureSuite: qualText(body.fixtureSuite),
    requiredLevel: graded ? qualText(body.requiredLevel) : null,
    achievedLevel: graded ? qualText(body.achievedLevel) : null,
    qualified,
    levels,
    fixtures: parseFixtures(body.fixtures),
  };
}

/**
 * The dispatch run-name is `calibrate <provider>/<model> (<checks>)`. For a
 * run whose artifacts survive, route comes from the artifact JSON; this parse
 * exists so an *expired* run still states which route it examined. Anything
 * not matching the shape is null, never a guess.
 */
export function routeFromTitle(title) {
  const match = typeof title === 'string' ? /^calibrate (\S+)\/(\S+)/.exec(title) : null;
  return { provider: qualText(match?.[1]), model: qualText(match?.[2]) };
}

/**
 * Collect the qualification section, or null when it cannot be stated.
 *
 * `ghJson` and `gh` arrive injected from the main collector so this module
 * owns no token and no retry policy of its own — and so tests hand it fakes.
 * `ghJson` throws on non-OK responses; here that means this section (never
 * the whole snapshot) fails closed.
 */
export async function collectQualifications({ ghJson, gh, warn = () => {} }) {
  try {
    const listing = await ghJson(
      `/repos/${QUALIFICATIONS_SOURCE.repo}/actions/workflows/${QUALIFICATIONS_SOURCE.workflow}/runs` +
        `?status=completed&per_page=${MAX_QUALIFICATION_RUNS}`,
      { label: 'qualification run listing' },
    );
    const workflowRuns = listing?.workflow_runs;
    if (!Array.isArray(workflowRuns)) return null;

    const runs = [];
    let unreadableRuns = 0;
    for (const run of workflowRuns.slice(0, MAX_QUALIFICATION_RUNS)) {
      const runId = Number.isInteger(run?.id) && run.id > 0 ? run.id : null;
      if (runId === null) {
        unreadableRuns += 1;
        continue;
      }
      const row = await collectRun({ ghJson, gh, run, runId });
      if (row === null) unreadableRuns += 1;
      else runs.push(row);
    }
    if (unreadableRuns > 0) warn(`qualifications: ${unreadableRuns} runs could not be read`);

    return { source: { ...QUALIFICATIONS_SOURCE }, runs };
  } catch {
    // The label-only message from ghJson is safe to log, but the aggregate
    // rule is simpler to keep than an allowlist of safe messages.
    warn('qualifications: collection failed — published as null');
    return null;
  }
}

async function collectRun({ ghJson, gh, run, runId }) {
  const title = routeFromTitle(run.display_title);
  const base = {
    runId,
    url: sanitizeGithubUrl(run.html_url),
    createdAt: typeof run.created_at === 'string' ? run.created_at : null,
    headSha: qualSha(run.head_sha),
    conclusion: qualText(run.conclusion),
    provider: title.provider,
    model: title.model,
  };
  if (base.createdAt === null) return null;

  let artifacts;
  try {
    const listing = await ghJson(`/repos/${QUALIFICATIONS_SOURCE.repo}/actions/runs/${runId}/artifacts?per_page=50`, {
      label: 'qualification artifact listing',
    });
    artifacts = Array.isArray(listing?.artifacts) ? listing.artifacts : null;
  } catch {
    artifacts = null;
  }
  if (artifacts === null) return { ...base, artifacts: 'unreadable', results: null };

  const relevant = artifacts.filter((a) => typeof a?.name === 'string' && a.name.startsWith('qualification-'));
  if (relevant.length === 0) return { ...base, artifacts: 'unreadable', results: null };
  if (relevant.every((a) => a.expired === true)) return { ...base, artifacts: 'expired', results: null };

  // An exam larger than the bound is refused whole, not published as a
  // prefix: a truncated result list under `artifacts: 'read'` would present a
  // partial exam as a complete one, silently — the exact shape of claim the
  // pairing rule exists to prevent.
  if (relevant.length > MAX_RESULTS_PER_RUN) return { ...base, artifacts: 'unreadable', results: null };

  const results = [];
  for (const artifact of relevant) {
    if (artifact.expired === true || !Number.isInteger(artifact.id)) continue;
    const response = await gh(`/repos/${QUALIFICATIONS_SOURCE.repo}/actions/artifacts/${artifact.id}/zip`);
    if (!response.ok) return { ...base, artifacts: 'unreadable', results: null };
    const entries = unzip(Buffer.from(await response.arrayBuffer()));
    if (entries === null) return { ...base, artifacts: 'unreadable', results: null };
    for (const [name, data] of entries) {
      if (!name.endsWith('.json')) continue;
      const result = parseSelfTest(data.toString('utf8'));
      // The artifact's own route is the measurement; the title parse is the
      // fallback for runs whose artifacts are gone.
      if (result !== null) results.push(result);
    }
  }
  if (results.length === 0) return { ...base, artifacts: 'unreadable', results: null };
  if (results.length > MAX_RESULTS_PER_RUN) return { ...base, artifacts: 'unreadable', results: null };

  const routed = {
    ...base,
    provider: results[0].provider ?? base.provider,
    model: results[0].model ?? base.model,
    artifacts: 'read',
    results: results.map(({ provider: _p, model: _m, ...rest }) => rest),
  };
  return routed;
}
