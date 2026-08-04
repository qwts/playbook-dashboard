/**
 * Static assessment of one repo's workflow files into Actions security pillars.
 *
 * Pure functions over file text — no network, no filesystem, nothing executes.
 * The collector fetches the bytes (post-visibility-gate, read-only token) and
 * hands them here; what leaves is `{ status, reason }` per pillar, statuses in
 * `pass | warn | fail | null`, reasons from the closed vocabulary in
 * `src/lib/snapshot-schema.ts`. `'none'` (no workflows at all) is decided by
 * the collector from the directory listing, never here.
 *
 * Everything parsed is untrusted input from governed repos. A file that will
 * not parse as YAML makes every pillar unknown for that file — corruption
 * must make the run louder, never quieter — and nothing from the file's
 * content (names, paths, values) survives into a return value or a throw:
 * these results cross into a public artifact and public Actions logs.
 *
 * Honest limits, stated once: only default-branch workflow files are seen —
 * not org-level required workflows, not composite actions' own `uses:`, not
 * reusable workflows' bodies. `if:` gates are not evaluated, so a label-gated
 * privileged checkout still flags (a gate is one typo from useless). A
 * combined verdict follows `fail > warn > null > pass`: unknown poisons a
 * pass claim but cannot hide a fail already found, and a partial read may
 * prove presence while only a complete read may claim cleanliness.
 */

import { parse } from 'yaml';
import { PILLARS, PILLAR_REASONS } from '../src/lib/snapshot-schema.ts';

/** More files than this and the assessment is incomplete — never a pass claimed from a subset. */
export const MAX_WORKFLOW_FILES = 30;
/** A workflow file larger than this is skipped and the assessment marked incomplete. */
export const MAX_WORKFLOW_FILE_BYTES = 512 * 1024;

/**
 * Owners whose unpinned actions downgrade to `warn` rather than `fail`.
 * First-party compromise requires compromising the org or GitHub itself —
 * a different blast radius than a third-party tag owner re-pointing a tag.
 */
export const FIRST_PARTY_OWNERS = new Set(['qwts', 'actions', 'github']);

/**
 * Expression contexts that carry an untrusted head ref into a checkout.
 * Matched as substrings of a checkout step's `ref:` — the closed list keeps
 * false positives explainable; anything cleverer belongs to CodeQL (phase 2).
 */
const UNTRUSTED_HEAD_CONTEXTS = [
  'github.event.pull_request.head',
  'github.head_ref',
  'github.event.workflow_run.head',
];

/** Triggers that run with base-repo secrets and a write-capable token on stranger-caused events. */
const PRIVILEGED_TRIGGERS = new Set(['pull_request_target', 'workflow_run']);

const rank = { fail: 3, warn: 2, null: 1, pass: 0 };

/**
 * Worst-of with unknown poisoning pass: `fail > warn > null > pass`.
 * `null` (unknown) outranks `pass` because an unread file cannot vouch for
 * cleanliness; it does not outrank `warn`/`fail` because a defect already
 * found stands whatever else went unread.
 */
export function combineStatuses(statuses) {
  let worst = 'pass';
  for (const status of statuses) {
    const key = status === null ? 'null' : status;
    if (!(key in rank)) return null; // corrupt input is unknown, never clean
    if (rank[key] > rank[worst === null ? 'null' : worst]) worst = status;
  }
  return worst;
}

/**
 * The single reason accompanying a combined `warn`/`fail`: the first code in
 * the pillar's own vocabulary order whose bound severity matches the combined
 * status and which some file actually produced. Vocabulary order, not
 * encounter order, so the same defects always publish the same code.
 */
function combineReasons(pillar, status, reasons) {
  if (status !== 'warn' && status !== 'fail') return null;
  const seen = new Set(reasons.filter((reason) => reason !== null));
  for (const [code, severity] of Object.entries(PILLAR_REASONS[pillar])) {
    if (severity === status && seen.has(code)) return code;
  }
  // A warn/fail with no matching reason cannot be published — the schema
  // refuses the pairing — so an inconsistency here degrades to unknown.
  return null;
}

/** Every `uses:` reference in the workflow: job-level (reusable) and step-level. */
function usesRefs(doc) {
  const refs = [];
  const jobs = doc?.jobs && typeof doc.jobs === 'object' ? Object.values(doc.jobs) : [];
  for (const job of jobs) {
    if (typeof job?.uses === 'string') refs.push(job.uses);
    const steps = Array.isArray(job?.steps) ? job.steps : [];
    for (const step of steps) {
      if (typeof step?.uses === 'string') refs.push(step.uses);
    }
  }
  return refs;
}

/**
 * P1 — every `uses:` pinned to a full-length commit SHA.
 *
 * Local references (`./…`) have no ref to pin and are exempt. Docker
 * references pin by digest. A 40-hex tag name would false-positive as pinned;
 * accepted, stated. A SHA pointing at malicious code is out of scope — pinning
 * is provenance of the ref, not review of the target.
 */
export function assessPinning(doc) {
  let unpinnedFirstParty = false;
  for (const ref of usesRefs(doc)) {
    if (ref.startsWith('./')) continue;
    if (ref.startsWith('docker://')) {
      if (!ref.includes('@sha256:')) return { status: 'fail', reason: 'unpinned-third-party' };
      continue;
    }
    const at = ref.lastIndexOf('@');
    const pinned = at !== -1 && /^[0-9a-f]{40}$/.test(ref.slice(at + 1));
    if (pinned) continue;
    const owner = ref.slice(0, ref.indexOf('/') === -1 ? ref.length : ref.indexOf('/'));
    if (FIRST_PARTY_OWNERS.has(owner)) unpinnedFirstParty = true;
    else return { status: 'fail', reason: 'unpinned-third-party' };
  }
  if (unpinnedFirstParty) return { status: 'warn', reason: 'unpinned-first-party' };
  return { status: 'pass', reason: null };
}

/**
 * P2 — an explicit `permissions:` block at workflow level or on every job,
 * and no `write-all` anywhere.
 *
 * Absent block = the default token grant, a repo/org setting the workflow's
 * author did not choose — `warn`, not `fail`, because the repo default may
 * itself be read-only (phase 1 does not read that setting; D7 defers it).
 * An explicit block that is broader than the job needs is a false negative:
 * necessity is not statically decidable.
 */
export function assessPermissions(doc) {
  const jobs = doc?.jobs && typeof doc.jobs === 'object' ? Object.values(doc.jobs) : [];
  const grants = [doc?.permissions, ...jobs.map((job) => job?.permissions)];
  if (grants.some((grant) => grant === 'write-all')) {
    return { status: 'fail', reason: 'write-all' };
  }
  const workflowLevel = doc !== null && typeof doc === 'object' && Object.hasOwn(doc, 'permissions');
  const everyJob = jobs.length > 0 && jobs.every((job) => job && typeof job === 'object' && Object.hasOwn(job, 'permissions'));
  if (!workflowLevel && !everyJob) {
    return { status: 'warn', reason: 'no-permissions-block' };
  }
  return { status: 'pass', reason: null };
}

/** `on:` in all three YAML spellings, plus the boolean-key defence for YAML 1.1 parsers. */
function triggerNames(doc) {
  const on = doc?.on ?? doc?.[true];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.filter((name) => typeof name === 'string');
  if (on && typeof on === 'object') return Object.keys(on);
  return [];
}

/**
 * P3 — privileged triggers (`pull_request_target`, `workflow_run`) paired with
 * untrusted code or secrets.
 *
 * Severity ladder, matching the published copy exactly:
 * - tainted checkout + `secrets.` referenced → `secrets-in-privileged-trigger`
 *   (secrets exposed *to untrusted code* — the copy's claim, so both must hold)
 * - tainted checkout alone → `privileged-trigger-checkout`
 * - the trigger present, nothing tainted found → `privileged-trigger` (warn):
 *   trusted base code using secrets under these triggers is the intended
 *   pattern, not a finding.
 *
 * The secrets scan is file-level, not job-reachability — a `push`-path secret
 * in a mixed-trigger file flags too. Accepted: reachability needs `if:`/needs
 * analysis this phase does not attempt, and the false positive errs loud.
 */
export function assessTriggers(doc, text) {
  const privileged = triggerNames(doc).filter((name) => PRIVILEGED_TRIGGERS.has(name));
  if (privileged.length === 0) return { status: 'pass', reason: null };

  let taintedCheckout = false;
  const jobs = doc?.jobs && typeof doc.jobs === 'object' ? Object.values(doc.jobs) : [];
  for (const job of jobs) {
    const steps = Array.isArray(job?.steps) ? job.steps : [];
    for (const step of steps) {
      if (typeof step?.uses !== 'string' || !/^actions\/checkout(?:[@/]|$)/.test(step.uses)) continue;
      const ref = step?.with?.ref;
      if (typeof ref !== 'string') continue;
      if (UNTRUSTED_HEAD_CONTEXTS.some((context) => ref.includes(context))) taintedCheckout = true;
    }
  }

  if (taintedCheckout) {
    const secretsReferenced = /\$\{\{[^}]*\bsecrets\s*\./.test(text);
    if (secretsReferenced) return { status: 'fail', reason: 'secrets-in-privileged-trigger' };
    return { status: 'fail', reason: 'privileged-trigger-checkout' };
  }
  return { status: 'warn', reason: 'privileged-trigger' };
}

/**
 * One file, all pillars. `null` when the file does not parse as a YAML
 * mapping — unknown for every pillar, because a file the parser cannot read
 * is exactly the file a reviewer cannot vouch for.
 */
export function assessWorkflowFile(text) {
  if (typeof text !== 'string') return null;
  let doc;
  try {
    doc = parse(text);
  } catch {
    return null;
  }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return null;
  return {
    pinning: assessPinning(doc),
    permissions: assessPermissions(doc),
    triggers: assessTriggers(doc, text),
  };
}

/**
 * All fetched files → one verdict per pillar.
 *
 * `complete: false` means some file was not read — over the caps, fetch
 * failed, or truncated — so no pillar may claim `pass`: a pass degrades to
 * `null`, while a `warn`/`fail` found in what *was* read stands. A partial
 * read can prove presence; only a complete read can claim cleanliness.
 */
export function assessWorkflows(texts, { complete = true } = {}) {
  const perFile = texts.map((text) => assessWorkflowFile(text));

  const posture = {};
  for (const pillar of PILLARS) {
    const statuses = perFile.map((file) => (file === null ? null : file[pillar].status));
    if (!complete) statuses.push(null);
    const status = combineStatuses(statuses);
    const reason = combineReasons(
      pillar,
      status,
      perFile.map((file) => (file === null ? null : file[pillar].reason)),
    );
    // A warn/fail whose reason could not be reconciled cannot be published —
    // the schema refuses the pairing — so it degrades to unknown, the loud
    // direction.
    posture[pillar] =
      (status === 'warn' || status === 'fail') && reason === null
        ? { status: null, reason: null }
        : { status, reason };
  }
  return posture;
}
