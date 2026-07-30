#!/usr/bin/env node

/**
 * Build a redacted fleet snapshot for the public dashboard.
 *
 * Publishes counts and boolean posture only — never alert titles, paths,
 * CVEs, secret material, or private vulnerability report bodies.
 *
 * That rule is enforced, not just stated: `tools/snapshot-schema.mjs` is the
 * executable contract, and `npm run validate` refuses to publish an artifact
 * that violates it. Adding a field here without adding it there fails the run —
 * deliberately, because a comment cannot fail a build and the published surface
 * was otherwise free to grow silently on the next hourly cron.
 *
 * Publication is opt-in and double-gated (see DESIGN.md): a repo is collected
 * only if the manifest sets `publish: true`, and it is emitted only if GitHub
 * reports it as public at collection time. A repo that fails either gate
 * contributes nothing but an increment to `withheld`.
 *
 * Auth: GITHUB_TOKEN or GH_TOKEN (fine-grained: Contents read on playbook,
 * Metadata + Security events / Dependabot alerts / Actions on governed repos).
 */

import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED_URL_ORIGIN,
  MAX_DELTA_LENGTH,
  MAX_WORKFLOW_NAME_LENGTH,
  sanitizeGithubUrl,
} from '../src/lib/snapshot-schema.ts';

// Re-exported so existing importers keep a stable path. The definitions moved
// to src/lib/snapshot-schema.ts — zero Node dependencies — so the browser can
// hold a fetched snapshot to the same contract this collector publishes under.
// One definition at both ends of the pipe; a second copy is how drift arrives.
export { ALLOWED_URL_ORIGIN, MAX_DELTA_LENGTH, MAX_WORKFLOW_NAME_LENGTH, sanitizeGithubUrl };

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ACCOUNT = 'qwts';
const MANIFEST_REPO = 'playbook-engineering';
const MANIFEST_PATH = 'governance/repos.json';
const API = 'https://api.github.com';

const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

function warn(message) {
  process.stderr.write(`${message}\n`);
}

function token() {
  const value = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!value) {
    throw new Error('Set GITHUB_TOKEN or GH_TOKEN');
  }
  return value;
}

/** No request may outlive this. A hung endpoint fails; it does not wait. */
export const REQUEST_TIMEOUT_MS = 10_000;
/** Bounded: a rate limit outlasting this is reported, not waited out. */
export const MAX_ATTEMPTS = 3;
export const MAX_BACKOFF_MS = 30_000;

/**
 * Rate-limited and forbidden both arrive as 403 and previously collapsed into
 * the same `null`. They mean opposite things: one is transient and worth
 * retrying, the other is a permission the token does not have and never will
 * on this run.
 *
 * GitHub signals a limit three ways — 429, a primary limit with
 * `x-ratelimit-remaining: 0`, or a secondary limit carrying `retry-after`.
 */
export function isRateLimited(response) {
  if (!response) return false;
  if (response.status === 429) return true;
  if (response.status !== 403) return false;
  return (
    response.headers?.get('x-ratelimit-remaining') === '0' ||
    response.headers?.get('retry-after') !== null
  );
}

/**
 * How long the server actually asked us to wait, or `null` if it did not say.
 *
 * The single answer to that question, because two callers need it and a second
 * copy of this precedence is what let them disagree.
 *
 * `retry-after` is a direct instruction about *this* refusal and wins.
 * `x-ratelimit-reset` is only an answer when `x-ratelimit-remaining` is `0`:
 * the header rides on every response, and on a secondary limit or a bare 429
 * it is just when the hourly window rolls over — up to an hour out, and
 * nothing to do with why this request was refused. Reading it unconditionally
 * turns an unrelated header into a delay, and worse, into a reason to stop.
 */
function serverRetryHintMs(response, now) {
  const retryAfter = Number(response?.headers?.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return retryAfter * 1000;
  if (response?.headers?.get('x-ratelimit-remaining') !== '0') return null;
  const reset = Number(response?.headers?.get('x-ratelimit-reset'));
  if (!Number.isFinite(reset) || reset <= 0) return null;
  const waitMs = reset * 1000 - now;
  return waitMs > 0 ? waitMs : null;
}

/** Honours the server's own guidance before falling back to exponential backoff. */
export function retryDelayMs(response, attempt, now = Date.now()) {
  const hint = serverRetryHintMs(response, now);
  if (hint !== null) return Math.min(hint, MAX_BACKOFF_MS);
  return Math.min(2 ** attempt * 1000, MAX_BACKOFF_MS);
}

/** Aggregate only — never which repo. Counts, like everything else published. */
const health = { denied: 0, rateLimited: 0, failed: 0 };

export function collectionHealth() {
  return { ...health };
}

export function resetCollectionHealth() {
  health.denied = 0;
  health.rateLimited = 0;
  health.failed = 0;
}

/**
 * When a limit will not lift inside this run's patience.
 *
 * A primary rate limit is account-wide, not per-endpoint: once it fires, every
 * remaining request is limited too, and each would independently spend its own
 * retry budget. Nine repos at eight requests each turns a bounded per-request
 * wait into tens of minutes — on an hourly schedule, in a concurrency group
 * that queues rather than supersedes.
 *
 * If the wait will outlast the run's patience, retrying is not resilience; it
 * is spending the run. Stop retrying and let the counts be honestly unknown.
 *
 * A wait the server asked for and we are willing to sit out must *not* latch
 * this. On this workload — roughly 73 requests an hour against a budget of
 * 5,000 — a secondary limit from burst concurrency is the failure that will
 * actually happen, and it is the one worth waiting the few seconds for.
 */
let rateLimitedUntilMs = null;

export function resetRateLimitWindow() {
  rateLimitedUntilMs = null;
}

function noteRateLimitWindow(response, now = Date.now()) {
  const hint = serverRetryHintMs(response, now);
  if (hint !== null && hint > MAX_BACKOFF_MS) rateLimitedUntilMs = now + hint;
}

export function rateLimitWindowIsOpen(now = Date.now()) {
  return rateLimitedUntilMs === null || now >= rateLimitedUntilMs;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function gh(pathname, { token: auth, accept } = {}) {
  let lastError = null;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    let response;
    try {
      response = await fetch(`${API}${pathname}`, {
        // Without a deadline a single hung request holds the job for the
        // workflow's whole timeout, and every scheduled run behind it queues.
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          Accept: accept || 'application/vnd.github+json',
          Authorization: `Bearer ${auth || token()}`,
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'playbook-dashboard-collect',
        },
      });
    } catch (error) {
      // Timeout or transport failure. Retry, then give the caller a synthetic
      // 503 so every call site keeps its existing not-ok handling.
      lastError = error;
      if (attempt < MAX_ATTEMPTS - 1) {
        await sleep(Math.min(2 ** attempt * 1000, MAX_BACKOFF_MS));
        continue;
      }
      // A synthetic response rather than a rethrow. Most call sites do not
      // catch, and a throw from here would abort the whole collection over one
      // timed-out request — the same defect as routing /rulesets through
      // ghJson. `health.failed` is where the distinction is kept.
      health.failed += 1;
      return new Response(null, { status: 503, statusText: 'request failed or timed out' });
    }

    if (isRateLimited(response)) {
      noteRateLimitWindow(response);
      // Retry only while the window might still reopen within this run.
      if (attempt < MAX_ATTEMPTS - 1 && rateLimitWindowIsOpen()) {
        await sleep(retryDelayMs(response, attempt));
        continue;
      }
      health.rateLimited += 1;
      return response;
    }
    if (response.status === 403) health.denied += 1;
    if (response.status >= 500) health.failed += 1;
    return response;
  }

  // Unreachable: every branch on the final attempt returns. Kept as an
  // explicit assertion rather than a silent fall-through to undefined.
  throw lastError ?? new Error(`exhausted ${MAX_ATTEMPTS} attempts without returning`);
}

/**
 * Set any non-empty value to put the request path and response body into
 * failures. Never set in CI, and there is nothing to set it from: the Pages
 * workflow passes only `GITHUB_TOKEN` into the collect step.
 */
function debugFailures() {
  return Boolean(process.env.COLLECT_DEBUG);
}

/**
 * JSON read whose failure is fatal to the run.
 *
 * **Never call this before the visibility gate.** It throws, and `main().catch()`
 * prints what it throws into an Actions log that is public on this repository —
 * so a pre-gate failure would name the repository the gate was about to
 * withhold. `fetchRepoForGate` exists for that side of the line and returns bare
 * statuses instead of throwing. This is not a hypothetical ordering: the
 * pre-gate lookup went through this function until review caught it (#14).
 *
 * The message therefore carries a caller-supplied literal and a status, and
 * nothing derived from the response. GitHub's error bodies are ordinarily
 * `{"message", "documentation_url"}`, but they cross a boundary the threat
 * model treats as attacker-controlled, and copying them verbatim into a public
 * log is the GHSA-2qv8 class. `label` is a constant at the call site rather
 * than the path, so the safety does not depend on which path was requested.
 */
async function ghJson(pathname, { label = 'request', ...options } = {}) {
  const response = await gh(pathname, options);
  if (response.status === 404) return null;
  if (!response.ok) {
    const detail = debugFailures() ? ` ${pathname}: ${(await response.text()).slice(0, 200)}` : '';
    throw new Error(`${label} failed → ${response.status}${detail}`);
  }
  if (response.status === 204) return null;
  // The OK path can leak too: V8's JSON SyntaxError quotes a snippet of the
  // input it choked on, so an unguarded `.json()` on a garbled 200 puts body
  // bytes into the throw — the same route to a public log as the not-ok
  // branch, just dressed as a parse error. Same rule: the label, nothing
  // derived from the response.
  try {
    return await response.json();
  } catch {
    throw new Error(`${label} returned unparseable JSON`);
  }
}

/**
 * Open alert count for one repository.
 *
 * **Never call this before the visibility gate.** `repo` is interpolated into
 * three request paths, so any failure that named the path would name a repo the
 * gate may be about to withhold. Nothing here throws or logs for exactly that
 * reason: an unsuccessful read returns `null`, which the page renders as `?`
 * and `collectionHealth()` explains in aggregate.
 */
export async function countOpenAlerts(repo, kind) {
  const paths = {
    dependabot: `/repos/${ACCOUNT}/${repo}/dependabot/alerts?state=open&per_page=1`,
    codeScanning: `/repos/${ACCOUNT}/${repo}/code-scanning/alerts?state=open&per_page=1`,
    secretScanning: `/repos/${ACCOUNT}/${repo}/secret-scanning/alerts?state=open&per_page=1`,
  };
  const accepts = {
    dependabot: 'application/vnd.github+json',
    codeScanning: 'application/vnd.github+json',
    secretScanning: 'application/vnd.github+json',
  };

  const response = await gh(paths[kind], { accept: accepts[kind] });
  // Any unsuccessful read is an unknown count, not a fatal error. This used to
  // map 403/404 to null and throw on everything else — which included the 429
  // that `gh` returns once its retries are exhausted, i.e. exactly the case the
  // rate-limit handling exists for. The run died before writeFileSync, so
  // `collection.rateLimited` was incremented and then discarded.
  //
  // `collectionHealth()` carries the reason now, and #3 made a null count
  // render `?` rather than a green zero, so there is nothing left for the
  // throw to protect. Dropping it also stops 200 bytes of GitHub's response
  // body reaching a public Actions log (#23).
  if (!response.ok) return null;

  const link = response.headers.get('link') || '';
  const last = [...link.matchAll(/[?&]page=(\d+)>;\s*rel="last"/g)].pop();
  if (last) return Number(last[1]);

  // `.json()` was the one path left that could throw: V8's parse error quotes
  // the body it choked on. A garbled body is an unknown count — null, not 0,
  // so it renders `?` rather than a green zero nobody questions.
  const rows = await response.json().catch(() => null);
  return Array.isArray(rows) ? rows.length : null;
}

async function fetchSecurityFloor(repo, detail) {
  // `detail` comes from the gate, which already fetched this exact endpoint and
  // kept only `private`/`visibility`. Re-fetching cost one extra request per
  // repo per run for a field the caller was already holding — pure pressure
  // against the rate limit this change exists to survive.
  const analysis = detail?.security_and_analysis ?? {};

  let privateVulnerabilityReporting = null;
  const pvr = await gh(`/repos/${ACCOUNT}/${repo}/private-vulnerability-reporting`);
  if (pvr.ok) {
    // The same guard the branch-ruleset read below already carries: V8's parse
    // error quotes the body, and an uncaught throw here rides main().catch()
    // into a public log. An unparseable body leaves the bit unknown, like a
    // denied one.
    const body = await pvr.json().catch(() => null);
    if (body) privateVulnerabilityReporting = Boolean(body.enabled);
  } else if (pvr.status === 404 || pvr.status === 403) {
    privateVulnerabilityReporting = null;
  }

  let codeqlConfigured = null;
  const codeql = await gh(`/repos/${ACCOUNT}/${repo}/code-scanning/default-setup`);
  if (codeql.ok) {
    const body = await codeql.json().catch(() => null);
    if (body) codeqlConfigured = body.state === 'configured' || body.state === 'CodeQL exists';
  } else if (codeql.status === 404) {
    codeqlConfigured = false;
  } else if (codeql.status === 403) {
    codeqlConfigured = null;
  }

  // Reads through `gh` rather than `ghJson`, matching the two calls above.
  // `ghJson` throws on any non-OK status except 404, so a 403 here — exactly
  // what a token without Administration: Read returns — aborts the entire
  // collection rather than leaving one boolean unknown. A posture field the
  // token cannot read is unknown, not fatal: the floor bit renders `?` and
  // every other repo still collects.
  let defaultBranchRuleset = null;
  const rulesets = await gh(`/repos/${ACCOUNT}/${repo}/rulesets`);
  if (rulesets.ok) {
    const body = await rulesets.json().catch(() => null);
    if (Array.isArray(body)) {
      defaultBranchRuleset = body.some((row) => row.enforcement === 'active');
    }
  }

  return {
    secretScanning: analysis.secret_scanning?.status === 'enabled' ? true : analysis.secret_scanning ? false : null,
    pushProtection:
      analysis.secret_scanning_push_protection?.status === 'enabled'
        ? true
        : analysis.secret_scanning_push_protection
          ? false
          : null,
    dependabotAlerts:
      analysis.dependabot_security_updates?.status === 'enabled'
        ? true
        : analysis.dependabot_security_updates
          ? false
          : null,
    privateVulnerabilityReporting,
    codeqlConfigured,
    defaultBranchRuleset,
  };
}

/**
 * GitHub-authored free text crossing into the artifact the fail-closed gate
 * inspects. The schema rejects a snapshot whose workflow name exceeds the cap
 * or carries a control character — correctly, but validation runs fleet-wide:
 * left unsanitized, one repo's overlong or newline-bearing workflow name would
 * block publication for every repo in the fleet.
 *
 * Unlike `delta` this truncates rather than drops. A delta is authored copy
 * where a half-sentence misleads; a workflow name is a label, and a clipped
 * label still identifies the workflow where an absent one renders as no CI.
 */
export function sanitizeWorkflowName(value) {
  if (typeof value !== 'string' || value === '') return null;
  const cleaned = value.replace(new RegExp(CONTROL_CHARS.source, 'gu'), '');
  if (cleaned === '') return null;
  return cleaned.slice(0, MAX_WORKFLOW_NAME_LENGTH);
}

async function fetchCi(repo, defaultBranch) {
  // Reads through `gh`, not `ghJson`. Dropping Actions: Read returns 403, and
  // `ghJson` throws on it — killing the whole collection over one repo's CI
  // row. The all-null return below is exactly the right degradation and was
  // already here; the call simply did not route to it.
  const response = await gh(
    `/repos/${ACCOUNT}/${repo}/actions/runs?branch=${encodeURIComponent(defaultBranch)}&per_page=1`,
  );
  const runs = response.ok ? await response.json().catch(() => null) : null;
  const run = runs?.workflow_runs?.[0];
  if (!run) {
    return {
      workflowName: null,
      conclusion: null,
      status: null,
      updatedAt: null,
      htmlUrl: null,
    };
  }
  return {
    workflowName: sanitizeWorkflowName(run.name),
    conclusion: run.conclusion ?? null,
    status: run.status ?? null,
    updatedAt: run.updated_at ?? null,
    htmlUrl: sanitizeGithubUrl(run.html_url),
  };
}

/**
 * `true`/`false` only when the manifest says so, `null` when it is silent.
 *
 * The previous default published an unconfigured repo as managed, so a repo
 * nobody had set up and a repo deliberately enabled were indistinguishable on
 * the page — and the ambiguity resolved toward the one that prompts no
 * follow-up. That matters most during onboarding, when manifest entries are
 * least complete and someone is most likely to read the dashboard to decide
 * whether a repo is ready.
 *
 * If "omission means default-on" is genuinely the fleet contract, it belongs in
 * the manifest as an explicit field, not in a fallback here where the reader
 * cannot see it.
 */
export function parseCodexSync(entry) {
  const codexSync = entry?.codexSync;
  if (codexSync && typeof codexSync === 'object' && !Array.isArray(codexSync)) {
    if (typeof codexSync.enabled === 'boolean') return codexSync.enabled;
  }
  return null;
}

// `ALLOWED_URL_ORIGIN` and `sanitizeGithubUrl` lived here; they moved to
// src/lib/snapshot-schema.ts with the rest of the contract so the browser
// applies the identical URL rule at render time. Imported and re-exported at
// the top of this file.

/**
 * Gate 1 — publication is an explicit act recorded in the governance manifest.
 * Only the boolean `true` opts a repo in; absent, false, or any truthy
 * non-boolean (`"true"`, `1`) means do not publish.
 */
export function isPublishable(entry) {
  return entry?.publish === true;
}

/**
 * Gate 2 — GitHub's own answer, not the manifest's claim. A repo the manifest
 * still describes as public may have been flipped private since the last
 * manifest edit; requiring `private: false` and `visibility: "public"` to agree
 * means an unreadable or partial repo response fails closed.
 */
export function isObservedPublic(detail) {
  return detail?.private === false && detail?.visibility === 'public';
}

/**
 * Manifest free text crossing into the published page. Rejected wholesale
 * rather than truncated — a half-sentence reads as authored copy. The reason is
 * logged, the value never is: the manifest is untrusted and Actions logs on a
 * public repo are themselves public.
 */
export function sanitizeDelta(value, repoName) {
  if (typeof value !== 'string' || value === '') return '';
  if (value.length > MAX_DELTA_LENGTH) {
    warn(`${repoName}: delta dropped — ${value.length} chars exceeds ${MAX_DELTA_LENGTH}`);
    return '';
  }
  if (CONTROL_CHARS.test(value)) {
    warn(`${repoName}: delta dropped — control characters`);
    return '';
  }
  return value;
}

export async function loadManifest() {
  const encoded = MANIFEST_PATH.split('/').map(encodeURIComponent).join('/');
  const file = await ghJson(`/repos/${ACCOUNT}/${MANIFEST_REPO}/contents/${encoded}`, {
    label: 'governance manifest read',
  });
  if (!file?.content) throw new Error('Unable to load governance/repos.json');
  const raw = Buffer.from(file.content, 'base64').toString('utf8');
  // JSON.parse's SyntaxError quotes the text it choked on — here, decoded file
  // content from a private repo. The filename is everything a maintainer needs
  // to fix it; the content is exactly what must not reach a public log.
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('governance/repos.json is not valid JSON');
  }
}

/**
 * Pre-gate repo lookup.
 *
 * Runs before gate 2 has decided whether this repo may be named at all, so it
 * must never put the name, the request path, or GitHub's response body into an
 * error: `main().catch()` prints those, and Actions logs on a public repository
 * are public. `ghJson` throws at all, which is the disqualifying property here
 * whatever its message says — this side of the gate has no failure worth ending
 * the run over, only a repo that does not get published.
 *
 * Any failure is withholding, not an exception. If visibility cannot be
 * determined, the repo is not published. Statuses accumulate into `failures`
 * for an aggregated summary — never logged next to the loop's position counter,
 * because the manifest is public and pairing position with outcome would
 * re-identify the repo the gate just withheld.
 */
export async function fetchRepoForGate(name, failures = []) {
  let response;
  try {
    response = await gh(`/repos/${ACCOUNT}/${name}`);
  } catch {
    failures.push('network');
    return null;
  }
  if (!response.ok) {
    failures.push(String(response.status));
    return null;
  }
  try {
    return await response.json();
  } catch {
    failures.push('malformed');
    return null;
  }
}

/** Returns the redacted row, or `null` if the repo must not be published. */
/** Exported for the round-trip test: collector output must satisfy the schema. */
export async function collectRepo(entry, failures) {
  const detail = await fetchRepoForGate(entry.name, failures);
  // Withheld before any alert or CI call: nothing we do not publish is fetched.
  // The name is deliberately not logged — see the summary in main().
  if (!isObservedPublic(detail)) return null;

  const defaultBranch = detail.default_branch || 'main';

  const [securityFloor, dependabotOpen, codeScanningOpen, secretScanningOpen, ci] =
    await Promise.all([
      fetchSecurityFloor(entry.name, detail),
      countOpenAlerts(entry.name, 'dependabot'),
      countOpenAlerts(entry.name, 'codeScanning'),
      countOpenAlerts(entry.name, 'secretScanning'),
      fetchCi(entry.name, defaultBranch),
    ]);

  return {
    name: entry.name,
    visibility: detail.visibility,
    status: entry.status,
    sharedCi: Boolean(entry.sharedCi),
    codexSyncEnabled: parseCodexSync(entry),
    delta: sanitizeDelta(entry.delta, entry.name),
    // No hand-built fallback. The previous `|| https://github.com/${ACCOUNT}/${entry.name}`
    // constructed a URL from an untrusted manifest name for a case that cannot
    // happen post-gate — gate 2 already required a readable repo response. An
    // unlinked repo name is a better answer than a guessed link.
    htmlUrl: sanitizeGithubUrl(detail.html_url),
    securityFloor,
    security: {
      dependabotOpen,
      codeScanningOpen,
      secretScanningOpen,
    },
    ci,
  };
}

async function main() {
  const outPath =
    process.argv.includes('--out')
      ? process.argv[process.argv.indexOf('--out') + 1]
      : path.join(ROOT, 'public', 'data', 'snapshot.json');

  const manifest = await loadManifest();
  // Retired repos have always left the fleet view; `governed` is the denominator
  // the page reports against, so withholding stays visible as a number.
  const governed = (manifest.repos || []).filter((repo) => repo.status !== 'retired');
  const candidates = governed.filter(isPublishable);

  const repos = [];
  const gateFailures = [];
  for (const [index, entry] of candidates.entries()) {
    // Position, not identity. Gate 2 runs inside collectRepo, so a name logged
    // here would be published *before* we know whether the repo passes it — and
    // the repo that fails is exactly the one whose name must not appear in an
    // Actions log. The candidate count is already public via `withheld`.
    //
    // Nothing about this repo's *outcome* may be logged here either: candidate
    // order comes from a public manifest, so position plus outcome re-identifies
    // it. Outcomes are aggregated below instead.
    warn(`collect ${index + 1}/${candidates.length}`);
    const row = await collectRepo(entry, gateFailures);
    if (row) repos.push(row);
  }

  // Counts only. Naming the withheld repos in an Actions log on a public
  // repository would republish exactly what the gates just withheld.
  //
  // `withheld` is a count of *decisions*, so a repo whose gate call failed does
  // not belong in it. Both produce no published row, which is why they were one
  // number — but they mean opposite things to a reader. "We chose not to publish
  // these" is a stable, reassuring statement about a fleet under control; "we
  // could not tell" is a transient failure that will resolve itself next hour,
  // and folding it into the reassuring number is the same defect as a denied
  // read rendering as a green zero, one level up. A rate limit made the fleet
  // look more deliberately curated than it was.
  const tally = publicationTally({
    governed: governed.length,
    candidates: candidates.length,
    published: repos.length,
    unreadable: gateFailures.length,
  });
  const { withheld, unreadable, notOptedIn, notObservedPublic } = tally;
  warn(
    `withheld ${withheld} of ${governed.length} governed repos ` +
      `(${notOptedIn} without publish: true, ${notObservedPublic} not observed public)` +
      (unreadable > 0 ? `, and ${unreadable} could not be read at all` : ''),
  );
  if (gateFailures.length) {
    // Sorted and tallied, so the order tells you nothing about which candidate
    // produced which status.
    const tally = [...gateFailures.reduce((m, s) => m.set(s, (m.get(s) ?? 0) + 1), new Map())]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([status, count]) => `${status}x${count}`)
      .join(', ');
    warn(`repo lookups that failed before the visibility gate: ${tally}`);
  }
  // An empty snapshot is published, not suppressed. Zero repos renders as
  // "published 0 of N governed · N withheld" — visibly, unmistakably nothing.
  // Falling back to the committed fixture instead would serve yesterday's posture
  // numbers as though they were current, and nobody reads a plausible page twice.
  // Obviously broken beats plausibly wrong on a board whose whole job is posture.
  //
  // The run still fails (see pages.yml) so the blank is noticed, not just served.
  if (repos.length === 0) {
    // The breakdown must include the failure bucket: when emptiness is caused
    // by gate failures, `notOptedIn` and `notObservedPublic` are both zero and
    // a message listing only decisions would explain nothing.
    warn(
      `WARNING: no repos passed the publication gates — publishing an empty snapshot. ` +
        `${governed.length} governed, ${notOptedIn} without publish: true, ` +
        `${notObservedPublic} not observed public` +
        (unreadable > 0 ? `, and ${unreadable} could not be read at all.` : '.'),
    );
  }

  const snapshot = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    source: {
      account: ACCOUNT,
      manifestRepo: `${ACCOUNT}/${MANIFEST_REPO}`,
      manifestPath: MANIFEST_PATH,
    },
    withheld,
    // Kept apart from `withheld` because they are not the same claim: this one
    // is "the gate could not be evaluated", which is a failure, not a decision.
    unreadable,
    // Why reads were missing, in aggregate and never per repo. A `null` count
    // used to mean "denied" and "rate limited" indistinguishably; the first is
    // a permission that will not change this run, the second is transient.
    collection: collectionHealth(),
    repos,
  };

  const reasons = degradedReasons(snapshot);
  if (reasons.length > 0) {
    warn(
      `degraded: ${reasons.join(', ')} — published as unknown, not zero. ` +
        'This run is not clean.',
    );
  }
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(snapshot, null, 2)}\n`);
  process.stderr.write(`wrote ${outPath}\n`);

  // After the write, so the verdict only describes a snapshot that shipped. If
  // the write throws, the step fails, `fresh` is false, and the stale gate — not
  // this one — is the accurate complaint.
  reportDegradation(reasons);
}

/**
 * How the governed set divides, with failures kept out of the decisions.
 *
 * Every governed repo lands in exactly one bucket, and the invariant
 * `published + withheld + unreadable === governed` is what makes the published
 * denominator mean anything. It is asserted here rather than trusted, because
 * the failure is silent in both directions: too high and the page claims a
 * fleet larger than it is, too low and a repo vanishes with nothing to say so.
 *
 * `withheld` counts *decisions* — not opted in, or observed non-public.
 * `unreadable` counts gates that could not be evaluated. Both publish no row,
 * which is why they were once one number, but they are opposite claims about
 * whether the fleet is under control.
 */
export function publicationTally({ governed, candidates, published, unreadable }) {
  const notOptedIn = governed - candidates;
  const notObservedPublic = candidates - published - unreadable;
  const withheld = notOptedIn + notObservedPublic;

  // The last condition is implied by the two above it: with non-negative
  // integer inputs the sum reduces to `governed` algebraically, so no *input*
  // can trip it. It is not dead. It is the only guard against a future change
  // to the *derivation* — dropping the `- unreadable` term above makes it the
  // sole thing that fires. Verified by doing exactly that with the other checks
  // removed. Noted because the alternative reading is that it is an unreachable
  // branch pretending to be a safety net.
  if (
    [governed, candidates, published, unreadable].some((n) => !Number.isInteger(n) || n < 0) ||
    notOptedIn < 0 ||
    notObservedPublic < 0 ||
    published + withheld + unreadable !== governed
  ) {
    // Not recoverable by guessing. Publishing a denominator we cannot derive
    // would state something about the fleet that is not true.
    throw new Error(
      `publication tally does not add up: ${published} published + ${withheld} withheld + ` +
        `${unreadable} unreadable != ${governed} governed`,
    );
  }

  return { withheld, unreadable, notOptedIn, notObservedPublic };
}

/**
 * Which floor flag, when known-false, explains a `null` count as "feature
 * disabled" rather than "read refused". A count with no entry here is never
 * excused. See the rule on `degradedReasons`.
 */
const FLOOR_FLAG_FOR_COUNT = {
  dependabotOpen: 'dependabotAlerts',
  codeScanningOpen: 'codeqlConfigured',
  secretScanningOpen: 'secretScanning',
};

/**
 * Why a snapshot that was written successfully still knows less than it looks
 * like it knows. Empty means the run read everything it set out to read.
 *
 * This is the layer the earlier fixes left open. A denied read became `null`,
 * #3 stopped `null` becoming a green zero in the UI, and #12's first half
 * stopped a rate limit killing the run — but the *run* stayed green through
 * all of it, because `continue-on-error` on the collect step only distinguishes
 * "collection failed" from "collection succeeded". A collection that succeeded
 * while unable to read half the fleet is a third state, and it looked like the
 * good one: green check, published page, question marks nobody was told about.
 *
 * Two sources, and they overlap on purpose. The artifact is what gets
 * published: a 404 yields a `null` count without touching a counter, and a
 * gate lookup that 404s or returns an unparseable body reaches `unreadable`
 * without touching one either — so only the snapshot knows what the page will
 * show, a `?` or a repo the run could not evaluate at all. The health counters see
 * what the artifact cannot: a denied or rate-limited read against a repo the
 * gates then withheld leaves no trace in `repos` at all. Including both means
 * a denied posture read on a published repo is reported twice — once as
 * `denied`, once as `unreadable` — and a failed gate call reddens the run for
 * a repo that was never going to be published. Accepted, deliberately: this
 * gate exists because its failure mode is silence, and every overlap errs in
 * the loud direction.
 *
 * A `null` count is only unreadable when the read could have succeeded. GitHub
 * answers 403 on `dependabot/alerts` when Dependabot alerts are disabled and
 * 404 on `code-scanning/alerts` when code scanning was never enabled —
 * permanent, owner-chosen states, not failures, and reddening every hourly run
 * over them forever would make this gate noise (the `codexSyncEnabled`
 * argument below, one field over). So each count is excused by its floor flag
 * when that flag is known-false: the feature is off, the missing number is the
 * owner's choice, and the page already says so via the flag itself. When the
 * flag is `true` or itself unknown, a `null` count stays unreadable — the
 * feature was (or may have been) on, and the collector still learned nothing.
 *
 * Counts only, never which repo — same contract as everything else that leaves
 * this file, and the reason string reaches a public Actions log.
 */
export function degradedReasons(snapshot) {
  const reasons = [];
  const health = snapshot?.collection ?? {};
  if (health.denied > 0) reasons.push(`${health.denied} denied`);
  if (health.rateLimited > 0) reasons.push(`${health.rateLimited} rate-limited`);
  if (health.failed > 0) reasons.push(`${health.failed} failed or timed out`);

  // The path the counters cannot see. A deleted repo left in the manifest with
  // `publish: true` 404s at the gate: no counter moves, no row publishes, and
  // without this check the run stays green while the page reports a repo it
  // could not evaluate. The snapshot is the only place that failure survives.
  // Guarded like every count read back out of an artifact: anything that is
  // not a sane count is not evidence of degradation.
  const unreadable = snapshot?.unreadable;
  if (Number.isInteger(unreadable) && unreadable > 0) {
    reasons.push(`${unreadable} repos unreadable at the gate`);
  }

  let unknown = 0;
  for (const repo of snapshot?.repos ?? []) {
    // `codexSyncEnabled` is deliberately not counted. Its `null` means the
    // manifest never asserted the fact (#8), not that a read was refused —
    // most governed repos are silent about it today, and reddening every run
    // over an absent declaration would make this gate noise within a week. The
    // gate is for what the collector could not *read*.
    const floor = repo?.securityFloor ?? {};
    for (const [field, value] of Object.entries(repo?.security ?? {})) {
      if (Number.isInteger(value) && value >= 0) continue;
      // Excused only for `null`, and only when the flag is known-false: a
      // malformed value is corruption whatever the owner chose, and an unknown
      // flag cannot vouch for anything.
      if (value === null && floor[FLOOR_FLAG_FOR_COUNT[field]] === false) continue;
      unknown += 1;
    }
    for (const value of Object.values(floor)) {
      if (typeof value !== 'boolean') unknown += 1;
    }
  }
  if (unknown > 0) reasons.push(`${unknown} posture fields unreadable`);

  return reasons;
}

/**
 * Hand the verdict to the workflow, which is the only place that can act on it.
 *
 * A degraded snapshot and a failed collection want opposite handling: the
 * degraded one is still the freshest truth available and must be published, it
 * just must not be published quietly. So this cannot ride on the step's exit
 * code — a non-zero exit makes `fresh` false and swaps in the committed
 * fixture, throwing away the better artifact to report the smaller problem.
 *
 * No-ops outside Actions.
 *
 * The key names here are a contract with `pages.yml`, which nothing at runtime
 * would notice breaking: a renamed key makes the job output empty, the gate's
 * `if` false, and every degraded run green again — silently, and in the
 * direction that looks fine. Pinned across both files in workflows.test.mjs.
 */
export function reportDegradation(reasons, outputPath = process.env.GITHUB_OUTPUT) {
  if (!outputPath) return;
  // Every character here originates in this file's own literals and integers.
  // Stripped anyway: a newline would let a value forge a second output line,
  // and this is the one place a collector string crosses into the workflow.
  const reason = reasons.join(', ').replace(/[^\w ,.:;/()-]/gu, '');
  appendFileSync(outputPath, `degraded=${reasons.length > 0}\ndegraded_reason=${reason}\n`);
}

// Only collect when run as a script; importing this module (from tests) must
// not reach for a token or the network.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
