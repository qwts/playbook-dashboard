#!/usr/bin/env node

/**
 * Build a redacted fleet snapshot for the public dashboard.
 *
 * Publishes counts and boolean posture only — never alert titles, paths,
 * CVEs, secret material, or private vulnerability report bodies.
 *
 * Publication is opt-in and double-gated (see DESIGN.md): a repo is collected
 * only if the manifest sets `publish: true`, and it is emitted only if GitHub
 * reports it as public at collection time. A repo that fails either gate
 * contributes nothing but an increment to `withheld`.
 *
 * Auth: GITHUB_TOKEN or GH_TOKEN (fine-grained: Contents read on playbook,
 * Metadata + Security events / Dependabot alerts / Actions on governed repos).
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ACCOUNT = 'qwts';
const MANIFEST_REPO = 'playbook-engineering';
const MANIFEST_PATH = 'governance/repos.json';
const API = 'https://api.github.com';

/** Longest manifest `delta` string that may reach the published page. */
export const MAX_DELTA_LENGTH = 200;

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

/** Honours the server's own guidance before falling back to exponential backoff. */
export function retryDelayMs(response, attempt, now = Date.now()) {
  const retryAfter = Number(response?.headers?.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) {
    return Math.min(retryAfter * 1000, MAX_BACKOFF_MS);
  }
  const reset = Number(response?.headers?.get('x-ratelimit-reset'));
  if (Number.isFinite(reset) && reset > 0) {
    const waitMs = reset * 1000 - now;
    if (waitMs > 0) return Math.min(waitMs, MAX_BACKOFF_MS);
  }
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
 * When a primary limit will not reopen inside this run's patience.
 *
 * A primary rate limit is account-wide, not per-endpoint: once it fires, every
 * remaining request is limited too, and each would independently spend its own
 * retry budget. Nine repos at eight requests each turns a bounded per-request
 * wait into tens of minutes — on an hourly schedule, in a concurrency group
 * that queues rather than supersedes.
 *
 * If the window will not reopen in time, retrying is not resilience; it is
 * spending the run. Stop retrying and let the counts be honestly unknown.
 */
let rateLimitedUntilMs = null;

export function resetRateLimitWindow() {
  rateLimitedUntilMs = null;
}

function noteRateLimitWindow(response, now = Date.now()) {
  const reset = Number(response?.headers?.get('x-ratelimit-reset'));
  if (!Number.isFinite(reset) || reset <= 0) return;
  const resetMs = reset * 1000;
  if (resetMs - now > MAX_BACKOFF_MS) rateLimitedUntilMs = resetMs;
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

async function ghJson(pathname, options) {
  const response = await gh(pathname, options);
  if (response.status === 404) return null;
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${pathname} → ${response.status}: ${body.slice(0, 200)}`);
  }
  if (response.status === 204) return null;
  return response.json();
}

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

  const rows = await response.json();
  return Array.isArray(rows) ? rows.length : 0;
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
    const body = await pvr.json();
    privateVulnerabilityReporting = Boolean(body.enabled);
  } else if (pvr.status === 404 || pvr.status === 403) {
    privateVulnerabilityReporting = null;
  }

  let codeqlConfigured = null;
  const codeql = await gh(`/repos/${ACCOUNT}/${repo}/code-scanning/default-setup`);
  if (codeql.ok) {
    const body = await codeql.json();
    codeqlConfigured = body.state === 'configured' || body.state === 'CodeQL exists';
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
    workflowName: run.name ?? null,
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

/** The only origin the published dashboard will ever emit a link to. */
export const ALLOWED_URL_ORIGIN = 'https://github.com';

/**
 * A URL reaches the snapshot only if it is `https:` at exactly
 * `https://github.com`. Everything else becomes `null`, and the UI renders
 * unlinked text.
 *
 * Validated here, where the value enters, rather than at render time. React
 * escapes text content but does not sanitize `href` schemes, so a `javascript:`
 * URL in an `href` is script execution on click. In practice these values come
 * from the GitHub API and are fine — but nothing enforced that, and the
 * property lived entirely in an upstream service's behaviour.
 *
 * Rejects embedded credentials: `https://user:pass@github.com` has an origin of
 * exactly `https://github.com`, so an origin check alone passes it through while
 * the rendered href still carries the credentials — a phishing shape.
 */
export function sanitizeGithubUrl(value) {
  if (typeof value !== 'string' || value === '') return null;

  let url;
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

async function loadManifest() {
  const encoded = MANIFEST_PATH.split('/').map(encodeURIComponent).join('/');
  const file = await ghJson(`/repos/${ACCOUNT}/${MANIFEST_REPO}/contents/${encoded}`);
  if (!file?.content) throw new Error('Unable to load governance/repos.json');
  const raw = Buffer.from(file.content, 'base64').toString('utf8');
  return JSON.parse(raw);
}

/**
 * Pre-gate repo lookup.
 *
 * Runs before gate 2 has decided whether this repo may be named at all, so it
 * must never put the name, the request path, or GitHub's response body into an
 * error: `main().catch()` prints those, and Actions logs on a public repository
 * are public. `ghJson` embeds all three, which is correct for every *post*-gate
 * call and wrong here.
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
async function collectRepo(entry, failures) {
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

  const withheld = governed.length - repos.length;
  // Counts only. Naming the withheld repos in an Actions log on a public
  // repository would republish exactly what the gates just withheld.
  const notOptedIn = governed.length - candidates.length;
  const notObservedPublic = candidates.length - repos.length;
  warn(
    `withheld ${withheld} of ${governed.length} governed repos ` +
      `(${notOptedIn} without publish: true, ${notObservedPublic} not observed public)`,
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
  const h = collectionHealth();
  if (h.denied || h.rateLimited || h.failed) {
    warn(
      `degraded reads: ${h.denied} denied, ${h.rateLimited} rate-limited, ${h.failed} failed ` +
        '— counts they would have filled are published as unknown, not zero',
    );
  }
  if (repos.length === 0) {
    warn(
      `WARNING: no repos passed the publication gates — publishing an empty snapshot. ` +
        `${governed.length} governed, ${notOptedIn} without publish: true, ` +
        `${notObservedPublic} not observed public.`,
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
    // Why reads were missing, in aggregate and never per repo. A `null` count
    // used to mean "denied" and "rate limited" indistinguishably; the first is
    // a permission that will not change this run, the second is transient.
    collection: collectionHealth(),
    repos,
  };

  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(snapshot, null, 2)}\n`);
  process.stderr.write(`wrote ${outPath}\n`);
}

// Only collect when run as a script; importing this module (from tests) must
// not reach for a token or the network.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
