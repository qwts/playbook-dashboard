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

async function gh(pathname, { token: auth, accept } = {}) {
  const response = await fetch(`${API}${pathname}`, {
    headers: {
      Accept: accept || 'application/vnd.github+json',
      Authorization: `Bearer ${auth || token()}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'playbook-dashboard-collect',
    },
  });
  return response;
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

async function countOpenAlerts(repo, kind) {
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
  if (response.status === 403 || response.status === 404) return null;
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${paths[kind]} → ${response.status}: ${body.slice(0, 200)}`);
  }

  const link = response.headers.get('link') || '';
  const last = [...link.matchAll(/[?&]page=(\d+)>;\s*rel="last"/g)].pop();
  if (last) return Number(last[1]);

  const rows = await response.json();
  return Array.isArray(rows) ? rows.length : 0;
}

async function fetchSecurityFloor(repo) {
  const detail = await ghJson(`/repos/${ACCOUNT}/${repo}`);
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

  let defaultBranchRuleset = null;
  const rulesets = await ghJson(`/repos/${ACCOUNT}/${repo}/rulesets`);
  if (Array.isArray(rulesets)) {
    defaultBranchRuleset = rulesets.some((row) => row.enforcement === 'active');
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
  const runs = await ghJson(
    `/repos/${ACCOUNT}/${repo}/actions/runs?branch=${encodeURIComponent(defaultBranch)}&per_page=1`,
  );
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
    htmlUrl: run.html_url ?? null,
  };
}

function parseCodexSync(entry) {
  if (entry.codexSync && typeof entry.codexSync === 'object') {
    if (typeof entry.codexSync.enabled === 'boolean') return entry.codexSync.enabled;
  }
  // Manifest omission means managed/default-on for consumers in this fleet.
  return true;
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

/** Returns the redacted row, or `null` if the repo must not be published. */
async function collectRepo(entry) {
  const detail = await ghJson(`/repos/${ACCOUNT}/${entry.name}`);
  // Withheld before any alert or CI call: nothing we do not publish is fetched.
  // The name is deliberately not logged — see the summary in main().
  if (!isObservedPublic(detail)) return null;

  const defaultBranch = detail.default_branch || 'main';

  const [securityFloor, dependabotOpen, codeScanningOpen, secretScanningOpen, ci] =
    await Promise.all([
      fetchSecurityFloor(entry.name),
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
    htmlUrl: detail.html_url || `https://github.com/${ACCOUNT}/${entry.name}`,
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
  for (const [index, entry] of candidates.entries()) {
    // Position, not identity. Gate 2 runs inside collectRepo, so a name logged
    // here would be published *before* we know whether the repo passes it — and
    // the repo that fails is exactly the one whose name must not appear in an
    // Actions log. The candidate count is already public via `withheld`.
    warn(`collect ${index + 1}/${candidates.length}`);
    const row = await collectRepo(entry);
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
  if (repos.length === 0) {
    warn('WARNING: no repos passed the publication gates — the dashboard will render empty');
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
