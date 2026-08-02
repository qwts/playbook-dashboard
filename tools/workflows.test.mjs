import assert from 'node:assert/strict';
import { readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reportDegradation } from './collect.mjs';
import { test } from 'node:test';

/**
 * Assertions on workflow *source*, because nothing else checks it.
 *
 * `pages.yml` has no `pull_request` trigger, so no PR ever runs it: a change
 * that breaks it is merged, then discovered by the hourly schedule against
 * production, with the fleet credential in hand. These are text assertions
 * rather than parsed YAML deliberately — the invariants worth guarding here are
 * about the literal expressions someone would edit, and a parser would add a
 * runtime dependency to check less.
 */
const PAGES = readFileSync(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');
const CI = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const WORKER = readFileSync(new URL('../.github/workflows/worker.yml', import.meta.url), 'utf8');
const CODEQL = readFileSync(new URL('../.github/workflows/codeql.yml', import.meta.url), 'utf8');

/**
 * A file with whole-line comments removed.
 *
 * These files document their own reasoning at length, and several of those
 * comments quote the very expressions asserted below — a structural check run
 * against the raw text matches the prose describing the rule as readily as the
 * rule. Two of these tests failed that way on first run.
 */
function structureOf(source) {
  return source
    .split('\n')
    .filter((line) => !/^\s*#/u.test(line))
    .join('\n');
}

const STRUCTURE = structureOf(PAGES);

/** Just the `jobs:` mapping, so trigger keys are not mistaken for job names. */
const JOBS = STRUCTURE.slice(STRUCTURE.indexOf('\njobs:'));

/**
 * Every workflow, not just pages.yml. The invariants that hold per-file —
 * bounded jobs, no expression spliced into a shell — rot precisely by someone
 * adding a workflow this file never heard of.
 */
const WORKFLOW_DIR = fileURLToPath(new URL('../.github/workflows/', import.meta.url));
const WORKFLOWS = readdirSync(WORKFLOW_DIR)
  .filter((name) => /\.ya?ml$/u.test(name))
  .sort()
  .map((name) => [name, structureOf(readFileSync(join(WORKFLOW_DIR, name), 'utf8'))]);

/**
 * Every `run:` script in a workflow, whatever YAML scalar shape it takes.
 *
 * The first version of the interpolation guard matched only `run: |` blocks at
 * one exact indentation, so a single-line `- run:` or a folded `run: >` was a
 * hole: an expression spliced there passed the guard. Extracted structurally
 * instead — from each `run:` key through every following line indented deeper
 * than the key — which covers plain, literal, and folded scalars alike.
 */
function runScripts(structure) {
  const lines = structure.split('\n');
  const scripts = [];
  for (let i = 0; i < lines.length; i += 1) {
    const key = /^(\s*(?:- )?)run:(.*)$/u.exec(lines[i]);
    if (!key) continue;
    const indent = key[1].length;
    let body = key[2];
    let j = i + 1;
    for (; j < lines.length; j += 1) {
      const depth = lines[j].search(/\S/u);
      if (lines[j].trim() !== '' && depth <= indent) break;
      body += `\n${lines[j]}`;
    }
    scripts.push(body);
    i = j - 1;
  }
  return scripts;
}

// The one-character version of this bug ships silently. `continue-on-error`
// makes a failed step's *conclusion* success — that is the entire purpose of
// the flag — so `conclusion` here would mark every failed collection as fresh
// and republish the stale-fixture-served-as-current bug that #20 exists to
// prevent. Nothing else in the repo distinguishes the two words.
test('freshness is read from the step outcome, not its conclusion', () => {
  assert.match(STRUCTURE, /fresh:\s*\$\{\{\s*steps\.collect\.outcome\s*==\s*'success'\s*\}\}/u);
  assert.doesNotMatch(
    STRUCTURE,
    /steps\.collect\.conclusion/u,
    'conclusion is success even when the step failed; outcome is the real result',
  );
});

test('the step allowed to fail is the only one allowed to fail', () => {
  const allowed = [...STRUCTURE.matchAll(/^\s*continue-on-error:\s*true$/gmu)];
  assert.equal(allowed.length, 1, 'exactly one step may fail without failing its job');
  // And it is the collect step, not something downstream that would swallow a
  // deploy failure or the gates below.
  assert.match(STRUCTURE, /id:\s*collect\n\s*continue-on-error:\s*true/u);
});

test('every job in every workflow is bounded, so a wedged run cannot hold a runner for six hours', () => {
  // The list pin is for pages.yml alone: its jobs partition one credential and
  // two grants, so a job appearing or vanishing must be looked at, not skipped.
  const pagesJobs = [...JOBS.matchAll(/^ {2}([a-z][\w-]*):$/gmu)].map((m) => m[1]);
  assert.deepEqual(
    pagesJobs,
    ['policy', 'collect', 'build', 'attest', 'deploy'],
    'job list changed — check the bounds',
  );

  // The bound is for every file: DESIGN.md says "every job declares
  // `timeout-minutes`", and ci.yml shipped without one for as long as this
  // test only read pages.yml.
  assert.ok(WORKFLOWS.length >= 2, 'the workflow directory went missing or empty');
  for (const [name, structure] of WORKFLOWS) {
    const jobsBlock = structure.slice(structure.indexOf('\njobs:'));
    const jobs = [...jobsBlock.matchAll(/^ {2}([a-z][\w-]*):$/gmu)].map((m) => m[1]);
    assert.ok(jobs.length > 0, `${name}: found no jobs — extraction broke or the file is empty`);

    const jobStarts = [...jobsBlock.matchAll(/^ {2}([a-z][\w-]*):$/gmu)];
    for (let i = 0; i < jobStarts.length; i += 1) {
      const start = jobStarts[i].index;
      const end = jobStarts[i + 1]?.index ?? jobsBlock.length;
      const job = jobsBlock.slice(start, end);
      const timeout = /^ {4}timeout-minutes:\s*(\d+)$/mu.exec(job);
      if (!timeout && /\n\s+uses:\s+\.\/\.github\/workflows\//u.test(job)) continue;
      assert.ok(timeout, `${name}: every executable job needs its own timeout-minutes`);
      assert.ok(Number(timeout[1]) <= 30, `${name}: ${timeout[1]}m is not a bound worth having`);
    }
  }
});

// Deploy-then-fail, in that order. Reversing them turns a legible degraded
// dashboard into an outage, which is the trade #20 explicitly rejected.
test('the run fails after deploying, never instead of deploying', () => {
  const deployAt = STRUCTURE.indexOf('uses: actions/deploy-pages@');
  const staleGate = STRUCTURE.indexOf('Fail the run when the snapshot was not freshly collected');
  const degradedGate = STRUCTURE.indexOf('Fail the run when the collection knew less than it should have');

  assert.ok(deployAt > 0 && staleGate > 0 && degradedGate > 0, 'a gate went missing');
  assert.ok(staleGate > deployAt, 'the stale gate must run after the deploy');
  assert.ok(degradedGate > deployAt, 'the degraded gate must run after the deploy');
});

// A successful-but-partial collection used to be indistinguishable from a clean
// one. It must fail the run, and it must do so *without* discarding the
// snapshot it collected — hence a separate output rather than an exit code.
test('a degraded collection reddens the run and still publishes', () => {
  assert.match(STRUCTURE, /degraded:\s*\$\{\{\s*steps\.collect\.outputs\.degraded\s*\}\}/u);
  assert.match(
    STRUCTURE,
    /if:\s*needs\.collect\.outputs\.fresh == 'true' && needs\.collect\.outputs\.degraded == 'true'/u,
    'the degraded gate only speaks for runs that actually collected something',
  );
});

// An expression is data crossing a boundary. Bound to env, never spliced into
// the shell — the rule does not get an exception for strings we believe we own.
// Checked across every scalar shape and every workflow: the first version of
// this guard matched only `run: |` blocks at one indentation, which made a
// single-line `- run:` a silent exemption.
test('no expression is interpolated into a run script, in any workflow', () => {
  let total = 0;
  for (const [name, structure] of WORKFLOWS) {
    for (const body of runScripts(structure)) {
      total += 1;
      assert.doesNotMatch(
        body,
        /\$\{\{/u,
        `${name}: an expression is spliced into a shell script:\n${body}`,
      );
    }
  }
  // A count, so a regression in the extraction fails loudly instead of
  // quietly asserting nothing about nothing.
  assert.ok(total >= 8, `expected at least the 8 known run scripts, found ${total}`);
});

test('third-party actions are pinned to a commit sha', () => {
  let total = 0;
  for (const [name, structure] of WORKFLOWS) {
    const uses = [...structure.matchAll(/uses:\s*(\S+)/gu)].map((m) => m[1]);
    total += uses.length;
    for (const ref of uses) {
      if (ref.startsWith('./')) continue;
      assert.match(ref, /@[0-9a-f]{40}$/u, `${name}: ${ref} is not pinned to a full commit sha`);
    }
  }
  assert.ok(total >= 10, `expected the action list, found ${total}`);
});

test('governed CI declares every lifecycle lane and the exact preflight title', () => {
  assert.match(CI, /run-name: CI \$\{\{ github\.event_name \}\} purpose=\$\{\{ inputs\.purpose \|\| 'automatic' \}\}/u);
  assert.match(CI, /merge_group:\n\s+types: \[checks_requested\]/u);
  assert.match(CI, /cancel-in-progress: \$\{\{ github\.event_name != 'push' \}\}/u);
  assert.match(CI, /uses: qwts\/playbook-engineering\/\.github\/actions\/ci-policy@[0-9a-f]{40}/u);
  assert.match(CI, /display_title == "CI workflow_dispatch purpose=exact-sha-preflight"/u);
  assert.match(CI, /uses: actions\/setup-go@[0-9a-f]{40}/u);
  assert.match(CI, /go install github\.com\/rhysd\/actionlint\/cmd\/actionlint@03d0035246f3e81f36aed592ffb4bebf33a03106/u);
  assert.match(CI, /run: actionlint/u);
  assert.match(CI, /name: CI\n\s+needs: \[policy, merge-evidence, preflight-evidence, complete-suite, codeql, post-merge\]/u);
});

test('direct Pages and Worker entrypoints authorize before code or credentials', () => {
  for (const [name, source, privileged] of [
    ['pages.yml', PAGES, ['actions/deploy-pages', 'attest-build-provenance', 'FLEET_DASHBOARD_TOKEN']],
    ['worker.yml', WORKER, ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID']],
  ]) {
    const structure = structureOf(source);
    const policy = structure.indexOf('uses: qwts/playbook-engineering/.github/actions/ci-policy@');
    assert.ok(policy >= 0, `${name}: missing policy action`);
    assert.match(structure, /authorization-only: true/u, `${name}: direct entrypoint must use authorization-only mode`);
    for (const marker of privileged) {
      assert.ok(structure.indexOf(marker) > policy, `${name}: ${marker} is reachable before policy`);
    }
  }
  assert.match(PAGES, /collect:\n\s+needs: policy\n\s+if: needs\.policy\.result == 'success' && github\.ref == 'refs\/heads\/main'/u);
  assert.match(PAGES, /deploy:\n\s+needs: \[policy, collect, build\]/u);
  assert.match(WORKER, /worker:\n\s+name: Worker\n\s+needs: policy\n\s+if: needs\.policy\.result == 'success'/u);
  assert.match(WORKER, /policy:\n\s+name: Action Policy\n\s+if: github\.event_name != 'pull_request' \|\| github\.event\.pull_request\.draft == false/u);
  assert.match(WORKER, /if: github\.ref == 'refs\/heads\/main'/u);
});

test('Advanced CodeQL is reusable and covers both governed languages', () => {
  assert.match(CODEQL, /workflow_call:/u);
  assert.match(CODEQL, /language: \[actions, javascript-typescript\]/u);
  assert.match(CI, /uses: \.\/\.github\/workflows\/codeql\.yml/u);
  assert.match(CI, /security-events: write/u);
});

// Least privilege is the property most easily lost to a passing build: widening
// a permissions block is the first thing that makes a failing step go green.
test('the job holding the fleet credential can do nothing else with it', () => {
  assert.match(STRUCTURE, /^permissions: \{\}$/mu, 'no ambient grants at the workflow level');

  const collect = JOBS.slice(JOBS.indexOf('\n  collect:'), JOBS.indexOf('\n  build:'));
  assert.match(collect, /permissions:\n\s*contents: read\n/u);
  assert.doesNotMatch(collect, /id-token: write/u, 'the PAT holder must not mint an OIDC token');
  assert.doesNotMatch(collect, /pages: write/u, 'the PAT holder must not be able to deploy');

  const deploy = JOBS.slice(JOBS.indexOf('\n  deploy:'));
  assert.doesNotMatch(deploy, /FLEET_DASHBOARD_TOKEN/u, 'the Pages job must never see the PAT');
});

test('checkout never persists the git credential into the working tree', () => {
  const checkouts = [...STRUCTURE.matchAll(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n\s*with:\n\s*persist-credentials: false/gu)];
  const total = [...STRUCTURE.matchAll(/uses: actions\/checkout@/gu)];
  assert.equal(checkouts.length, total.length, 'every checkout must set persist-credentials: false');
});

// A contract spanning two files that nothing at runtime would notice breaking.
// Rename the key on either side and the job output goes empty, the gate's `if`
// evaluates false, and every degraded run is green again — silently, and in the
// reassuring direction. Neither file's own tests can see the other half.
//
// Driven through the real function rather than grepped out of the source: the
// first attempt matched the text and read `\ndegraded_reason` as a key name,
// which is the sort of answer only a source-scraping test can give.
test('the collector writes the output keys the workflow reads', () => {
  const out = join(tmpdir(), `gh-output-contract-${process.pid}.txt`);
  let written;
  try {
    reportDegradation(['1 denied'], out);
    written = readFileSync(out, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => line.slice(0, line.indexOf('=')));
  } finally {
    rmSync(out, { force: true });
  }
  assert.ok(written.length > 0, 'the collector wrote no outputs at all');

  const read = [...STRUCTURE.matchAll(/steps\.collect\.outputs\.(\w+)/gu)].map((m) => m[1]);
  assert.ok(read.length > 0, 'the workflow reads no step outputs');

  for (const key of read) {
    assert.ok(written.includes(key), `pages.yml reads '${key}', which the collector never writes`);
  }
});

// #25. The grant that mints an OIDC token asserting this repository's identity
// must not sit in the job that executes the build toolchain — vite, esbuild, and
// every plugin in the tree. `--ignore-scripts` closes install-time execution and
// does nothing about build-time execution, which is what a bundler is for.
test('the job that signs runs no repository code', () => {
  const attest = JOBS.slice(JOBS.indexOf('\n  attest:'), JOBS.indexOf('\n  deploy:'));
  assert.ok(attest.length > 0, 'the attest job went missing');

  assert.match(attest, /id-token: write/u, 'it has to be able to sign');
  assert.doesNotMatch(attest, /actions\/checkout/u, 'no checkout — nothing to execute');
  assert.doesNotMatch(attest, /actions\/setup-node/u, 'no toolchain');
  assert.doesNotMatch(attest, /npm /u, 'no npm — install or build');
  assert.doesNotMatch(attest, /^\s*(?:- )?run:/mu, 'no shell step at all');

  // Every step is a SHA-pinned GitHub-owned action over files already produced.
  const steps = [...attest.matchAll(/uses:\s*(\S+)/gu)].map((m) => m[1]);
  assert.ok(steps.length >= 2, `expected the attest steps, found ${steps.length}`);
  for (const step of steps) {
    assert.match(step, /^actions\//u, `${step} is not a GitHub-owned action`);
  }
});

test('the job that builds holds no signing grant', () => {
  const build = JOBS.slice(JOBS.indexOf('\n  build:'), JOBS.indexOf('\n  attest:'));
  assert.ok(build.length > 0, 'the build job went missing');

  assert.match(build, /permissions:\n\s*contents: read\n\s*steps:/u, 'contents: read and nothing else');
  assert.doesNotMatch(build, /id-token: write/u, 'the toolchain must not be able to mint an OIDC token');
  assert.doesNotMatch(build, /attestations: write/u, 'the toolchain must not be able to sign');
});

// Attesting from `deploy` would need one job fewer and attest the Pages tarball
// — a single subject instead of many. `data/snapshot.json` would stop being
// individually verifiable, which is the part with actual value for a repo whose
// product is auditable claims.
test('the attestation subject is the individual files, not a tarball', () => {
  const attest = JOBS.slice(JOBS.indexOf('\n  attest:'), JOBS.indexOf('\n  deploy:'));
  assert.match(attest, /subject-path:\s*dist\/\*\*/u);

  const deploy = JOBS.slice(JOBS.indexOf('\n  deploy:'));
  assert.doesNotMatch(deploy, /attest-build-provenance/u, 'attesting there coarsens the subject');
});

// `upload-pages-artifact` tars dist wholesale; plain `upload-artifact`
// defaults to `include-hidden-files: false`. The attestation copy must carry
// the same file set as the deployed one, or the first dotfile someone adds to
// dist — `.well-known/security.txt`, `.vite/manifest.json` — deploys
// unattested, which is the exact gap the attest job exists to close.
test('the attestation copy of dist carries hidden files, like the deployed one', () => {
  const build = JOBS.slice(JOBS.indexOf('\n  build:'), JOBS.indexOf('\n  attest:'));
  assert.match(
    build,
    /name: site\n\s*path: dist\n\s*include-hidden-files: true\n\s*if-no-files-found: error/u,
    'the site artifact must include dotfiles so nothing deploys unattested',
  );
});

// #9. This gate is the one that fails *closed*. The stale and degraded gates
// deploy first and then redden the run, because a legible degraded dashboard
// beats an outage. That trade does not hold here: a snapshot failing validation
// may contain something the redaction contract forbids, and publishing it to
// find out is the entire failure.
test('an artifact that fails the redaction contract is never deployed', () => {
  const collect = JOBS.slice(JOBS.indexOf('\n  collect:'), JOBS.indexOf('\n  build:'));

  const validateAt = collect.indexOf('npm run validate');
  const collectAt = collect.indexOf('npm run collect');
  const handoffAt = collect.indexOf('Hand the fresh snapshot to the build');
  assert.ok(validateAt > 0, 'the collect job never validates the snapshot');
  assert.ok(validateAt > collectAt, 'validation must run after collection');
  assert.ok(handoffAt > validateAt, 'nothing may leave this job before it is validated');

  // The step must be able to fail the job. `continue-on-error` here would turn
  // the one fail-closed gate into another advisory warning.
  const step = collect.slice(collect.indexOf('Validate the snapshot'), handoffAt);
  assert.doesNotMatch(step, /continue-on-error/u, 'the validation gate must fail the job');
});

test('only a run that actually collected may demand a fresh snapshot', () => {
  // The committed fixture is deliberately old — being the fallback is its job —
  // so `--fresh` against it would fail every run where collection failed, in
  // the one situation the fixture exists to cover.
  const collect = JOBS.slice(JOBS.indexOf('\n  collect:'), JOBS.indexOf('\n  build:'));
  assert.match(collect, /FRESH:\s*\$\{\{\s*steps\.collect\.outcome == 'success'\s*\}\}/u);
  assert.match(collect, /npm run validate -- --fresh/u);
  assert.match(collect, /npm run validate\n/u, 'and a plain run for the fixture path');
});

test('the same validator guards CI and the workflow', () => {
  // Two definitions of "is this publishable" drift, and the drift is invisible
  // until one of them is wrong.
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.match(pkg.scripts.ci, /npm run validate/u, 'npm run ci must validate too');
  assert.match(pkg.scripts.validate, /tools\/validate-snapshot\.mjs/u);
  assert.match(STRUCTURE, /npm run validate/u, 'and the workflow runs the same script');
});
