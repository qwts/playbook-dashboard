import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assessPermissions,
  assessPinning,
  assessTriggers,
  assessWorkflowFile,
  assessWorkflows,
  combineStatuses,
} from './pillars.mjs';

// Every reason code gets a fixture exhibiting it and a corrected twin that
// passes — the check suite doubles as the curriculum (#15's discipline), so a
// detector change that stops seeing a red flag fails a test that names it.

const SHA = 'a'.repeat(40);

// --- pinning ---------------------------------------------------------------

test('unpinned-third-party: a mutable third-party tag fails', () => {
  const flagged = assessWorkflowFile(`
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
      - uses: some-vendor/setup-tool@v2
`);
  assert.deepEqual(flagged.pinning, { status: 'fail', reason: 'unpinned-third-party' });

  const corrected = assessWorkflowFile(`
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
      - uses: some-vendor/setup-tool@${SHA}
`);
  assert.deepEqual(corrected.pinning, { status: 'pass', reason: null });
});

test('unpinned-first-party: a mutable first-party tag warns, and only warns', () => {
  for (const owner of ['actions', 'github', 'qwts']) {
    const doc = { jobs: { a: { steps: [{ uses: `${owner}/thing@v4` }] } } };
    assert.deepEqual(
      assessPinning(doc),
      { status: 'warn', reason: 'unpinned-first-party' },
      `${owner} should be first-party`,
    );
  }
});

test('pinning: a third-party unpinned ref outranks a first-party one', () => {
  const doc = {
    jobs: {
      a: { steps: [{ uses: 'actions/checkout@v4' }, { uses: 'vendor/tool@main' }] },
    },
  };
  assert.deepEqual(assessPinning(doc), { status: 'fail', reason: 'unpinned-third-party' });
});

test('pinning: local references have no ref to pin and are exempt', () => {
  const doc = { jobs: { a: { steps: [{ uses: './.github/actions/local-thing' }] } } };
  assert.deepEqual(assessPinning(doc), { status: 'pass', reason: null });
});

test('pinning: docker references pin by full digest, and nothing less', () => {
  const pinned = { jobs: { a: { steps: [{ uses: `docker://alpine@sha256:${'a'.repeat(64)}` }] } } };
  assert.equal(assessPinning(pinned).status, 'pass');

  const floating = { jobs: { a: { steps: [{ uses: 'docker://alpine:3.20' }] } } };
  assert.deepEqual(assessPinning(floating), { status: 'fail', reason: 'unpinned-third-party' });

  // A truncated digest is not immutable; "contains @sha256:" must not pass it.
  const truncated = { jobs: { a: { steps: [{ uses: 'docker://alpine@sha256:deadbeef' }] } } };
  assert.deepEqual(assessPinning(truncated), { status: 'fail', reason: 'unpinned-third-party' });
});

test('pinning: reusable-workflow refs at job level are assessed too', () => {
  const doc = { jobs: { call: { uses: 'qwts/playbook-engineering/.github/workflows/docs.yml@v1' } } };
  assert.deepEqual(assessPinning(doc), { status: 'warn', reason: 'unpinned-first-party' });
});

// --- permissions -----------------------------------------------------------

test('write-all: the blanket grant fails at workflow and job level alike', () => {
  const workflowLevel = assessWorkflowFile(`
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps: []
`);
  assert.deepEqual(workflowLevel.permissions, { status: 'fail', reason: 'write-all' });

  const jobLevel = { jobs: { a: { permissions: 'write-all' } } };
  assert.deepEqual(assessPermissions(jobLevel), { status: 'fail', reason: 'write-all' });
});

test('no-permissions-block: an absent block warns; workflow-level or every-job coverage passes', () => {
  const absent = { on: 'push', jobs: { a: {}, b: {} } };
  assert.deepEqual(assessPermissions(absent), { status: 'warn', reason: 'no-permissions-block' });

  const workflowLevel = { on: 'push', permissions: { contents: 'read' }, jobs: { a: {} } };
  assert.deepEqual(assessPermissions(workflowLevel), { status: 'pass', reason: null });

  const everyJob = {
    on: 'push',
    jobs: { a: { permissions: { contents: 'read' } }, b: { permissions: {} } },
  };
  assert.deepEqual(assessPermissions(everyJob), { status: 'pass', reason: null });

  const oneJobShort = {
    on: 'push',
    jobs: { a: { permissions: { contents: 'read' } }, b: {} },
  };
  assert.deepEqual(assessPermissions(oneJobShort), { status: 'warn', reason: 'no-permissions-block' });
});

test('permissions: an empty explicit block is the strictest grant and passes', () => {
  const doc = { on: 'push', permissions: {}, jobs: { a: {} } };
  assert.equal(assessPermissions(doc).status, 'pass');
});

// --- triggers --------------------------------------------------------------

const PR_TARGET_CHECKOUT = `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`;

test('privileged-trigger-checkout: pr_target checking out the PR head fails', () => {
  const flagged = assessWorkflowFile(PR_TARGET_CHECKOUT);
  assert.deepEqual(flagged.triggers, { status: 'fail', reason: 'privileged-trigger-checkout' });
});

test('secrets-in-privileged-trigger: tainted checkout plus secrets is the worst verdict', () => {
  const flagged = assessWorkflowFile(`
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          ref: \${{ github.head_ref }}
      - run: ./deploy.sh
        env:
          TOKEN: \${{ secrets.DEPLOY_TOKEN }}
`);
  assert.deepEqual(flagged.triggers, { status: 'fail', reason: 'secrets-in-privileged-trigger' });
});

test('privileged-trigger: the trigger alone warns — trusted base code with secrets is the intended pattern', () => {
  const labeler = assessWorkflowFile(`
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@${SHA}
        with:
          repo-token: \${{ secrets.GITHUB_TOKEN }}
`);
  assert.deepEqual(labeler.triggers, { status: 'warn', reason: 'privileged-trigger' });
});

test('triggers: a checkout of the base ref under pr_target is not tainted', () => {
  const based = assessWorkflowFile(`
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
      - run: npm test
`);
  assert.deepEqual(based.triggers, { status: 'warn', reason: 'privileged-trigger' });
});

test('triggers: plain pull_request passes — fork PRs get no secrets and a read token', () => {
  const corrected = assessWorkflowFile(`
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`);
  assert.deepEqual(corrected.triggers, { status: 'pass', reason: null });
});

test('triggers: workflow_run is privileged in every on-spelling', () => {
  for (const doc of [
    { on: 'workflow_run', jobs: {} },
    { on: ['push', 'workflow_run'], jobs: {} },
    { on: { workflow_run: { workflows: ['CI'] } }, jobs: {} },
  ]) {
    assert.equal(assessTriggers(doc, '').status, 'warn', JSON.stringify(doc.on));
  }
});

// --- parse failure and combination ----------------------------------------

test('a file that will not parse is unknown for every pillar, never a pass', () => {
  assert.equal(assessWorkflowFile('on: [push\n  broken yaml'), null);
  assert.equal(assessWorkflowFile('just a scalar'), null);

  const posture = assessWorkflows(['on: [push\n  broken yaml']);
  for (const pillar of ['pinning', 'permissions', 'triggers']) {
    assert.deepEqual(posture[pillar], { status: null, reason: null }, pillar);
  }
});

test('combination: fail > warn > null > pass, and unknown poisons only the pass', () => {
  assert.equal(combineStatuses(['pass', 'pass']), 'pass');
  assert.equal(combineStatuses(['pass', null]), null);
  assert.equal(combineStatuses(['warn', null]), 'warn');
  assert.equal(combineStatuses(['fail', null, 'warn']), 'fail');
  assert.equal(combineStatuses([]), 'pass');
});

test('an incomplete read cannot claim a pass, but a fail already found stands', () => {
  const clean = `
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
`;
  const complete = assessWorkflows([clean], { complete: true });
  assert.equal(complete.pinning.status, 'pass');

  const partial = assessWorkflows([clean], { complete: false });
  assert.equal(partial.pinning.status, null, 'a pass degraded to unknown');

  const partialWithFail = assessWorkflows([clean, PR_TARGET_CHECKOUT], { complete: false });
  assert.deepEqual(partialWithFail.triggers, {
    status: 'fail',
    reason: 'privileged-trigger-checkout',
  });
});

test('a defect in one file is not laundered by a clean neighbour', () => {
  const clean = `
on: push
permissions: {}
jobs:
  a:
    steps:
      - uses: actions/checkout@${SHA}
`;
  const unpinned = `
on: push
permissions: {}
jobs:
  a:
    steps:
      - uses: vendor/tool@v1
`;
  const posture = assessWorkflows([clean, unpinned]);
  assert.deepEqual(posture.pinning, { status: 'fail', reason: 'unpinned-third-party' });
  assert.equal(posture.permissions.status, 'pass');
});

test('nothing from file content reaches a reason — codes come from the closed vocabulary', () => {
  const hostile = `
on: pull_request_target
jobs:
  a:
    steps:
      - uses: evil-\${{ secrets.LEAK }}/tool@v1
      - run: echo \${{ github.event.pull_request.title }}
`;
  const posture = assessWorkflows([hostile]);
  for (const pillar of ['pinning', 'permissions', 'triggers']) {
    const { reason } = posture[pillar];
    if (reason !== null) {
      assert.doesNotMatch(reason, /secrets|evil|LEAK/u, `${pillar} reason leaked content`);
    }
  }
});

// --- review round: the two P1s and their corrected twins --------------------

test('a checkout selecting the attacker fork by repository is tainted, ref or no ref', () => {
  const flagged = assessWorkflowFile(`
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          repository: \${{ github.event.pull_request.head.repo.full_name }}
      - run: npm test
`);
  assert.deepEqual(flagged.triggers, { status: 'fail', reason: 'privileged-trigger-checkout' });

  const corrected = assessWorkflowFile(`
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${SHA}
        with:
          repository: qwts/known-repo
      - run: npm test
`);
  assert.deepEqual(corrected.triggers, { status: 'warn', reason: 'privileged-trigger' });
});

test('a parser warning is silenced, not copied into a public log', async () => {
  // The default logLevel routes warnings (e.g. an unresolved custom tag)
  // through process.emitWarning, and the diagnostic quotes the offending
  // source line — untrusted workflow content into a public Actions log. The
  // catch cannot intercept it because nothing throws. Verified here: parse
  // the tag-bearing document, drain the async warning queue, and assert no
  // warning fired.
  const warnings = [];
  const listener = (warning) => warnings.push(String(warning));
  process.on('warning', listener);
  try {
    const posture = assessWorkflowFile('secret: !vault s3cr3t-value\non: push\njobs: {}');
    assert.notEqual(posture, null, 'an unresolved tag is a warning, not a parse failure');
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(warnings, [], 'parser diagnostics must never reach a log');
  } finally {
    process.removeListener('warning', listener);
  }
});
