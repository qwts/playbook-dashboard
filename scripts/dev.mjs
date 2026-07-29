#!/usr/bin/env node

/**
 * Local HTTPS dev server launcher.
 *
 * Loads the TLS private-key passphrase into DASHBOARD_TLS_KEY_PASSPHRASE from
 * a passphrase file when the env var is unset. The passphrase value is never
 * logged or written to disk by this script.
 *
 * Auth is bypassed locally by default: the /auth/* endpoints live in the
 * Cloudflare Worker, which Vite does not serve. Set VITE_AUTH_DISABLED=0 and
 * run `wrangler dev` in front of this server to exercise the real flow.
 *
 * Defaults:
 *   certs dir:   ~/.quorum/certs
 *   passphrase:  ~/.quorum/certs/key.passphrase  (via DASHBOARD_TLS_KEY_PASSPHRASE_FILE)
 *   listen:      https://local.dev.zts1.com:8443
 *   auth:        disabled (VITE_AUTH_DISABLED=1)
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_CERTS_DIR = path.join(homedir(), '.quorum', 'certs');
const DEFAULT_PORT = '8443';
const DEFAULT_BIND = '127.0.0.1';
const BROWSE_HOST = 'local.dev.zts1.com';
const DEFAULT_AUTH_DISABLED = '1';

function loadPassphraseIntoEnv() {
  if (process.env.DASHBOARD_TLS_KEY_PASSPHRASE) {
    return;
  }

  const passphraseFile =
    process.env.DASHBOARD_TLS_KEY_PASSPHRASE_FILE ||
    path.join(DEFAULT_CERTS_DIR, 'key.passphrase');

  if (!existsSync(passphraseFile)) {
    console.error(
      [
        'Missing TLS key passphrase.',
        'Set DASHBOARD_TLS_KEY_PASSPHRASE (preferred), or point',
        `DASHBOARD_TLS_KEY_PASSPHRASE_FILE at a passphrase file (tried: ${passphraseFile}).`,
      ].join(' '),
    );
    process.exit(1);
  }

  const value = readFileSync(passphraseFile, 'utf8').trim();
  if (!value) {
    console.error(`Passphrase file is empty: ${passphraseFile}`);
    process.exit(1);
  }

  process.env.DASHBOARD_TLS_KEY_PASSPHRASE = value;
}

function main() {
  const viteArgs = process.argv.slice(2);
  // `preview` serves an existing build, where VITE_AUTH_DISABLED was already baked in.
  const isPreview = viteArgs.includes('preview');

  process.env.DASHBOARD_TLS_CERTS_DIR ||= DEFAULT_CERTS_DIR;
  process.env.DASHBOARD_DEV_BIND ||= DEFAULT_BIND;
  process.env.DASHBOARD_DEV_PORT ||= DEFAULT_PORT;
  if (!isPreview) {
    process.env.VITE_AUTH_DISABLED ||= DEFAULT_AUTH_DISABLED;
  }

  loadPassphraseIntoEnv();

  const port = process.env.DASHBOARD_DEV_PORT;
  const authMode = isPreview
    ? 'auth as built'
    : process.env.VITE_AUTH_DISABLED === '1'
      ? 'auth bypassed'
      : 'auth enabled (needs wrangler dev)';
  console.log(
    `Local HTTPS → https://${BROWSE_HOST}:${port}/ (bound ${process.env.DASHBOARD_DEV_BIND}, ${authMode})`,
  );

  const viteBin = path.join(ROOT, 'node_modules', 'vite', 'bin', 'vite.js');
  const child = spawn(process.execPath, [viteBin, ...viteArgs], {
    cwd: ROOT,
    env: process.env,
    stdio: 'inherit',
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

main();
