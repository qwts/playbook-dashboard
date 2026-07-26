import react from '@vitejs/plugin-react';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { defineConfig, type ServerOptions } from 'vite';

const DEFAULT_CERTS_DIR = path.join(homedir(), '.quorum', 'certs');
/** Bind address — browse via local.dev.zts1.com (see README /etc/hosts). */
const DEFAULT_BIND = '127.0.0.1';
/** Local HTTPS port — intentionally not 443; documented in README. */
const DEFAULT_PORT = 8443;

function resolveTls(): NonNullable<ServerOptions['https']> {
  const certsDir = process.env.DASHBOARD_TLS_CERTS_DIR || DEFAULT_CERTS_DIR;
  const certPath = process.env.DASHBOARD_TLS_CERT || path.join(certsDir, 'fullchain.pem');
  const keyPath = process.env.DASHBOARD_TLS_KEY || path.join(certsDir, 'key.pem');
  const passphrase = process.env.DASHBOARD_TLS_KEY_PASSPHRASE;

  if (!passphrase) {
    throw new Error(
      'DASHBOARD_TLS_KEY_PASSPHRASE is required for local HTTPS. Run via `npm run dev`, which loads it from the passphrase file into the environment.',
    );
  }

  for (const filePath of [certPath, keyPath]) {
    if (!existsSync(filePath)) {
      throw new Error(`TLS material missing: ${filePath}`);
    }
  }

  return {
    cert: readFileSync(certPath),
    key: readFileSync(keyPath),
    passphrase,
  };
}

function listenOptions(withTls: boolean) {
  return {
    host: process.env.DASHBOARD_DEV_BIND || DEFAULT_BIND,
    port: Number(process.env.DASHBOARD_DEV_PORT || DEFAULT_PORT),
    strictPort: true,
    ...(withTls ? { https: resolveTls() } : {}),
  };
}

export default defineConfig(({ command }) => {
  const localTls = command === 'serve';

  return {
    base: process.env.VITE_BASE || '/playbook-dashboard/',
    plugins: [react()],
    server: listenOptions(localTls),
    preview: listenOptions(localTls),
  };
});
