import react from '@vitejs/plugin-react';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { defineConfig, type Plugin, type ServerOptions } from 'vite';

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

/**
 * Dev and build deliberately diverge on the Content-Security-Policy meta.
 *
 * The policy lives in index.html so the built page carries it with no build
 * step to forget, and so tools/page.test.mjs can assert it against the source
 * of truth. But Vite's dev pipeline serves every imported stylesheet as an
 * inline <style> element injected by the module runner, and HMR keeps editing
 * those elements in place. `style-src 'self'` — the directive doing real work
 * in production — blocks all of it: the dev page renders unstyled and CSS
 * hot-reload dies silently.
 *
 * Loosening the policy for dev (an 'unsafe-inline' allowance behind a flag)
 * would put an escape hatch one copy-paste away from the shipped page, which
 * is the failure mode this repo exists to avoid. Stripping the meta from the
 * served transform only — `apply: 'serve'` never runs during `vite build` —
 * keeps the shipped policy byte-identical to what the tests read, at the cost
 * of dev not exercising the CSP. The built page is what `npm run preview`
 * and the browser verification in page.test.mjs are for.
 */
function servedWithoutPolicy(): Plugin {
  return {
    name: 'strip-csp-meta-in-dev',
    apply: 'serve',
    transformIndexHtml(html) {
      return html.replace(/[ \t]*<meta\s+http-equiv="Content-Security-Policy"[\s\S]*?\/>\n?/u, '');
    },
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
    base: process.env.VITE_BASE || '/',
    plugins: [react(), servedWithoutPolicy()],
    server: listenOptions(localTls),
    preview: listenOptions(localTls),
    build: {
      // Enforcement lives in the Worker, so this is hygiene rather than a
      // control: mangle names, drop dev-only calls, and ship no source maps.
      minify: 'terser',
      sourcemap: false,
      terserOptions: {
        compress: {
          drop_console: true,
          drop_debugger: true,
          passes: 2,
        },
        mangle: { toplevel: true },
        format: { comments: false },
      },
    },
  };
});
