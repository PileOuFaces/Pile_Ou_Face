// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file authLicensingInteropE2E.js
 * @brief Vrai test d'interopérabilité host <-> auth pour XSYNC-LIC-001 (Pile_Ou_Face#70).
 *
 * Contrairement aux tests unitaires (authService.test.ts, deviceLicensing.test.ts,
 * Pile_ou_Face_auth/tests/test_plugin_licensing.py) qui stubent chacun leur côté du
 * réseau, ce script démarre un VRAI serveur auth (uvicorn, process Python séparé) et
 * fait dialoguer le vrai AuthService (Node) avec lui : login, enroll, lease, puis
 * déchiffrement du DEK enveloppé (RSA-OAEP) et vérification du lease (JWT RS256).
 *
 * C'est le seul test qui peut détecter une incompatibilité crypto/JWT entre les deux
 * langages (ex. format PEM différent, encodage JWT non compatible entre `python-jose`
 * et la vérification manuelle côté Node dans deviceLicensing.ts) — les tests unitaires
 * de chaque côté ne peuvent pas la voir puisqu'ils ne parlent jamais vraiment entre eux.
 *
 * Usage: npm run test:e2e:auth-licensing
 * Nécessite le repo sibling Pile_ou_Face_auth avec un .venv déjà installé
 * (AUTH_REPO_PATH pour surcharger le chemin par défaut).
 */
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const proxyquire = require('proxyquire').noCallThru();

const EXTENSION_ROOT = path.join(__dirname, '..', '..');
const AUTH_REPO_PATH = path.resolve(
  process.env.AUTH_REPO_PATH || path.join(EXTENSION_ROOT, '..', '..', 'Pile_ou_Face_auth'),
);
const PORT = Number(process.env.AUTH_E2E_PORT || 8791);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ADMIN_SECRET = 'e2e-interop-admin-secret';

function fail(message) {
  console.error(`[authLicensingInteropE2E] FAIL: ${message}`);
  process.exitCode = 1;
}

function assert(condition, message) {
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

function generateServerRsaKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  return { publicKey, privateKey };
}

function pythonBin() {
  const venvPython = path.join(AUTH_REPO_PATH, '.venv', 'bin', 'python');
  if (fs.existsSync(venvPython)) return venvPython;
  return process.env.PYTHON || 'python3';
}

async function waitForHealth(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (res.ok) return;
    } catch { /* pas encore prêt */ }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`auth server did not become healthy within ${timeoutMs}ms`);
}

function runPython(pythonExe, args, env, cwd) {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonExe, args, { cwd, env, stdio: 'pipe' });
    let stderr = '';
    proc.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    proc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`python exited ${code}: ${stderr}`));
    });
  });
}

async function adminPost(pathname, body) {
  const res = await fetch(`${BASE_URL}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': ADMIN_SECRET },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`admin POST ${pathname} failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function adminPut(pathname, body) {
  const res = await fetch(`${BASE_URL}${pathname}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': ADMIN_SECRET },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`admin PUT ${pathname} failed: ${res.status} ${await res.text()}`);
  return res.json();
}

function makeInMemorySecrets() {
  const store = new Map();
  return {
    async get(key) { return store.get(key); },
    async store(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
  };
}

async function main() {
  if (!fs.existsSync(AUTH_REPO_PATH)) {
    fail(`auth repo not found at ${AUTH_REPO_PATH} (set AUTH_REPO_PATH to override) — skipping`);
    return;
  }

  const tmpDbFile = path.join(os.tmpdir(), `pof-auth-e2e-${Date.now()}.db`);
  const { publicKey, privateKey } = generateServerRsaKeys();
  const env = {
    ...process.env,
    DATABASE_URL: `sqlite:///${tmpDbFile}`,
    JWT_PRIVATE_KEY: privateKey,
    JWT_PUBLIC_KEY: publicKey,
    ADMIN_SECRET,
    ENV: 'prod', // clés réelles fournies — pas besoin du repli dev
    LOG_LEVEL: 'WARNING',
  };
  const pythonExe = pythonBin();

  console.log(`[authLicensingInteropE2E] creating schema in ${tmpDbFile}`);
  await runPython(
    pythonExe,
    ['-c', 'from app.db import Base, engine; import app.models; Base.metadata.create_all(engine)'],
    env,
    AUTH_REPO_PATH,
  );

  console.log(`[authLicensingInteropE2E] starting auth server on ${BASE_URL}`);
  const server = spawn(
    pythonExe,
    ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(PORT)],
    { cwd: AUTH_REPO_PATH, env, stdio: 'pipe' },
  );
  let serverOutput = '';
  server.stdout.on('data', (c) => { serverOutput += c.toString(); });
  server.stderr.on('data', (c) => { serverOutput += c.toString(); });

  try {
    await waitForHealth();

    const email = 'e2e-interop@pof-e2e-interop-test.dev';
    const password = 'e2e-interop-password-123';
    const pluginId = 'pof.e2e-interop-plugin';
    const contentKeyB64 = crypto.randomBytes(32).toString('base64');

    const user = await adminPost('/admin/users', { email, password });
    await adminPost('/admin/subscriptions', {
      owner_type: 'user',
      owner_id: user.id,
      plugin_id: pluginId,
    });
    await adminPut('/admin/plugin-keys', { plugin_id: pluginId, content_key: contentKeyB64 });

    const { AuthService } = proxyquire(path.join(EXTENSION_ROOT, 'src', 'shared', 'authService'), {
      vscode: {},
    });
    AuthService._instance = null;
    const secrets = makeInMemorySecrets();
    const svc = AuthService.getInstance(secrets, BASE_URL);

    console.log('[authLicensingInteropE2E] logging in against the real auth server');
    await svc.login(email, password);

    const keys = await svc.getContentKeys();
    assert(keys[pluginId] === contentKeyB64, `unwrapped DEK should match the seeded content_key (got ${keys[pluginId]})`);
    console.log('[authLicensingInteropE2E] PASS: real enroll + lease + RSA-OAEP unwrap + JWT verification round-trip matches');

    // Mode offline borné (design doc §5) : au-delà de 7 jours sans sync réussie,
    // les content_keys dérivées du lease ne doivent plus être servies, même si
    // elles sont toujours en cache. On simule le vieillissement du timestamp
    // (attendre 7 jours pour de vrai n'est pas praticable dans un test).
    const realSyncedAt = await secrets.get('pof.auth.leaseSyncedAt');
    await secrets.store('pof.auth.leaseSyncedAt', String(Date.now() - 8 * 24 * 3600_000));
    const keysAfterOfflineWindow = await svc.getContentKeys();
    assert(Object.keys(keysAfterOfflineWindow).length === 0, 'content_keys must be refused once the 7-day offline window is exceeded');
    await secrets.store('pof.auth.leaseSyncedAt', realSyncedAt);
    console.log('[authLicensingInteropE2E] PASS: bounded offline window refuses stale lease-derived content_keys');

    // La révocation doit couper l'émission de nouveaux leases — vérifie que le
    // chemin d'erreur (403) interagit correctement de bout en bout lui aussi,
    // pas seulement le chemin nominal ci-dessus.
    const deviceId = await secrets.get('pof.auth.deviceId');
    await adminPost(`/admin/installations/${deviceId}/revoke`, {});
    const accessToken = await secrets.get('pof.auth.accessToken');
    let leaseRejected = false;
    try {
      await svc._postJsonAuthenticated(BASE_URL, '/plugins/lease', accessToken, { device_id: deviceId });
    } catch (err) {
      leaseRejected = err.status === 403;
    }
    assert(leaseRejected, 'lease request for a revoked installation must be rejected with 403');
    console.log('[authLicensingInteropE2E] PASS: revoked installation is refused a new lease end-to-end');
  } catch (err) {
    fail(err.message);
    console.error('---- auth server output ----');
    console.error(serverOutput);
  } finally {
    server.kill();
    fs.rmSync(tmpDbFile, { force: true });
  }
}

main();
