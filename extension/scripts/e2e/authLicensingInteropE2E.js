// SPDX-License-Identifier: AGPL-3.0-only
/* global fetch */
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
const PLUGINS_REPO_PATH = path.resolve(
  process.env.PLUGINS_REPO_PATH || path.join(EXTENSION_ROOT, '..', '..', 'Pile_ou_Face_plugins'),
);
const PORT = Number(process.env.AUTH_E2E_PORT || 8791);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ADMIN_SECRET = 'e2e-interop-admin-secret';

function expectStatus(error, status, context) {
  assert(error?.status === status, `${context} must fail with ${status} (got ${error?.status || 'no status'})`);
}

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

function runPythonJson(pythonExe, args, env, cwd, stdin = '') {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonExe, args, { cwd, env, stdio: 'pipe' });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    proc.on('close', (code) => {
      if (code !== 0) return reject(new Error(`python exited ${code}: ${stderr || stdout}`));
      try { return resolve(JSON.parse(stdout)); } catch { return reject(new Error(`invalid Python JSON output: ${stdout}\n${stderr}`)); }
    });
    proc.stdin.end(stdin);
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

async function adminDelete(pathname) {
  const res = await fetch(`${BASE_URL}${pathname}`, {
    method: 'DELETE',
    headers: { 'X-Admin-Secret': ADMIN_SECRET },
  });
  if (!res.ok) throw new Error(`admin DELETE ${pathname} failed: ${res.status} ${await res.text()}`);
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
  if (!fs.existsSync(PLUGINS_REPO_PATH)) {
    fail(`plugins repo not found at ${PLUGINS_REPO_PATH} (set PLUGINS_REPO_PATH to override)`);
    return;
  }

  const tmpDbFile = path.join(os.tmpdir(), `pof-auth-e2e-${Date.now()}.db`);
  const tmpPluginRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-plugin-e2e-'));
  const releaseRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-plugin-release-e2e-'));
  const { publicKey, privateKey } = generateServerRsaKeys();
  const env = {
    ...process.env,
    DATABASE_URL: `sqlite:///${tmpDbFile}`,
    JWT_PRIVATE_KEY: privateKey,
    JWT_PUBLIC_KEY: publicKey,
    ADMIN_SECRET,
    // Requis par app/services/content_keys.py (chiffrement des content_keys
    // au repos) — une valeur aléatoire par run suffit, cette base est jetée.
    CONTENT_KEY_ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64url'),
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
    const pluginId = 'pof.vulnerability-audit-pro';
    const releaseId = 'e2e-release-v1';
    const contentKeyB64 = crypto.randomBytes(32).toString('base64');
    const signingKey = path.join(releaseRoot, 'signing-private.pem');
    const signingPublicKey = path.join(releaseRoot, 'signing-public.pem');
    fs.writeFileSync(signingKey, privateKey, { mode: 0o600 });
    fs.writeFileSync(signingPublicKey, publicKey);
    const installedPluginDir = path.join(tmpPluginRoot, pluginId);

    async function runtimeUnlock(contentKeys) {
      return runPythonJson(pythonExe, [
        '-c',
        [
          'import json, sys',
          'from backends.plugins.manifest import load_plugin_manifest',
          'from backends.plugins.runtime import _resolve_effective_plugin_root',
          'manifest = load_plugin_manifest(sys.argv[1])',
          'try:',
          ' root = _resolve_effective_plugin_root(manifest)',
          ' print(json.dumps({"active": True, "root": str(root)}))',
          'except Exception as exc:',
          ' print(json.dumps({"active": False, "error": str(exc)}))',
        ].join('\n'),
        installedPluginDir,
      ], { ...process.env, BINHOST_CONTENT_KEYS_STDIN: '1' }, EXTENSION_ROOT,
      JSON.stringify({ content_keys: contentKeys }));
    }

    async function buildAndInstallRelease(nextReleaseId, nextContentKey) {
      const releaseLicense = path.join(releaseRoot, `${nextReleaseId}.json`);
      const releaseDist = path.join(releaseRoot, `dist-${nextReleaseId}`);
      await runPython(pythonExe, [
        '-m', 'tooling.license_tool', 'create-license', '--plugin-id', pluginId,
        '--licensee', 'E2E Interop', '--private-key', signingKey, '--output', releaseLicense,
        '--license-id', nextReleaseId, '--content-key', nextContentKey,
      ], process.env, PLUGINS_REPO_PATH);
      await runPython(pythonExe, [
        '-m', 'tooling.plugin_builder', '--plugin', 'vulnerability-audit-pro',
        '--release-license', releaseLicense, '--public-key', signingPublicKey,
        '--release-profile', 'bytecode', '--output-dir', releaseDist, '--clean',
      ], process.env, PLUGINS_REPO_PATH);
      const bundlePath = fs.readdirSync(releaseDist)
        .filter((name) => name.endsWith('.pofplug'))
        .map((name) => path.join(releaseDist, name))[0];
      assert(bundlePath, `plugin builder must produce a .pofplug bundle for ${nextReleaseId}`);
      const installResult = await runPythonJson(pythonExe, [
        path.join(EXTENSION_ROOT, 'backends', 'plugins', 'install_plugin.py'),
        '--source', bundlePath, '--target-root', tmpPluginRoot,
      ], process.env, EXTENSION_ROOT);
      assert(installResult.ok === true, `real host installer rejected ${nextReleaseId}: ${installResult.error || 'unknown error'}`);
      const installedManifest = JSON.parse(fs.readFileSync(path.join(installedPluginDir, 'manifest.json'), 'utf8'));
      assert(installedManifest.licensing.release_id === nextReleaseId, `installed bundle must expose ${nextReleaseId}`);
      return crypto.createHash('sha256')
        .update(fs.readFileSync(path.join(installedPluginDir, 'payload.enc'))).digest('hex');
    }

    const ciphertextSha256 = await buildAndInstallRelease(releaseId, contentKeyB64);

    const user = await adminPost('/admin/users', { email, password });
    const subscription = await adminPost('/admin/subscriptions', {
      owner_type: 'user',
      owner_id: user.id,
      plugin_id: pluginId,
    });
    await adminPut('/admin/plugin-keys', {
      plugin_id: pluginId,
      release_id: releaseId,
      content_key: contentKeyB64,
      ciphertext_sha256: ciphertextSha256,
    });

    const { AuthService } = proxyquire(path.join(EXTENSION_ROOT, 'src', 'shared', 'authService'), {
      vscode: {},
    });
    const { signEnrollmentChallenge, unwrapDek } = require(path.join(
      EXTENSION_ROOT, 'src', 'shared', 'deviceLicensing',
    ));
    AuthService._instance = null;
    const secrets = makeInMemorySecrets();
    const svc = AuthService.getInstance(secrets, BASE_URL, { pluginSearchDirs: [tmpPluginRoot] });

    console.log('[authLicensingInteropE2E] logging in against the real auth server');
    await svc.login(email, password);

    const keys = await svc.getContentKeys();
    assert(keys[pluginId] === contentKeyB64, `unwrapped DEK should match the seeded content_key (got ${keys[pluginId]})`);
    console.log('[authLicensingInteropE2E] PASS: real enroll + lease + RSA-OAEP unwrap + JWT verification round-trip matches');

    const initialRefreshToken = await secrets.get('pof.auth.refreshToken');
    const refreshed = await svc.refresh();
    const rotatedRefreshToken = await secrets.get('pof.auth.refreshToken');
    const renewedKeys = await svc.getContentKeys();
    assert(refreshed === true, 'real refresh must succeed');
    assert(rotatedRefreshToken && rotatedRefreshToken !== initialRefreshToken, 'refresh token must rotate');
    assert(renewedKeys[pluginId] === contentKeyB64, 'refresh must renew a usable lease for the installed release');
    console.log('[authLicensingInteropE2E] PASS: refresh token rotation renews the real plugin lease');

    // Une même licence utilisateur peut autoriser plusieurs installations, mais
    // chacune doit recevoir un DEK enveloppé pour sa propre paire RSA.
    const secondSecrets = makeInMemorySecrets();
    const secondSvc = new AuthService(secondSecrets, BASE_URL, { pluginSearchDirs: [tmpPluginRoot] });
    await secondSvc.login(email, password);
    const firstDeviceId = await secrets.get('pof.auth.deviceId');
    const secondDeviceId = await secondSecrets.get('pof.auth.deviceId');
    const firstPrivateKey = await secrets.get('pof.auth.devicePrivateKey');
    const secondPrivateKey = await secondSecrets.get('pof.auth.devicePrivateKey');
    assert(firstDeviceId !== secondDeviceId, 'two installations must use distinct device ids');
    assert(firstPrivateKey !== secondPrivateKey, 'two installations must use distinct private keys');
    assert((await secondSvc.getContentKeys())[pluginId] === contentKeyB64, 'second installation must obtain its own usable DEK');

    const firstAccessToken = await secrets.get('pof.auth.accessToken');
    const secondAccessToken = await secondSecrets.get('pof.auth.accessToken');
    const firstLease = await svc._postJsonAuthenticated(BASE_URL, '/plugins/lease', firstAccessToken, {
      device_id: firstDeviceId,
      releases: { [pluginId]: releaseId },
    });
    const secondLease = await secondSvc._postJsonAuthenticated(BASE_URL, '/plugins/lease', secondAccessToken, {
      device_id: secondDeviceId,
      releases: { [pluginId]: releaseId },
    });
    const firstWrappedDek = firstLease.plugins[pluginId].wrapped_dek;
    const secondWrappedDek = secondLease.plugins[pluginId].wrapped_dek;
    assert(firstWrappedDek !== secondWrappedDek, 'each installation must receive a distinct RSA-OAEP ciphertext');
    assert(unwrapDek(firstWrappedDek, firstPrivateKey) === contentKeyB64, 'first installation must unwrap its own DEK');
    assert(unwrapDek(secondWrappedDek, secondPrivateKey) === contentKeyB64, 'second installation must unwrap its own DEK');
    let crossDeviceUnwrapRejected = false;
    try {
      unwrapDek(firstWrappedDek, secondPrivateKey);
    } catch {
      crossDeviceUnwrapRejected = true;
    }
    assert(crossDeviceUnwrapRejected, 'a wrapped DEK must not be reusable on another installation');
    console.log('[authLicensingInteropE2E] PASS: wrapped DEKs are cryptographically isolated between installations');

    // Un autre tenant sans abonnement ne reçoit aucune clé et ne peut pas
    // s'approprier l'identité déjà enrôlée, même s'il présente une preuve signée.
    const otherEmail = 'e2e-other-tenant@pof-e2e-interop-test.dev';
    const otherPassword = 'e2e-other-tenant-password-123';
    await adminPost('/admin/users', { email: otherEmail, password: otherPassword });
    const otherSecrets = makeInMemorySecrets();
    const otherSvc = new AuthService(otherSecrets, BASE_URL, { pluginSearchDirs: [tmpPluginRoot] });
    await otherSvc.login(otherEmail, otherPassword);
    assert(Object.keys(await otherSvc.getContentKeys()).length === 0, 'tenant without subscription must receive no plugin DEK');
    const otherAccessToken = await otherSecrets.get('pof.auth.accessToken');
    const firstPublicKey = await secrets.get('pof.auth.devicePublicKey');
    const hijackChallenge = await otherSvc._postJsonAuthenticated(
      BASE_URL, '/plugins/enroll/challenge', otherAccessToken,
      { device_id: firstDeviceId, public_key: firstPublicKey },
    );
    let ownershipRejected = false;
    try {
      await otherSvc._postJsonAuthenticated(BASE_URL, '/plugins/enroll', otherAccessToken, {
        challenge_id: hijackChallenge.challenge_id,
        signature: signEnrollmentChallenge(hijackChallenge.challenge, firstPrivateKey),
      });
    } catch (err) {
      expectStatus(err, 409, 'cross-tenant device enrollment');
      ownershipRejected = true;
    }
    assert(ownershipRejected, 'another tenant must not claim an enrolled device id');
    console.log('[authLicensingInteropE2E] PASS: tenant access and device ownership are isolated end-to-end');

    const runtimeState = await runtimeUnlock(keys);
    assert(runtimeState.active === true, `real runtime must unlock the packaged plugin (${runtimeState.error || 'unknown error'})`);
    console.log('[authLicensingInteropE2E] PASS: real ONLINE_STANDARD bundle installs, decrypts and loads in the host runtime');

    const releaseIdV2 = 'e2e-release-v2';
    const contentKeyV2 = crypto.randomBytes(32).toString('base64');
    const ciphertextSha256V2 = await buildAndInstallRelease(releaseIdV2, contentKeyV2);
    await adminPut('/admin/plugin-keys', {
      plugin_id: pluginId,
      release_id: releaseIdV2,
      content_key: contentKeyV2,
      ciphertext_sha256: ciphertextSha256V2,
    });
    assert(await svc.refresh(), 'refresh after installing release v2 must succeed');
    assert(await secondSvc.refresh(), 'second installation refresh after release rotation must succeed');
    const rotatedKeys = await svc.getContentKeys();
    assert(rotatedKeys[pluginId] === contentKeyV2, 'host must replace the v1 DEK with the v2 DEK');
    const runtimeWithOldKey = await runtimeUnlock({ [pluginId]: contentKeyB64 });
    assert(runtimeWithOldKey.active === false, 'v1 DEK must not unlock the v2 bundle');
    const runtimeWithV2Key = await runtimeUnlock(rotatedKeys);
    assert(runtimeWithV2Key.active === true, `v2 DEK must unlock the v2 bundle (${runtimeWithV2Key.error || 'unknown error'})`);
    console.log('[authLicensingInteropE2E] PASS: packaged release rotation replaces the DEK and rejects the previous key');

    await runPython(pythonExe, [
      '-c',
      'import sys; from app.db import SessionLocal; from app.models import PluginContentKey; db=SessionLocal(); row=db.query(PluginContentKey).filter_by(plugin_id=sys.argv[1], release_id=sys.argv[2]).one(); db.delete(row); db.commit(); db.close()',
      pluginId, releaseIdV2,
    ], env, AUTH_REPO_PATH);
    assert(await svc.refresh(), 'auth refresh must still succeed after release removal');
    assert(Object.keys(await svc.getContentKeys()).length === 0, 'removed release must clear the cached DEK at renewal');
    await adminPut('/admin/plugin-keys', {
      plugin_id: pluginId,
      release_id: releaseIdV2,
      content_key: contentKeyV2,
      ciphertext_sha256: ciphertextSha256V2,
    });
    assert(await svc.refresh(), 'refresh after restoring release v2 must succeed');
    assert((await svc.getContentKeys())[pluginId] === contentKeyV2, 'restored release must return only its v2 DEK');
    console.log('[authLicensingInteropE2E] PASS: release withdrawal clears the host cache at lease renewal');

    const realExpiresAt = await secrets.get('pof.auth.leaseExpiresAt');
    await secrets.store('pof.auth.leaseExpiresAt', String(Date.now() - 1));
    const keysAfterExpiration = await svc.getContentKeys();
    assert(Object.keys(keysAfterExpiration).length === 0, 'content_keys must be refused immediately after lease expiration');
    await secrets.store('pof.auth.leaseExpiresAt', realExpiresAt);
    console.log('[authLicensingInteropE2E] PASS: expired lease refuses cached content_keys without offline grace');

    // La révocation doit couper l'émission de nouveaux leases — vérifie que le
    // chemin d'erreur (403) interagit correctement de bout en bout lui aussi,
    // pas seulement le chemin nominal ci-dessus.
    const deviceId = firstDeviceId;
    await adminPost(`/admin/installations/${deviceId}/revoke`, {});
    const accessToken = await secrets.get('pof.auth.accessToken');
    let leaseRejected = false;
    try {
      await svc._postJsonAuthenticated(BASE_URL, '/plugins/lease', accessToken, {
        device_id: deviceId,
        releases: { [pluginId]: releaseId },
      });
    } catch (err) {
      leaseRejected = err.status === 403;
    }
    assert(leaseRejected, 'lease request for a revoked installation must be rejected with 403');
    console.log('[authLicensingInteropE2E] PASS: revoked installation is refused a new lease end-to-end');

    await adminDelete(`/admin/subscriptions/${subscription.id}`);
    const accessWithdrawal = await secondSvc.refreshKeysIfStale(0);
    assert(accessWithdrawal.refreshed === true, 'subscription withdrawal must renew the still-valid auth session and plugin lease');
    assert(accessWithdrawal.revoked === false, 'plugin subscription withdrawal must not revoke the user auth session');
    const keysAfterAccessWithdrawal = await secondSvc.getContentKeys();
    assert(Object.keys(keysAfterAccessWithdrawal).length === 0, 'subscription withdrawal must clear cached plugin keys');
    const runtimeAfterAccessWithdrawal = await runtimeUnlock(keysAfterAccessWithdrawal);
    assert(runtimeAfterAccessWithdrawal.active === false, 'runtime must lock after subscription withdrawal');
    console.log('[authLicensingInteropE2E] PASS: subscription withdrawal clears keys and locks the runtime');
  } catch (err) {
    fail(err.message);
    console.error('---- auth server output ----');
    console.error(serverOutput);
  } finally {
    server.kill('SIGKILL');
    fs.rmSync(tmpDbFile, { force: true });
    fs.rmSync(tmpPluginRoot, { recursive: true, force: true });
    fs.rmSync(releaseRoot, { recursive: true, force: true });
  }
}

main().then(() => {
  // uvicorn (spawn 'pipe') peut laisser des handles stdio ouverts un instant
  // après server.kill(), ce qui empêche Node de sortir de lui-même même si
  // le script est logiquement terminé — observé en CI (le job restait
  // "in_progress" indéfiniment alors que les deux PASS s'étaient déjà
  // affichés). Sortie explicite pour ne pas dépendre du nettoyage des
  // handles du child process.
  process.exit(process.exitCode || 0);
});
