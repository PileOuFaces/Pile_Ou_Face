// @ts-nocheck
const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

// ---------------------------------------------------------------------------
// Existing suite — loopback fallback
// ---------------------------------------------------------------------------
describe("auth service loopback fallback", () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  function createSecrets() {
    const store = new Map();
    return {
      async get(key) {
        return store.get(key);
      },
      async store(key, value) {
        store.set(key, value);
      },
      async delete(key) {
        store.delete(key);
      },
    };
  }

  it("retries loopback auth on ::1 when localhost resolves to the wrong server", async () => {
    const { AuthService } = proxyquire("../shared/authService", {
      vscode: {},
    });
    AuthService._instance = null;

    const calls = [];
    global.fetch = async (url) => {
      calls.push(String(url));
      if (String(url).startsWith("http://localhost:8000/")) {
        return {
          ok: false,
          async json() {
            return { detail: "Invalid credentials" };
          },
        };
      }
      if (String(url).startsWith("http://[::1]:8000/")) {
        return {
          ok: true,
          async json() {
            return {
              access_token: "access",
              refresh_token: "refresh",
              content_keys: {},
            };
          },
        };
      }
      throw new Error(`unexpected url: ${url}`);
    };

    const service = AuthService.getInstance(createSecrets(), "http://localhost:8000");
    await service.login("test@test.com", "test");

    expect(calls[0]).to.equal("http://localhost:8000/auth/login");
    expect(calls[1]).to.equal("http://[::1]:8000/auth/login");
    expect(service.serverUrl).to.equal("http://[::1]:8000");
  });
});

// ---------------------------------------------------------------------------
// New suite — refreshKeysIfStale() with 24h TTL
// ---------------------------------------------------------------------------

// Fabrique un AuthService avec des secrets stubés en mémoire
function makeAuthService({
  storedKeys = null,
  storedValidatedAt = null,
  refreshResponse = null,
  refreshThrows = false,
  refreshThrows401 = false,
  pluginSearchDirs = [],
} = {}) {
  // Reset du singleton avant chaque usage
  const mod = require("../shared/authService");
  mod.AuthService._instance = null;

  const store = {};
  if (storedKeys) store["pof.auth.contentKeys"] = JSON.stringify(storedKeys);
  if (storedValidatedAt !== null)
    store["pof.auth.keysValidatedAt"] = String(storedValidatedAt);
  store["pof.auth.accessToken"] = "fake-token";
  store["pof.auth.refreshToken"] = "fake-refresh";

  const secrets = {
    _store: store,
    get: sinon.stub().callsFake(async (k) => store[k]),
    store: sinon.stub().callsFake(async (k, v) => {
      store[k] = v;
    }),
    delete: sinon.stub().callsFake(async (k) => {
      delete store[k];
    }),
  };

  const svc = mod.AuthService.getInstance(secrets, "http://localhost:8000", { pluginSearchDirs });

  // Stub _postJson pour contrôler la réponse réseau
  if (refreshThrows) {
    sinon.stub(svc, "_postJson").rejects(new Error("network error"));
  } else if (refreshThrows401) {
    sinon
      .stub(svc, "_postJson")
      .rejects(Object.assign(new Error("Auth failed: 401"), {}));
  } else if (refreshResponse) {
    sinon.stub(svc, "_postJson").resolves(refreshResponse);
  } else {
    sinon
      .stub(svc, "_postJson")
      .resolves({ access_token: "new-token", content_keys: {} });
  }

  return { svc, secrets, store };
}

describe("AuthService.refreshKeysIfStale()", () => {
  const TTL = 24 * 3600_000;

  afterEach(() => {
    sinon.restore();
    const mod = require("../shared/authService");
    mod.AuthService._instance = null;
  });

  it("does NOT refresh when keysValidatedAt is recent (< TTL)", async () => {
    const recent = Date.now() - 1000; // 1 seconde — bien en dessous du TTL
    const { svc } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: recent,
    });

    const result = await svc.refreshKeysIfStale(TTL);

    expect(result.refreshed).to.equal(false);
    expect(result.revoked).to.equal(false);
    expect(svc._postJson.called).to.equal(false);
  });

  it("refreshes when keysValidatedAt is absent", async () => {
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: null,
      refreshResponse: {
        access_token: "new-tok",
        content_keys: { "pof.plugin-x": "new-key==" },
      },
    });
    // Supprimer explicitement le timestamp (ne pas l'avoir stocké)
    delete store["pof.auth.keysValidatedAt"];

    const result = await svc.refreshKeysIfStale(TTL);

    expect(result.refreshed).to.equal(true);
    expect(result.revoked).to.equal(false);
    // keysValidatedAt doit être écrit après le refresh
    expect(store["pof.auth.keysValidatedAt"]).to.exist;
    expect(Number(store["pof.auth.keysValidatedAt"])).to.be.closeTo(
      Date.now(),
      3000
    );
  });

  it("refreshes when keysValidatedAt is older than TTL", async () => {
    const old = Date.now() - TTL - 5000; // dépassé de 5 secondes
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: old,
      refreshResponse: {
        access_token: "new-tok",
        content_keys: { "pof.plugin-x": "fresh==" },
      },
    });

    const result = await svc.refreshKeysIfStale(TTL);

    expect(result.refreshed).to.equal(true);
    expect(result.revoked).to.equal(false);
    expect(Number(store["pof.auth.keysValidatedAt"])).to.be.closeTo(
      Date.now(),
      3000
    );
  });

  it("returns revoked=false on network error (graceful fallback)", async () => {
    const old = Date.now() - TTL - 5000;
    const { svc } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: old,
      refreshThrows: true,
    });

    const result = await svc.refreshKeysIfStale(TTL);

    expect(result.revoked).to.equal(false);
    expect(result.refreshed).to.equal(false);
  });

  it("returns revoked=true and clears content keys on auth error (401)", async () => {
    const old = Date.now() - TTL - 5000;
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: old,
      refreshThrows401: true,
    });

    const result = await svc.refreshKeysIfStale(TTL);

    expect(result.revoked).to.equal(true);
    expect(result.refreshed).to.equal(false);
    // Les clés doivent être supprimées
    expect(store["pof.auth.contentKeys"]).to.equal(undefined);
    expect(store["pof.auth.keysValidatedAt"]).to.equal(undefined);
    expect(store["pof.auth.accessToken"]).to.equal(undefined);
    expect(store["pof.auth.refreshToken"]).to.equal(undefined);
    expect(store["pof.auth.email"]).to.equal(undefined);
  });

  it("stores the rotated refresh_token when the server returns one", async () => {
    const old = Date.now() - TTL - 5000;
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: old,
      refreshResponse: {
        access_token: "new-tok",
        refresh_token: "rotated-refresh",
        content_keys: {},
      },
    });

    await svc.refreshKeysIfStale(TTL);

    expect(store["pof.auth.refreshToken"]).to.equal("rotated-refresh");
  });

  it("keeps the existing refresh token when the server doesn't rotate it (back-compat)", async () => {
    const old = Date.now() - TTL - 5000;
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "key==" },
      storedValidatedAt: old,
      refreshResponse: { access_token: "new-tok", content_keys: {} },
    });

    await svc.refreshKeysIfStale(TTL);

    expect(store["pof.auth.refreshToken"]).to.equal("fake-refresh");
  });
});

// ---------------------------------------------------------------------------
// New suite — refresh() rotation (Pile_ou_Face_auth#9)
// ---------------------------------------------------------------------------
describe("AuthService.refresh() — refresh token rotation", () => {
  afterEach(() => {
    sinon.restore();
    const mod = require("../shared/authService");
    mod.AuthService._instance = null;
  });

  it("stores the rotated refresh_token when the server returns one", async () => {
    const { svc, store } = makeAuthService({
      refreshResponse: {
        access_token: "new-tok",
        refresh_token: "rotated-refresh",
        content_keys: {},
      },
    });

    const ok = await svc.refresh();

    expect(ok).to.equal(true);
    expect(store["pof.auth.refreshToken"]).to.equal("rotated-refresh");
    expect(store["pof.auth.accessToken"]).to.equal("new-tok");
  });

  it("keeps the existing refresh token when the server doesn't rotate it (back-compat)", async () => {
    const { svc, store } = makeAuthService({
      refreshResponse: { access_token: "new-tok", content_keys: {} },
    });

    const ok = await svc.refresh();

    expect(ok).to.equal(true);
    expect(store["pof.auth.refreshToken"]).to.equal("fake-refresh");
  });
});

// ---------------------------------------------------------------------------
// New suite — _syncLicenseLeases() (XSYNC-LIC-001, Pile_Ou_Face#70)
// ---------------------------------------------------------------------------
describe("AuthService._syncLicenseLeases()", () => {
  const tempDirs = [];
  const encryptedPayload = Buffer.from("encrypted-plugin-payload");
  const ciphertextSha256 = crypto.createHash("sha256").update(encryptedPayload).digest("hex");

  function pluginSearchDir(pluginId = "pof.plugin-x", releaseId = "release-test-1") {
    const pluginsDir = fs.mkdtempSync(path.join(os.tmpdir(), "pof-online-license-"));
    const pluginDir = path.join(pluginsDir, "plugin-x");
    fs.mkdirSync(pluginDir);
    fs.writeFileSync(
      path.join(pluginDir, "manifest.json"),
      JSON.stringify({ id: pluginId, licensing: { release_id: releaseId } }),
    );
    fs.writeFileSync(path.join(pluginDir, "payload.enc"), encryptedPayload);
    tempDirs.push(pluginsDir);
    return pluginsDir;
  }

  function b64url(buf) {
    return buf
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  function signLease(payload, signingPrivateKeyPem) {
    const header = { alg: "RS256", typ: "JWT" };
    const headerB64 = b64url(Buffer.from(JSON.stringify(header)));
    const payloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), signingPrivateKeyPem);
    return `${signingInput}.${b64url(signature)}`;
  }

  function serverKeypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const jwk = crypto.createPublicKey(publicKey).export({ format: "jwk" });
    return { publicKey, privateKey, jwks: { keys: [{ kty: "RSA", n: jwk.n, e: jwk.e, kid: "1" }] } };
  }

  afterEach(() => {
    sinon.restore();
    for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
    const mod = require("../shared/authService");
    mod.AuthService._instance = null;
  });

  it("overwrites cached content_keys with freshly lease-derived DEKs on success", async () => {
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "stale-cached-key==" },
      refreshResponse: { access_token: "new-tok" },
      pluginSearchDirs: [pluginSearchDir()],
    });

    const server = serverKeypair();
    sinon.stub(svc, "_fetchJwks").resolves(server.jwks);

    let capturedPublicKey;
    sinon.stub(svc, "_postJsonAuthenticated").callsFake(async (baseUrl, path, token, payload) => {
      if (path === "/plugins/enroll") {
        capturedPublicKey = payload.public_key;
        return { device_id: payload.device_id };
      }
      if (path === "/plugins/lease") {
        const dek = crypto.randomBytes(32);
        const wrapped = crypto.publicEncrypt(
          { key: capturedPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
          dek,
        );
        const now = Math.floor(Date.now() / 1000);
        const lease = signLease(
          { device_id: payload.device_id, plugin_id: "pof.plugin-x", release_id: "release-test-1", ciphertext_sha256: ciphertextSha256, iat: now, exp: now + 3600 },
          server.privateKey,
        );
        return {
          plugins: {
            "pof.plugin-x": { wrapped_dek: wrapped.toString("base64"), lease, release_id: "release-test-1", ciphertext_sha256: ciphertextSha256 },
          },
        };
      }
      throw new Error(`unexpected path: ${path}`);
    });

    await svc.refresh();

    const contentKeys = JSON.parse(store["pof.auth.contentKeys"]);
    expect(contentKeys["pof.plugin-x"]).to.not.equal("stale-cached-key==");
    expect(Buffer.from(contentKeys["pof.plugin-x"], "base64")).to.have.lengthOf(32);
    expect(Number(store["pof.auth.leaseExpiresAt"])).to.be.greaterThan(Date.now());
  });

  it("does not touch cached content_keys when the lease sync fails (no bypass, no legacy fallback)", async () => {
    const { svc, store } = makeAuthService({
      storedKeys: { "pof.plugin-x": "stale-cached-key==" },
      refreshResponse: { access_token: "new-tok" },
    });
    sinon.stub(svc, "_postJsonAuthenticated").rejects(Object.assign(new Error("Not Found"), { status: 404 }));

    const ok = await svc.refresh();

    expect(ok).to.equal(true);
    // _syncLicenseLeases échoue avant d'écrire quoi que ce soit — la valeur
    // en cache reste celle d'avant, ni écrasée ni "réparée" par un repli.
    expect(JSON.parse(store["pof.auth.contentKeys"])).to.deep.equal({ "pof.plugin-x": "stale-cached-key==" });
  });

  it("persists the same device_id across multiple syncs (idempotent identity)", async () => {
    const { svc } = makeAuthService({
      refreshResponse: { access_token: "new-tok", content_keys: {} },
    });
    sinon.stub(svc, "_fetchJwks").resolves({ keys: [] });
    const deviceIds = [];
    sinon.stub(svc, "_postJsonAuthenticated").callsFake(async (baseUrl, path, token, payload) => {
      if (path === "/plugins/enroll") deviceIds.push(payload.device_id);
      if (path === "/plugins/lease") deviceIds.push(payload.device_id);
      return { plugins: {} };
    });

    await svc.refresh();
    await svc.refresh();

    expect(new Set(deviceIds).size).to.equal(1);
  });

  it("keeps no lease expiry when no customer release is installed", async () => {
    const { svc, store } = makeAuthService({
      refreshResponse: { access_token: "new-tok", content_keys: {} },
    });
    sinon.stub(svc, "_fetchJwks").resolves({ keys: [] });
    sinon.stub(svc, "_postJsonAuthenticated").resolves({ plugins: {} });

    await svc.refresh();

    expect(JSON.parse(store["pof.auth.contentKeys"])).to.deep.equal({});
    expect(store["pof.auth.leaseExpiresAt"]).to.equal(undefined);
  });

  it("does NOT set leaseExpiresAt when the sync fails (network error, server down, etc.)", async () => {
    const { svc, store } = makeAuthService({
      refreshResponse: { access_token: "new-tok", content_keys: {} },
    });
    sinon.stub(svc, "_postJsonAuthenticated").rejects(Object.assign(new Error("Not Found"), { status: 404 }));

    await svc.refresh();

    expect(store["pof.auth.leaseExpiresAt"]).to.equal(undefined);
  });
});

// ---------------------------------------------------------------------------
// ONLINE_STANDARD — no grace beyond the signed lease expiration
// ---------------------------------------------------------------------------
describe("AuthService.getContentKeys() — signed lease validity", () => {
  function createSecrets(initial = {}) {
    const store = { ...initial };
    return {
      store,
      secrets: {
        async get(key) { return store[key]; },
        async store(key, value) { store[key] = value; },
        async delete(key) { delete store[key]; },
      },
    };
  }

  afterEach(() => {
    const mod = require("../shared/authService");
    mod.AuthService._instance = null;
  });

  it("serves lease-derived content_keys while the lease is valid", async () => {
    const { secrets } = createSecrets({
      "pof.auth.contentKeys": JSON.stringify({ "pof.x": "key==" }),
      "pof.auth.leaseExpiresAt": String(Date.now() + 60_000),
    });
    const { AuthService } = proxyquire("../shared/authService", { vscode: {} });
    AuthService._instance = null;
    const svc = AuthService.getInstance(secrets, "http://localhost:8000");

    expect(await svc.getContentKeys()).to.deep.equal({ "pof.x": "key==" });
  });

  it("refuses lease-derived content_keys immediately after lease expiration", async () => {
    const { secrets } = createSecrets({
      "pof.auth.contentKeys": JSON.stringify({ "pof.x": "key==" }),
      "pof.auth.leaseExpiresAt": String(Date.now() - 1),
    });
    const { AuthService } = proxyquire("../shared/authService", { vscode: {} });
    AuthService._instance = null;
    const svc = AuthService.getInstance(secrets, "http://localhost:8000");

    expect(await svc.getContentKeys()).to.deep.equal({});
  });

  it("fails closed when leaseExpiresAt is missing", async () => {
    const { secrets } = createSecrets({
      "pof.auth.contentKeys": JSON.stringify({ "pof.x": "key==" }),
    });
    const { AuthService } = proxyquire("../shared/authService", { vscode: {} });
    AuthService._instance = null;
    const svc = AuthService.getInstance(secrets, "http://localhost:8000");

    expect(await svc.getContentKeys()).to.deep.equal({});
  });

  it("clears leaseExpiresAt on logout", async () => {
    const { secrets, store } = createSecrets({
      "pof.auth.refreshToken": "tok",
      "pof.auth.leaseExpiresAt": String(Date.now() + 60_000),
    });
    const { AuthService } = proxyquire("../shared/authService", { vscode: {} });
    AuthService._instance = null;
    const originalFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({}) });
    const svc = AuthService.getInstance(secrets, "http://localhost:8000");

    await svc.logout();
    global.fetch = originalFetch;

    expect(store["pof.auth.leaseExpiresAt"]).to.equal(undefined);
  });
});
