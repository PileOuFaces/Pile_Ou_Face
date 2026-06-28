// @ts-nocheck
const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

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

  const svc = mod.AuthService.getInstance(secrets, "http://localhost:8000");

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
});
