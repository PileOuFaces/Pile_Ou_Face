// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file authService.ts
 * @brief Authentification avec le serveur POF Auth. Stocke JWT + content_keys dans SecretStorage.
 * Interop réelle avec Pile_ou_Face_auth couverte par le job CI "Auth Licensing Interop E2E"
 * (npm run test:e2e:auth-licensing) ; couverture Windows par "Auth Licensing Windows Unit
 * Tests" — les deux déclenchés uniquement quand ce fichier change.
 */
const vscode = require('vscode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  generateDeviceKeypair,
  generateDeviceId,
  signEnrollmentChallenge,
  unwrapDek,
  verifyLeaseJwt,
} = require('./deviceLicensing');

const KEY_ACCESS_TOKEN  = 'pof.auth.accessToken';
const KEY_REFRESH_TOKEN = 'pof.auth.refreshToken';
const KEY_CONTENT_KEYS  = 'pof.auth.contentKeys';
const KEY_EMAIL             = 'pof.auth.email';
const KEY_KEYS_VALIDATED_AT = 'pof.auth.keysValidatedAt';
const KEY_DEVICE_ID          = 'pof.auth.deviceId';
const KEY_DEVICE_PRIVATE_KEY = 'pof.auth.devicePrivateKey';
const KEY_DEVICE_PUBLIC_KEY  = 'pof.auth.devicePublicKey';
const KEY_LEASE_EXPIRES_AT   = 'pof.auth.leaseExpiresAt';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function discoverInstalledPluginReleases(searchDirs = []) {
  const releases = {};
  for (const pluginsDir of searchDirs) {
    if (!pluginsDir || !fs.existsSync(pluginsDir)) continue;
    let entries = [];
    try { entries = fs.readdirSync(pluginsDir); } catch { continue; }
    for (const entry of entries) {
      const root = path.join(pluginsDir, entry);
      try {
        const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
        const releaseId = String(manifest?.licensing?.release_id || '').trim();
        const pluginId = String(manifest?.id || '').trim();
        if (pluginId && releaseId) releases[pluginId] = releaseId;
      } catch {
        // Les plugins de développement n'ont pas de release client et ne
        // participent pas au protocole ONLINE_STANDARD.
      }
    }
  }
  return releases;
}

function discoverInstalledPluginArtifacts(searchDirs = []) {
  const artifacts = {};
  for (const pluginsDir of searchDirs) {
    if (!pluginsDir || !fs.existsSync(pluginsDir)) continue;
    let entries = [];
    try { entries = fs.readdirSync(pluginsDir); } catch { continue; }
    for (const entry of entries) {
      const root = path.join(pluginsDir, entry);
      try {
        const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
        const releaseId = String(manifest?.licensing?.release_id || '').trim();
        const pluginId = String(manifest?.id || '').trim();
        const payload = fs.readFileSync(path.join(root, 'payload.enc'));
        if (pluginId && releaseId) {
          artifacts[pluginId] = {
            releaseId,
            ciphertextSha256: crypto.createHash('sha256').update(payload).digest('hex'),
          };
        }
      } catch {
        // Un artefact incomplet ne peut recevoir aucune clé de déchiffrement.
      }
    }
  }
  return artifacts;
}

class AuthService {
  constructor(secrets, serverUrl, options = {}) {
    this.secrets = secrets;
    this.serverUrl = serverUrl;
    this._refreshTimer = null;
    this.pluginSearchDirs = Array.isArray(options.pluginSearchDirs)
      ? options.pluginSearchDirs
      : [];
  }

  static getInstance(secrets, serverUrl, options = {}) {
    if (!AuthService._instance) {
      AuthService._instance = new AuthService(secrets, serverUrl, options);
    } else if (serverUrl && serverUrl !== AuthService._instance.serverUrl) {
      AuthService._instance.serverUrl = serverUrl;
    }
    if (Array.isArray(options.pluginSearchDirs)) {
      AuthService._instance.pluginSearchDirs = options.pluginSearchDirs;
    }
    return AuthService._instance;
  }

  async login(email, password) {
    const attempts = this._getCandidateServerUrls();
    let lastError = null;
    for (const baseUrl of attempts) {
      try {
        const data = await this._postJson(baseUrl, '/auth/login', { email, password });
        this.serverUrl = baseUrl;
        await this._store(data.access_token, data.refresh_token, email);
        await this._syncLicenseLeases(data.access_token);
        this._scheduleRefresh();
        return;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error('Connexion échouée');
  }

  async logout() {
    const refreshToken = await this.secrets.get(KEY_REFRESH_TOKEN);
    if (refreshToken) {
      fetch(`${this.serverUrl}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      }).catch(() => {});
    }
    await this.secrets.delete(KEY_ACCESS_TOKEN);
    await this.secrets.delete(KEY_REFRESH_TOKEN);
    await this.secrets.delete(KEY_CONTENT_KEYS);
    await this.secrets.delete(KEY_EMAIL);
    await this.secrets.delete(KEY_KEYS_VALIDATED_AT);
    await this.secrets.delete(KEY_LEASE_EXPIRES_AT);
    // La paire de clés d'installation (KEY_DEVICE_*) N'EST PAS effacée : c'est une
    // identité de machine, pas une session utilisateur. Se reconnecter avec un
    // autre compte ré-enrôle le même device_id (voir _syncLicenseLeases).
    this._clearRefreshTimer();
  }

  /**
   * ONLINE_STANDARD : les DEK ne sont utilisables que pendant la validité du
   * lease signé qui les accompagnait. Il n'existe aucune grâce offline après
   * expiration, ni fallback vers un ancien format de licence.
   */
  async getContentKeys() {
    const raw = await this.secrets.get(KEY_CONTENT_KEYS);
    if (!raw) { return {}; }
    const expiresAtRaw = await this.secrets.get(KEY_LEASE_EXPIRES_AT);
    const expiresAt = expiresAtRaw ? Number(expiresAtRaw) : 0;
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      this._log('lease absent ou expiré — content_keys refusées');
      return {};
    }
    try { return JSON.parse(raw); }
    catch { return {}; }
  }

  async getProfile() {
    const accessToken = await this.secrets.get(KEY_ACCESS_TOKEN);
    if (!accessToken) return null;
    try {
      return await this._getJsonAuthenticated(this.serverUrl, '/auth/me', accessToken);
    } catch {
      return null;
    }
  }

  async getEmail() {
    return (await this.secrets.get(KEY_EMAIL)) || '';
  }

  async getContentKey(pluginId) {
    const keys = await this.getContentKeys();
    return keys[pluginId] ?? null;
  }

  async isAuthenticated() {
    return !!(await this.secrets.get(KEY_ACCESS_TOKEN));
  }

  async refresh() {
    const refreshToken = await this.secrets.get(KEY_REFRESH_TOKEN);
    if (!refreshToken) { return false; }
    try {
      const data = await this._postJson(this.serverUrl, '/auth/refresh', { refresh_token: refreshToken });
      // Le serveur peut faire tourner le refresh token (rotation + détection de
      // réutilisation, cf. Pile_ou_Face_auth#9) — toujours stocker celui renvoyé
      // s'il y en a un, sinon garder l'ancien (compat avec un serveur qui n'a
      // pas encore la rotation).
      await this._store(data.access_token, data.refresh_token || refreshToken);
      await this._syncLicenseLeases(data.access_token);
      this._scheduleRefresh();
      return true;
    } catch { return false; }
  }

  async _store(accessToken, refreshToken, email) {
    await this.secrets.store(KEY_ACCESS_TOKEN, accessToken);
    await this.secrets.store(KEY_REFRESH_TOKEN, refreshToken);
    if (email) await this.secrets.store(KEY_EMAIL, email);
    await this.secrets.store(KEY_KEYS_VALIDATED_AT, String(Date.now()));
  }

  /**
   * Re-valide les clés si le timestamp est absent ou > ttlMs.
   * - refreshed: true si un refresh réseau a réussi
   * - revoked: true si le serveur a répondu 4xx (clés supprimées)
   * En cas d'erreur réseau, retourne { refreshed: false, revoked: false } (mode gracieux).
   */
  async refreshKeysIfStale(ttlMs = 24 * 3600_000) {
    const raw = await this.secrets.get(KEY_KEYS_VALIDATED_AT);
    const validatedAt = raw ? Number(raw) : 0;
    const age = Date.now() - validatedAt;
    if (age < ttlMs) {
      return { refreshed: false, revoked: false };
    }
    const refreshToken = await this.secrets.get(KEY_REFRESH_TOKEN);
    if (!refreshToken) {
      return { refreshed: false, revoked: false };
    }
    try {
      const data = await this._postJson(this.serverUrl, '/auth/refresh', { refresh_token: refreshToken });
      await this._store(data.access_token, data.refresh_token || refreshToken);
      await this._syncLicenseLeases(data.access_token);
      return { refreshed: true, revoked: false };
    } catch (err) {
      const status = err?.status ?? 0;
      const isAuthError = (status >= 400 && status < 500) || String(err?.message || '').includes('Auth failed');
      if (isAuthError) {
        await this.secrets.delete(KEY_ACCESS_TOKEN);
        await this.secrets.delete(KEY_REFRESH_TOKEN);
        await this.secrets.delete(KEY_CONTENT_KEYS);
        await this.secrets.delete(KEY_EMAIL);
        await this.secrets.delete(KEY_KEYS_VALIDATED_AT);
        await this.secrets.delete(KEY_LEASE_EXPIRES_AT);
        return { refreshed: false, revoked: true };
      }
      // Erreur réseau — mode gracieux, on garde les clés existantes
      return { refreshed: false, revoked: false };
    }
  }

  /**
   * Licence par installation (XSYNC-LIC-001, Pile_Ou_Face#70) : enrôle cette
   * installation puis récupère un lease + DEK enveloppé par plugin autorisé.
   * C'est la SEULE voie d'obtention des content_keys — il n'existe plus de
   * modèle content_key partageable brute à retomber dessus (migration sans
   * bypass, voir Pile_ou_Face_auth#24).
   *
   * Un échec réseau n'autorise aucune fenêtre supplémentaire : un DEK déjà
   * reçu reste utilisable uniquement jusqu'à l'expiration de son lease.
   */
  async _syncLicenseLeases(accessToken) {
    if (!accessToken) return;
    try {
      const { deviceId, privateKeyPem, publicKeyPem } = await this._getOrCreateDeviceIdentity();
      const enrollmentChallenge = await this._postJsonAuthenticated(
        this.serverUrl,
        '/plugins/enroll/challenge',
        accessToken,
        {
          device_id: deviceId,
          public_key: publicKeyPem,
        },
      );
      const signature = signEnrollmentChallenge(enrollmentChallenge.challenge, privateKeyPem);
      await this._postJsonAuthenticated(this.serverUrl, '/plugins/enroll', accessToken, {
        challenge_id: enrollmentChallenge.challenge_id,
        signature,
      });
      const installedArtifacts = discoverInstalledPluginArtifacts(this.pluginSearchDirs);
      const installedReleases = Object.fromEntries(
        Object.entries(installedArtifacts).map(([pluginId, artifact]) => [pluginId, artifact.releaseId]),
      );
      if (Object.keys(installedReleases).length === 0) {
        await this.secrets.store(KEY_CONTENT_KEYS, JSON.stringify({}));
        await this.secrets.delete(KEY_LEASE_EXPIRES_AT);
        return;
      }
      const leaseData = await this._postJsonAuthenticated(this.serverUrl, '/plugins/lease', accessToken, {
        device_id: deviceId,
        releases: installedReleases,
      });
      const jwks = await this._fetchJwks();
      const contentKeys = {};
      const leaseExpirations = [];
      for (const [pluginId, entry] of Object.entries(leaseData.plugins || {})) {
        try {
          const expectedReleaseId = installedReleases[pluginId];
          if (!expectedReleaseId) throw new Error('unexpected plugin in lease response');
          const expectedDigest = installedArtifacts[pluginId].ciphertextSha256;
          const leasePayload = verifyLeaseJwt(
            entry.lease,
            jwks,
            deviceId,
            pluginId,
            expectedReleaseId,
            expectedDigest,
          );
          if (entry.release_id !== expectedReleaseId) {
            throw new Error('lease response release_id mismatch');
          }
          if (entry.ciphertext_sha256 !== expectedDigest) {
            throw new Error('lease response ciphertext_sha256 mismatch');
          }
          contentKeys[pluginId] = unwrapDek(entry.wrapped_dek, privateKeyPem);
          leaseExpirations.push(Number(leasePayload.exp) * 1000);
        } catch (err) {
          // Un lease individuel invalide/expiré ne doit pas faire échouer les
          // autres plugins — celui-ci reste simplement absent des content_keys.
          this._log(`lease invalide pour ${pluginId}: ${err.message}`);
        }
      }
      // Remplace aussi le cache par un objet vide : une release installée sans
      // clé correspondante ne doit jamais continuer à utiliser le DEK précédent.
      await this.secrets.store(KEY_CONTENT_KEYS, JSON.stringify(contentKeys));
      if (leaseExpirations.length > 0) {
        await this.secrets.store(KEY_LEASE_EXPIRES_AT, String(Math.min(...leaseExpirations)));
      } else {
        await this.secrets.delete(KEY_LEASE_EXPIRES_AT);
      }
    } catch (err) {
      this._log(`sync licence par installation échouée: ${err.message}`);
    }
  }

  _log(message) {
    // Pas de canal de log injecté dans ce service — évite d'imposer une
    // dépendance vscode.OutputChannel pour un chemin best-effort. À
    // remplacer par un vrai logger si ce chemin devient bruyant en pratique.
    if (typeof console !== 'undefined' && console.warn) {
      console.warn(`[AuthService] ${message}`);
    }
  }

  async _getOrCreateDeviceIdentity() {
    let deviceId = await this.secrets.get(KEY_DEVICE_ID);
    let privateKeyPem = await this.secrets.get(KEY_DEVICE_PRIVATE_KEY);
    let publicKeyPem = await this.secrets.get(KEY_DEVICE_PUBLIC_KEY);
    if (deviceId && privateKeyPem && publicKeyPem) {
      return { deviceId, privateKeyPem, publicKeyPem };
    }
    deviceId = generateDeviceId();
    const keypair = generateDeviceKeypair();
    privateKeyPem = keypair.privateKeyPem;
    publicKeyPem = keypair.publicKeyPem;
    await this.secrets.store(KEY_DEVICE_ID, deviceId);
    await this.secrets.store(KEY_DEVICE_PRIVATE_KEY, privateKeyPem);
    await this.secrets.store(KEY_DEVICE_PUBLIC_KEY, publicKeyPem);
    return { deviceId, privateKeyPem, publicKeyPem };
  }

  async _fetchJwks() {
    const cacheTtlMs = 3600_000;
    if (this._jwksCache && Date.now() - this._jwksCache.fetchedAt < cacheTtlMs) {
      return this._jwksCache.jwks;
    }
    const res = await fetch(`${String(this.serverUrl || '').replace(/\/+$/, '')}/auth/jwks`);
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    const jwks = await res.json();
    this._jwksCache = { jwks, fetchedAt: Date.now() };
    return jwks;
  }

  async _postJsonAuthenticated(baseUrl, path, accessToken, payload) {
    const res = await fetch(`${String(baseUrl || '').replace(/\/+$/, '')}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw Object.assign(new Error(String(err['detail'] ?? `Auth failed: ${res.status}`)), { status: res.status });
    }
    return res.json();
  }

  _scheduleRefresh() {
    this._clearRefreshTimer();
    this._refreshTimer = setTimeout(
      () => { this.refresh().catch(() => {}); },
      55 * 60 * 1000,
    );
  }

  _clearRefreshTimer() {
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }
  }

  _getCandidateServerUrls() {
    const baseUrl = String(this.serverUrl || '').trim();
    let parsed;
    try {
      parsed = new URL(baseUrl);
    } catch (_) {
      return [baseUrl];
    }
    const hostname = String(parsed.hostname || '').trim().toLowerCase();
    if (!LOOPBACK_HOSTS.has(hostname)) {
      return [baseUrl];
    }
    const protocol = parsed.protocol || 'http:';
    const port = parsed.port ? `:${parsed.port}` : '';
    const candidates = [
      `${protocol}//[::1]${port}`,
      `${protocol}//localhost${port}`,
      `${protocol}//127.0.0.1${port}`,
    ];
    return [...new Set([baseUrl, ...candidates])];
  }

  async _postJson(baseUrl, path, payload) {
    const res = await fetch(`${String(baseUrl || '').replace(/\/+$/, '')}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw Object.assign(new Error(String(err['detail'] ?? `Auth failed: ${res.status}`)), { status: res.status });
    }
    return res.json();
  }

  async _getJsonAuthenticated(baseUrl, path, accessToken) {
    const res = await fetch(`${String(baseUrl || '').replace(/\/+$/, '')}${path}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(String(err['detail'] ?? `Auth failed: ${res.status}`));
    }
    return res.json();
  }
}

AuthService._instance = null;

module.exports = {
  AuthService,
  discoverInstalledPluginReleases,
  discoverInstalledPluginArtifacts,
};
