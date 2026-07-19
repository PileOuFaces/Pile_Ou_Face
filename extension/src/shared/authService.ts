// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file authService.ts
 * @brief Authentification avec le serveur POF Auth. Stocke JWT + content_keys dans SecretStorage.
 */
const vscode = require('vscode');
const {
  generateDeviceKeypair,
  generateDeviceId,
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
const KEY_LEASE_SYNCED_AT    = 'pof.auth.leaseSyncedAt';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

// Mode offline borné (XSYNC-LIC-001, design doc §5) : au-delà de cette durée
// sans synchronisation réussie du lease, les content_keys dérivées du lease
// ne sont plus servies — blocage explicite, pas de fallback permissif indéfini.
const LEASE_OFFLINE_GRACE_MS = 7 * 24 * 3600_000;

class AuthService {
  constructor(secrets, serverUrl) {
    this.secrets = secrets;
    this.serverUrl = serverUrl;
    this._refreshTimer = null;
  }

  static getInstance(secrets, serverUrl) {
    if (!AuthService._instance) {
      AuthService._instance = new AuthService(secrets, serverUrl);
    } else if (serverUrl && serverUrl !== AuthService._instance.serverUrl) {
      AuthService._instance.serverUrl = serverUrl;
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
        await this._store(data.access_token, data.refresh_token, data.content_keys, email);
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
    await this.secrets.delete(KEY_LEASE_SYNCED_AT);
    // La paire de clés d'installation (KEY_DEVICE_*) N'EST PAS effacée : c'est une
    // identité de machine, pas une session utilisateur. Se reconnecter avec un
    // autre compte ré-enrôle le même device_id (voir _syncLicenseLeases).
    this._clearRefreshTimer();
  }

  /**
   * Mode offline borné (design doc §5) : si des content_keys dérivées d'un
   * lease existent mais que la dernière synchronisation réussie remonte à
   * plus de LEASE_OFFLINE_GRACE_MS (7 jours), on refuse de les servir plutôt
   * que de les garder indéfiniment — blocage explicite, pas un fallback
   * permissif. N'affecte pas les content_keys legacy (server pas encore
   * migré) : KEY_LEASE_SYNCED_AT n'est posé que par un vrai succès du
   * chemin lease (_syncLicenseLeases), jamais par le login/refresh legacy.
   */
  async getContentKeys() {
    const raw = await this.secrets.get(KEY_CONTENT_KEYS);
    if (!raw) { return {}; }
    const syncedAtRaw = await this.secrets.get(KEY_LEASE_SYNCED_AT);
    if (syncedAtRaw) {
      const age = Date.now() - Number(syncedAtRaw);
      if (age > LEASE_OFFLINE_GRACE_MS) {
        this._log(`fenêtre offline dépassée (${Math.floor(age / 3600_000)}h) — content_keys refusées`);
        return {};
      }
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
      await this._store(data.access_token, data.refresh_token || refreshToken, data.content_keys);
      await this._syncLicenseLeases(data.access_token);
      this._scheduleRefresh();
      return true;
    } catch { return false; }
  }

  async _store(accessToken, refreshToken, contentKeys, email) {
    await this.secrets.store(KEY_ACCESS_TOKEN, accessToken);
    await this.secrets.store(KEY_REFRESH_TOKEN, refreshToken);
    await this.secrets.store(KEY_CONTENT_KEYS, JSON.stringify(contentKeys));
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
      await this._store(data.access_token, data.refresh_token || refreshToken, data.content_keys || {});
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
        await this.secrets.delete(KEY_LEASE_SYNCED_AT);
        return { refreshed: false, revoked: true };
      }
      // Erreur réseau — mode gracieux, on garde les clés existantes
      return { refreshed: false, revoked: false };
    }
  }

  /**
   * Licence par installation (XSYNC-LIC-001, Pile_Ou_Face#70) : enrôle cette
   * installation puis récupère un lease + DEK enveloppé par plugin autorisé,
   * en remplacement du content_key partagé déjà stocké par _store().
   *
   * Best-effort et silencieux en cas d'échec (serveur pas encore migré,
   * réseau indisponible, etc.) : les content_keys legacy posés par _store()
   * juste avant restent en place — voir le design doc §4 pour la fenêtre
   * de transition auth → host → plugins.
   */
  async _syncLicenseLeases(accessToken) {
    if (!accessToken) return;
    try {
      const { deviceId, privateKeyPem, publicKeyPem } = await this._getOrCreateDeviceIdentity();
      await this._postJsonAuthenticated(this.serverUrl, '/plugins/enroll', accessToken, {
        device_id: deviceId,
        public_key: publicKeyPem,
      });
      const leaseData = await this._postJsonAuthenticated(this.serverUrl, '/plugins/lease', accessToken, {
        device_id: deviceId,
      });
      const jwks = await this._fetchJwks();
      const contentKeys = {};
      for (const [pluginId, entry] of Object.entries(leaseData.plugins || {})) {
        try {
          verifyLeaseJwt(entry.lease, jwks, deviceId, pluginId);
          contentKeys[pluginId] = unwrapDek(entry.wrapped_dek, privateKeyPem);
        } catch (err) {
          // Un lease individuel invalide/expiré ne doit pas faire échouer les
          // autres plugins — celui-ci reste simplement absent des content_keys.
          this._log(`lease invalide pour ${pluginId}: ${err.message}`);
        }
      }
      // Le round-trip enroll+lease+jwks a réussi (indépendamment du nombre de
      // plugins autorisés) : c'est ce qui fait repartir la fenêtre offline à
      // zéro, pas le fait d'avoir des content_keys à écrire.
      await this.secrets.store(KEY_LEASE_SYNCED_AT, String(Date.now()));
      if (Object.keys(contentKeys).length > 0) {
        await this.secrets.store(KEY_CONTENT_KEYS, JSON.stringify(contentKeys));
      }
    } catch (err) {
      this._log(`sync licence par installation ignorée: ${err.message}`);
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

module.exports = { AuthService };
