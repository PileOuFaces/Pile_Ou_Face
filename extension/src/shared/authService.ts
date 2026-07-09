// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file authService.ts
 * @brief Authentification avec le serveur POF Auth. Stocke JWT + content_keys dans SecretStorage.
 */
const vscode = require('vscode');

const KEY_ACCESS_TOKEN  = 'pof.auth.accessToken';
const KEY_REFRESH_TOKEN = 'pof.auth.refreshToken';
const KEY_CONTENT_KEYS  = 'pof.auth.contentKeys';
const KEY_EMAIL             = 'pof.auth.email';
const KEY_KEYS_VALIDATED_AT = 'pof.auth.keysValidatedAt';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

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
    this._clearRefreshTimer();
  }

  async getContentKeys() {
    const raw = await this.secrets.get(KEY_CONTENT_KEYS);
    if (!raw) { return {}; }
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
        return { refreshed: false, revoked: true };
      }
      // Erreur réseau — mode gracieux, on garde les clés existantes
      return { refreshed: false, revoked: false };
    }
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
