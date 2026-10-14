// SPDX-License-Identifier: AGPL-3.0-only
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
const { discoverAuthServer } = require('./authDiscovery');
const {
  generateDeviceKeypair,
  generateDeviceId,
  getJwtSubject,
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
const KEY_SERVER_BINDING      = 'pof.auth.serverBinding.v1';
const SECRET_KEYS = Object.freeze([
  KEY_ACCESS_TOKEN,
  KEY_REFRESH_TOKEN,
  KEY_CONTENT_KEYS,
  KEY_EMAIL,
  KEY_KEYS_VALIDATED_AT,
  KEY_DEVICE_ID,
  KEY_DEVICE_PRIVATE_KEY,
  KEY_DEVICE_PUBLIC_KEY,
  KEY_LEASE_EXPIRES_AT,
]);
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

type ServerIdentity = Awaited<ReturnType<typeof discoverAuthServer>>;

interface SecretStore {
  get(key: string): PromiseLike<string | undefined>;
  store(key: string, value: string): PromiseLike<void>;
  delete(key: string): PromiseLike<void>;
}

interface AuthServiceOptions {
  deploymentProfile?: string;
  pluginSearchDirs?: string[];
}

interface AuthTokenResponse {
  access_token: string;
  refresh_token: string;
}

interface RefreshTokenResponse {
  access_token: string;
  refresh_token?: string;
}

interface AuthProfile {
  active_plugin_ids?: unknown[];
  [key: string]: unknown;
}

interface PluginArtifact {
  releaseId: string;
  ciphertextSha256: string;
}

interface EnrollmentChallengeResponse {
  challenge: string;
  challenge_id: string;
}

interface LeaseEntry {
  lease: string;
  release_id: string;
  ciphertext_sha256: string;
  wrapped_dek: string;
}

interface LeaseResponse {
  plugins?: Record<string, LeaseEntry>;
}

interface ServerBinding {
  profile?: string;
  origin?: string;
  namespace?: string;
}

interface StatusError extends Error {
  status?: number;
}

function discoverInstalledPluginReleases(searchDirs: readonly string[] = []): Record<string, string> {
  const releases: Record<string, string> = {};
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

function discoverInstalledPluginArtifacts(
  searchDirs: readonly string[] = [],
): Record<string, PluginArtifact> {
  const artifacts: Record<string, PluginArtifact> = {};
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
  declare static _instance: AuthService | null;

  declare private readonly _rawSecrets: SecretStore;
  declare serverUrl: string;
  declare readonly deploymentProfile: string;
  declare private readonly _secretIsolationEnabled: boolean;
  declare private _secretNamespace: string;
  declare private readonly secrets: SecretStore;
  declare private _refreshTimer: NodeJS.Timeout | null;
  declare pluginSearchDirs: string[];
  declare private _serverIdentity: ServerIdentity | null | undefined;
  declare private _jwksCache: { jwks: unknown; fetchedAt: number } | null | undefined;

  constructor(secrets: SecretStore, serverUrl: string, options: AuthServiceOptions = {}) {
    this._rawSecrets = secrets;
    this.serverUrl = serverUrl;
    this.deploymentProfile = String(options.deploymentProfile || '').trim();
    this._secretIsolationEnabled = Boolean(this.deploymentProfile);
    this._secretNamespace = '';
    this.secrets = this._secretIsolationEnabled ? {
      get: async (key) => this._rawSecrets.get(await this._resolveSecretKey(key)),
      store: async (key, value) => this._rawSecrets.store(await this._resolveSecretKey(key), value),
      delete: async (key) => this._rawSecrets.delete(await this._resolveSecretKey(key)),
    } : secrets;
    this._refreshTimer = null;
    this.pluginSearchDirs = Array.isArray(options.pluginSearchDirs)
      ? options.pluginSearchDirs
      : [];
  }

  static getInstance(
    secrets: SecretStore,
    serverUrl: string,
    options: AuthServiceOptions = {},
  ): AuthService {
    if (!AuthService._instance) {
      AuthService._instance = new AuthService(secrets, serverUrl, options);
    } else if (serverUrl && serverUrl !== AuthService._instance.serverUrl) {
      AuthService._instance.serverUrl = serverUrl;
      AuthService._instance._serverIdentity = null;
      AuthService._instance._jwksCache = null;
      AuthService._instance._secretNamespace = '';
    }
    if (Array.isArray(options.pluginSearchDirs)) {
      AuthService._instance.pluginSearchDirs = options.pluginSearchDirs;
    }
    return AuthService._instance;
  }

  getDeploymentStatus(configuredDeploymentId = ''): {
    profile: string;
    origin: string;
    deploymentId: string;
    verified: boolean;
  } {
    return {
      profile: this.deploymentProfile,
      origin: String(this._serverIdentity?.origin || this.serverUrl || '').replace(/\/+$/, ''),
      deploymentId: String(
        this._serverIdentity?.deployment_id || configuredDeploymentId || '',
      ).trim(),
      verified: Boolean(this._serverIdentity),
    };
  }

  async login(email: string, password: string): Promise<void> {
    const attempts = this._getCandidateServerUrls();
    let lastError: unknown = null;
    for (const baseUrl of attempts) {
      try {
        await this._ensureServerIdentity(baseUrl);
        const data = await this._postJson<AuthTokenResponse>(baseUrl, '/auth/login', { email, password });
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

  async logout(): Promise<void> {
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
  async getContentKeys(): Promise<Record<string, string>> {
    const raw = await this.secrets.get(KEY_CONTENT_KEYS);
    if (!raw) { return {}; }
    const expiresAtRaw = await this.secrets.get(KEY_LEASE_EXPIRES_AT);
    const expiresAt = expiresAtRaw ? Number(expiresAtRaw) : 0;
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      this._log('lease absent ou expiré — content_keys refusées');
      return {};
    }
    try { return JSON.parse(raw) as Record<string, string>; }
    catch { return {}; }
  }

  async getProfile(): Promise<AuthProfile | null> {
    const accessToken = await this.secrets.get(KEY_ACCESS_TOKEN);
    if (!accessToken) return null;
    try {
      return await this._getJsonAuthenticated<AuthProfile>(this.serverUrl, '/auth/me', accessToken);
    } catch {
      return null;
    }
  }

  async getEmail(): Promise<string> {
    return (await this.secrets.get(KEY_EMAIL)) || '';
  }

  async getContentKey(pluginId: string): Promise<string | null> {
    const keys = await this.getContentKeys();
    return keys[pluginId] ?? null;
  }

  async isAuthenticated(): Promise<boolean> {
    return !!(await this.secrets.get(KEY_ACCESS_TOKEN));
  }

  async refresh(): Promise<boolean> {
    if (this._secretIsolationEnabled) {
      try { await this._ensureServerIdentity(this.serverUrl); }
      catch { return false; }
    }
    const refreshToken = await this.secrets.get(KEY_REFRESH_TOKEN);
    if (!refreshToken) { return false; }
    try {
      await this._ensureServerIdentity(this.serverUrl);
      const data = await this._postJson<RefreshTokenResponse>(
        this.serverUrl,
        '/auth/refresh',
        { refresh_token: refreshToken },
      );
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

  private async _store(accessToken: string, refreshToken: string, email?: string): Promise<void> {
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
  async refreshKeysIfStale(
    ttlMs = 24 * 3600_000,
  ): Promise<{ refreshed: boolean; revoked: boolean }> {
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
      const data = await this._postJson<RefreshTokenResponse>(
        this.serverUrl,
        '/auth/refresh',
        { refresh_token: refreshToken },
      );
      await this._store(data.access_token, data.refresh_token || refreshToken);
      await this._syncLicenseLeases(data.access_token);
      return { refreshed: true, revoked: false };
    } catch (err) {
      const status = err instanceof Error && 'status' in err
        ? Number((err as StatusError).status || 0)
        : 0;
      const message = err instanceof Error ? err.message : String(err || '');
      const isAuthError = (status >= 400 && status < 500) || message.includes('Auth failed');
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
  private async _syncLicenseLeases(accessToken: string): Promise<void> {
    if (!accessToken) return;
    try {
      const { deviceId, privateKeyPem, publicKeyPem } = await this._getOrCreateDeviceIdentity();
      const enrollmentChallenge = await this._postJsonAuthenticated<EnrollmentChallengeResponse>(
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
      const leaseData = await this._postJsonAuthenticated<LeaseResponse>(
        this.serverUrl,
        '/plugins/lease',
        accessToken,
        { device_id: deviceId, releases: installedReleases },
      );
      const jwks = await this._fetchJwks();
      const expectedSubject = getJwtSubject(accessToken);
      const contentKeys: Record<string, string> = {};
      const leaseExpirations: number[] = [];
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
            expectedSubject,
            this._serverIdentity.issuer,
            this._serverIdentity.lease_audience,
            this._serverIdentity.deployment_id,
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
          this._log(`lease invalide pour ${pluginId}: ${err instanceof Error ? err.message : String(err)}`);
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
      this._log(`sync licence par installation échouée: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private _log(message: string): void {
    // Pas de canal de log injecté dans ce service — évite d'imposer une
    // dépendance vscode.OutputChannel pour un chemin best-effort. À
    // remplacer par un vrai logger si ce chemin devient bruyant en pratique.
    if (typeof console !== 'undefined' && console.warn) {
      console.warn(`[AuthService] ${message}`);
    }
  }

  private async _getOrCreateDeviceIdentity(): Promise<{
    deviceId: string;
    privateKeyPem: string;
    publicKeyPem: string;
  }> {
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

  private async _fetchJwks(): Promise<unknown> {
    const cacheTtlMs = 3600_000;
    if (this._jwksCache && Date.now() - this._jwksCache.fetchedAt < cacheTtlMs) {
      return this._jwksCache.jwks;
    }
    await this._ensureServerIdentity(this.serverUrl);
    const res = await fetch(this._serverIdentity.jwks_uri);
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    const jwks = await res.json();
    this._jwksCache = { jwks, fetchedAt: Date.now() };
    return jwks;
  }

  private async _ensureServerIdentity(serverUrl: string): Promise<ServerIdentity> {
    const normalized = String(serverUrl || '').replace(/\/+$/, '');
    if (this._serverIdentity?.origin === normalized) {
      if (this._secretIsolationEnabled && !this._secretNamespace) {
        await this._bindSecretNamespace(this._serverIdentity);
      }
      return this._serverIdentity;
    }
    this._serverIdentity = await discoverAuthServer(normalized);
    this.serverUrl = this._serverIdentity.origin;
    this._jwksCache = null;
    if (this._secretIsolationEnabled) await this._bindSecretNamespace(this._serverIdentity);
    return this._serverIdentity;
  }

  private _namespaceFor(identity: Pick<ServerIdentity, 'deployment_id' | 'origin'>): string {
    const fingerprint = [
      this.deploymentProfile,
      String(identity?.deployment_id || '').trim(),
      String(identity?.origin || '').replace(/\/+$/, ''),
    ].join('\n');
    return `pof.auth.ns.${crypto.createHash('sha256').update(fingerprint).digest('hex').slice(0, 24)}`;
  }

  private async _readServerBinding(): Promise<ServerBinding | null> {
    try {
      const raw = await this._rawSecrets.get(KEY_SERVER_BINDING);
      return raw ? JSON.parse(raw) as ServerBinding : null;
    } catch {
      return null;
    }
  }

  private async _resolveSecretKey(key: string): Promise<string> {
    if (!SECRET_KEYS.includes(key)) return key;
    if (!this._secretNamespace) {
      const binding = await this._readServerBinding();
      const origin = String(this.serverUrl || '').replace(/\/+$/, '');
      if (binding?.profile === this.deploymentProfile && binding?.origin === origin) {
        this._secretNamespace = String(binding.namespace || '');
      } else if (binding?.namespace) {
        await this._deleteNamespace(binding.namespace);
        await this._rawSecrets.delete(KEY_SERVER_BINDING);
      }
    }
    const namespace = this._secretNamespace || this._namespaceFor({
      deployment_id: 'unverified',
      origin: String(this.serverUrl || '').replace(/\/+$/, ''),
    });
    return `${namespace}.${key.slice('pof.auth.'.length)}`;
  }

  private async _deleteNamespace(namespace: string): Promise<void> {
    if (!namespace) return;
    await Promise.all(SECRET_KEYS.map((key) => (
      this._rawSecrets.delete(`${namespace}.${key.slice('pof.auth.'.length)}`)
    )));
  }

  private async _bindSecretNamespace(identity: ServerIdentity): Promise<void> {
    const namespace = this._namespaceFor(identity);
    const binding = await this._readServerBinding();
    if (binding?.namespace && binding.namespace !== namespace) {
      await this._deleteNamespace(binding.namespace);
    }
    this._secretNamespace = namespace;
    if (!binding) {
      for (const key of SECRET_KEYS) {
        // Les anciens secrets globaux ne prouvent pas à quelle autorité ils
        // appartenaient. Les rattacher au premier serveur découvert créerait
        // un risque de rejeu cross-déploiement : migration = déconnexion.
        await this._rawSecrets.delete(key);
      }
    }
    await this._rawSecrets.store(KEY_SERVER_BINDING, JSON.stringify({
      profile: this.deploymentProfile,
      deploymentId: identity.deployment_id,
      origin: identity.origin,
      namespace,
    }));
  }

  private async _postJsonAuthenticated<T>(
    baseUrl: string,
    requestPath: string,
    accessToken: string,
    payload: unknown,
  ): Promise<T> {
    const res = await fetch(`${String(baseUrl || '').replace(/\/+$/, '')}${requestPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw Object.assign(new Error(String(err.detail ?? `Auth failed: ${res.status}`)), { status: res.status });
    }
    return res.json() as Promise<T>;
  }

  private _scheduleRefresh(): void {
    this._clearRefreshTimer();
    this._refreshTimer = setTimeout(
      () => { this.refresh().catch(() => {}); },
      55 * 60 * 1000,
    );
  }

  private _clearRefreshTimer(): void {
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }
  }

  private _getCandidateServerUrls(): string[] {
    const baseUrl = String(this.serverUrl || '').trim();
    let parsed: URL;
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

  private async _postJson<T>(baseUrl: string, requestPath: string, payload: unknown): Promise<T> {
    const res = await fetch(`${String(baseUrl || '').replace(/\/+$/, '')}${requestPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw Object.assign(new Error(String(err.detail ?? `Auth failed: ${res.status}`)), { status: res.status });
    }
    return res.json() as Promise<T>;
  }

  private async _getJsonAuthenticated<T = unknown>(
    baseUrl: string,
    requestPath: string,
    accessToken: string,
  ): Promise<T> {
    const res = await fetch(`${String(baseUrl || '').replace(/\/+$/, '')}${requestPath}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(String(err.detail ?? `Auth failed: ${res.status}`));
    }
    return res.json() as Promise<T>;
  }
}

AuthService._instance = null;

module.exports = {
  AuthService,
  KEY_SERVER_BINDING,
  discoverInstalledPluginReleases,
  discoverInstalledPluginArtifacts,
};
