// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file staticHandlers.js
 * @brief Handlers de messages liés au mode statique (désassemblage, symboles, sections, etc.).
 * @see docs/ARCHITECTURE_AUDIT_PLAN.md Phase 2.2
 */

const vscode = require('vscode');
const cp = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const readline = require('readline');
const { detectPythonExecutable, buildRuntimeEnv, resolveDockerExecutable } = require('../shared/utils');
const { emptyPluginUiState, summarizePluginRuntimeState } = require('./pluginState');
const { AuthService } = require('../shared/authService');
const { resolveAuthServerUrl } = require('../shared/authConfig');
const {
  clearAiProcess,
  registerAiProcess,
} = require('../shared/aiProcessRegistry');
const { getKnownOciImagePlatform } = require('./decompilerCommands');

const AUTH_STRICT_LICENSE_ENV = 'BINHOST_DISABLE_LICENSE_FALLBACK';
const DOCKER_IMAGE_UPDATE_CACHE_TTL_MS = 10 * 60 * 1000;
const _dockerImageUpdateCache = new Map();
let _dockerRuntimeStatusCache = null;

function _collectProcessOutput(command, args, options = {}) {
  return new Promise((resolve) => {
    if (typeof cp.spawn !== 'function') {
      resolve({ code: -1, stdout: '', stderr: 'spawn unavailable' });
      return;
    }
    let stdout = '';
    let stderr = '';
    let settled = false;
    const proc = cp.spawn(command, args, {
      env: options.env || process.env,
      cwd: options.cwd,
    });
    const timeoutMs = options.timeout || 12000;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { proc.kill('SIGTERM'); } catch (_) {}
      resolve({ code: -1, stdout, stderr: stderr || 'timeout' });
    }, timeoutMs);
    proc.stdout?.on('data', (chunk) => { stdout += chunk.toString(); });
    proc.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
    proc.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: String(err.message || err) });
    });
    proc.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

function _extractDockerDigests(value, digests = new Set()) {
  if (value == null) return digests;
  if (typeof value === 'string') {
    for (const match of value.matchAll(/sha256:[a-f0-9]{64}/gi)) {
      digests.add(match[0].toLowerCase());
    }
    return digests;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => _extractDockerDigests(item, digests));
    return digests;
  }
  if (typeof value === 'object') {
    Object.values(value).forEach((item) => _extractDockerDigests(item, digests));
  }
  return digests;
}

function _extractLocalRepoDigests(payload) {
  const digests = new Set();
  const entries = Array.isArray(payload) ? payload : [];
  entries.forEach((entry) => {
    const repoDigests = Array.isArray(entry?.RepoDigests) ? entry.RepoDigests : [];
    repoDigests.forEach((digestRef) => _extractDockerDigests(digestRef, digests));
  });
  return Array.from(digests);
}

function _extractRemoteManifestDigests(payload) {
  const digests = new Set();
  const add = (value) => _extractDockerDigests(value, digests);
  const entries = Array.isArray(payload) ? payload : [payload];
  entries.forEach((entry) => {
    if (!entry || typeof entry !== 'object') return;
    add(entry.Descriptor?.digest);
    add(entry.digest);
    if (Array.isArray(entry.manifests)) {
      entry.manifests.forEach((manifest) => add(manifest?.digest));
    }
  });
  return Array.from(digests);
}

function _extractImagetoolsDigests(stdout) {
  const digests = new Set();
  const text = String(stdout || '');
  for (const match of text.matchAll(/(?:^|\s)Digest:\s*(sha256:[a-f0-9]{64})/gim)) {
    digests.add(match[1].toLowerCase());
  }
  for (const match of text.matchAll(/@((?:sha256:)[a-f0-9]{64})/gim)) {
    digests.add(match[1].toLowerCase());
  }
  return Array.from(digests);
}

function _shortDockerDigest(digest) {
  const value = String(digest || '').trim();
  const match = value.match(/sha256:([a-f0-9]{12})[a-f0-9]*/i);
  return match ? match[1].toLowerCase() : '';
}

function _dockerImageUpdateCacheKey(image, platform = '') {
  return `${String(image || '').trim()}|${String(platform || '').trim()}`;
}

function _getCachedDockerImageUpdate(image, platform = '') {
  const cached = _dockerImageUpdateCache.get(_dockerImageUpdateCacheKey(image, platform));
  if (!cached || Date.now() - cached.cachedAt > DOCKER_IMAGE_UPDATE_CACHE_TTL_MS) return null;
  return { ...cached.value, cached: true, cacheAgeMs: Date.now() - cached.cachedAt };
}

function _setCachedDockerImageUpdate(image, platform, value) {
  _dockerImageUpdateCache.set(_dockerImageUpdateCacheKey(image, platform), {
    cachedAt: Date.now(),
    value,
  });
}

function _getCachedDockerRuntimeStatus() {
  if (!_dockerRuntimeStatusCache || Date.now() - _dockerRuntimeStatusCache.cachedAt > DOCKER_IMAGE_UPDATE_CACHE_TTL_MS) return null;
  return { ..._dockerRuntimeStatusCache.value, cached: true, cacheAgeMs: Date.now() - _dockerRuntimeStatusCache.cachedAt };
}

function _setCachedDockerRuntimeStatus(value) {
  _dockerRuntimeStatusCache = { cachedAt: Date.now(), value };
}

function _formatLogDetails(details = {}) {
  return Object.entries(details)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(' ');
}

function _logDecompilerDocker(logChannel, event, details = {}) {
  if (!logChannel?.appendLine) return;
  const suffix = _formatLogDetails(details);
  logChannel.appendLine(`[decompiler/docker] ${event}${suffix ? ` ${suffix}` : ''}`);
}

function _pullProgressSummary(layersDone, layersTotal) {
  if (!layersTotal) return '';
  return `Layers ${layersDone}/${layersTotal}`;
}

function _classifyDockerStatusError(stderr) {
  const text = String(stderr || '').trim();
  if (/docker.*buildx.*not.*command|unknown command.*buildx|is not a docker command/i.test(text)) {
    return { errorKind: 'buildx-missing', errorLabel: 'Docker buildx indisponible' };
  }
  if (/ENOENT|not found|no such file or directory|executable file not found/i.test(text)) {
    return { errorKind: 'docker-missing', errorLabel: 'Docker introuvable' };
  }
  if (/cannot connect to the docker daemon|is the docker daemon running|docker daemon/i.test(text)) {
    return { errorKind: 'daemon-unavailable', errorLabel: 'Daemon Docker indisponible' };
  }
  if (/unauthorized|authentication required|denied|forbidden/i.test(text)) {
    return { errorKind: 'auth-required', errorLabel: 'Authentification registry requise' };
  }
  if (/manifest unknown|name unknown|not found|does not exist/i.test(text)) {
    return { errorKind: 'manifest-missing', errorLabel: 'Manifest distant introuvable' };
  }
  if (/lookup|no such host|connection refused|i\/o timeout|timed out|tls handshake|network is unreachable|timeout/i.test(text)) {
    return { errorKind: 'registry-unreachable', errorLabel: 'Registry inaccessible' };
  }
  return { errorKind: text ? 'unknown' : '', errorLabel: text ? 'Update non vérifiable' : '' };
}

function _readLocalDockerImageMetadata(payload) {
  const entries = Array.isArray(payload) ? payload : [];
  const first = entries[0] || {};
  const localDigests = _extractLocalRepoDigests(entries);
  const imageId = String(first.Id || '').trim();
  const osName = String(first.Os || '').trim();
  const architecture = String(first.Architecture || '').trim();
  return {
    localDigests,
    localDigest: localDigests[0] || '',
    localDigestShort: _shortDockerDigest(localDigests[0] || ''),
    localImageId: imageId,
    localImageIdShort: _shortDockerDigest(imageId),
    localCreated: String(first.Created || '').trim(),
    localOs: osName,
    localArchitecture: architecture,
    localPlatform: osName && architecture ? `${osName}/${architecture}` : '',
  };
}

async function _checkDockerRuntimeStatus(options = {}) {
  if (!options.force) {
    const cached = _getCachedDockerRuntimeStatus();
    if (cached) return cached;
  }
  const dockerExe = resolveDockerExecutable();
  const version = await _collectProcessOutput(dockerExe, ['--version'], { env: buildRuntimeEnv(''), timeout: 5000 });
  const info = version.code === 0
    ? await _collectProcessOutput(dockerExe, ['info'], { env: buildRuntimeEnv(''), timeout: 8000 })
    : { code: -1, stdout: '', stderr: version.stderr };
  const buildx = version.code === 0
    ? await _collectProcessOutput(dockerExe, ['buildx', 'version'], { env: buildRuntimeEnv(''), timeout: 8000 })
    : { code: -1, stdout: '', stderr: version.stderr };
  const runtimeError = version.code !== 0
    ? _classifyDockerStatusError(version.stderr)
    : info.code !== 0
      ? _classifyDockerStatusError(info.stderr)
      : buildx.code !== 0
        ? _classifyDockerStatusError(buildx.stderr)
        : { errorKind: '', errorLabel: '' };
  const value = {
    dockerFound: version.code === 0,
    daemonOk: info.code === 0,
    buildxOk: buildx.code === 0,
    dockerVersion: String(version.stdout || '').trim(),
    buildxVersion: String(buildx.stdout || '').trim(),
    checkedAt: new Date().toISOString(),
    ...runtimeError,
  };
  _setCachedDockerRuntimeStatus(value);
  return value;
}

async function _postDockerRuntimeStatus(panel, options = {}) {
  const status = await _checkDockerRuntimeStatus(options);
  _logDecompilerDocker(options.logChannel, 'runtime.status', {
    dockerFound: status.dockerFound,
    daemonOk: status.daemonOk,
    buildxOk: status.buildxOk,
    cached: status.cached === true,
    errorKind: status.errorKind,
  });
  panel.webview.postMessage({ type: 'hubDockerRuntimeStatus', status });
}

async function _checkDockerImageUpdate(image, platform = '', options = {}) {
  if (!options.force) {
    const cached = _getCachedDockerImageUpdate(image, platform);
    if (cached) return cached;
  }
  const dockerExe = resolveDockerExecutable();
  const local = await _collectProcessOutput(
    dockerExe,
    ['image', 'inspect', image],
    { env: buildRuntimeEnv(''), timeout: 8000 },
  );
  if (local.code !== 0) {
    const classified = _classifyDockerStatusError(local.stderr);
    const value = { image, platform, status: 'missing', error: local.stderr.trim(), ...classified };
    _setCachedDockerImageUpdate(image, platform, value);
    return value;
  }

  let localPayload = null;
  try { localPayload = JSON.parse(local.stdout || '[]'); } catch (_) {}
  const localMeta = _readLocalDockerImageMetadata(localPayload);
  const localDigests = localMeta.localDigests;
  if (localDigests.length === 0) {
    const value = { image, platform, status: 'unknown', ...localMeta, error: 'image locale sans digest registry', errorKind: 'local-digest-missing', errorLabel: 'Digest local absent' };
    _setCachedDockerImageUpdate(image, platform, value);
    return value;
  }

  const imagetools = await _collectProcessOutput(
    dockerExe,
    ['buildx', 'imagetools', 'inspect', image],
    { env: buildRuntimeEnv(''), timeout: 15000 },
  );
  let remoteDigests = [];
  if (imagetools.code === 0) {
    remoteDigests = _extractImagetoolsDigests(imagetools.stdout);
  }

  const remoteArgs = ['manifest', 'inspect', '--verbose', image];
  const remote = await _collectProcessOutput(
    dockerExe,
    remoteArgs,
    { env: buildRuntimeEnv(''), timeout: 15000 },
  );
  if (remote.code === 0) {
    let remotePayload = null;
    try { remotePayload = JSON.parse(remote.stdout || '{}'); } catch (_) {}
    remoteDigests = Array.from(new Set([
      ...remoteDigests,
      ..._extractRemoteManifestDigests(remotePayload),
    ]));
  }
  if (remoteDigests.length === 0) {
    const classified = _classifyDockerStatusError(imagetools.stderr || remote.stderr);
    const value = {
      image,
      platform,
      status: 'unknown',
      ...localMeta,
      error: imagetools.stderr.trim() || remote.stderr.trim() || 'digest distant introuvable',
      ...classified,
    };
    _setCachedDockerImageUpdate(image, platform, value);
    return value;
  }

  const isCurrent = localDigests.some((digest) => remoteDigests.includes(digest));
  const value = {
    image,
    platform,
    status: isCurrent ? 'up-to-date' : 'update-available',
    ...localMeta,
    remoteDigests,
    remoteDigest: remoteDigests[0] || '',
    remoteDigestShort: _shortDockerDigest(remoteDigests[0] || ''),
    checkedAt: new Date().toISOString(),
  };
  _setCachedDockerImageUpdate(image, platform, value);
  return value;
}

async function _postDecompilerImageUpdateStatus(panel, result, options = {}) {
  const meta = result?._meta || {};
  const dockerImages = meta.docker_images || {};
  const dockerAvail = meta.docker_images_available || {};
  const dockerPlatform = meta.docker_platform || {};
  const ids = Object.keys(dockerImages).filter((id) => dockerImages[id] && dockerAvail[id]);
  if (!ids.length) return;

  const pendingIds = [];
  const cached = {};
  ids.forEach((id) => {
    const image = dockerImages[id];
    const platform = dockerPlatform[id] || '';
    const cachedStatus = options.force ? null : _getCachedDockerImageUpdate(image, platform);
    if (cachedStatus) cached[id] = cachedStatus;
    else pendingIds.push(id);
  });
  if (Object.keys(cached).length) {
    Object.entries(cached).forEach(([id, status]) => {
      _logDecompilerDocker(options.logChannel, 'image.status.cached', {
        id,
        status: status.status,
        image: status.image,
      });
    });
    panel.webview.postMessage({ type: 'hubDecompilerImageUpdates', updates: cached });
  }
  if (!pendingIds.length) return;

  const checking = {};
  pendingIds.forEach((id) => {
    checking[id] = { image: dockerImages[id], platform: dockerPlatform[id] || '', status: 'checking' };
  });
  panel.webview.postMessage({ type: 'hubDecompilerImageUpdates', updates: checking });

  const entries = await Promise.all(pendingIds.map(async (id) => {
    const status = await _checkDockerImageUpdate(dockerImages[id], dockerPlatform[id] || '', options);
    _logDecompilerDocker(options.logChannel, 'image.status', {
      id,
      status: status.status,
      image: dockerImages[id],
      localDigest: status.localDigestShort,
      remoteDigest: status.remoteDigestShort,
      errorKind: status.errorKind,
    });
    return [id, status];
  }));
  panel.webview.postMessage({ type: 'hubDecompilerImageUpdates', updates: Object.fromEntries(entries) });
}

function staticHandlers(config) {
  const { root, panel, context, logChannel, storageDir, globalDir } = config;
  const extensionPath = context?.extensionPath || root;
  const getSavedSettings = () => {
    try {
      return context?.globalState?.get('pof-settings', {}) || {};
    } catch (_) {
      return {};
    }
  };
  const getPythonExecutable = () => getSavedSettings().pythonPath || detectPythonExecutable(root);
  const getAuthServerUrl = () => {
    const authConfig = vscode.workspace.getConfiguration('pileOuFace').inspect('authServerUrl');
    return resolveAuthServerUrl({
      savedAuthServerUrl: getSavedSettings().authServerUrl || '',
      configuredAuthServerUrl: authConfig?.workspaceFolderValue || authConfig?.workspaceValue || authConfig?.globalValue || '',
      projectRoot: root,
    });
  };
  const getHostArtifactRoot = (kind) => {
    const normalizedKind = String(kind || '').trim();
    const baseDir = storageDir;
    const base = normalizedKind ? path.join(baseDir, normalizedKind) : baseDir;
    try {
      if (!fs.existsSync(base)) fs.mkdirSync(base, { recursive: true });
    } catch (_) {}
    return base;
  };
  const buildPythonEnv = () => {
    const settings = getSavedSettings();
    const localPaths = settings.decompilerLocalPaths && typeof settings.decompilerLocalPaths === 'object'
      ? settings.decompilerLocalPaths
      : {};
    const env = buildRuntimeEnv(root, storageDir);
    const ghidraPath = String(localPaths.ghidra || '').trim();
    if (ghidraPath) env.GHIDRA_INSTALL_DIR = ghidraPath;
    return env;
  };
  const getPreferredPluginArtifactDir = (artifactKind) => {
    const kind = String(artifactKind || '').trim();
    const defaultRoot = kind === 'licenses' || kind === 'plugins'
      ? getHostArtifactRoot(kind)
      : null;
    const candidates = [];
    if (kind === 'licenses') {
      candidates.push(
        path.join(root, 'release', 'licenses'),
        path.join(path.dirname(root), 'Pile_ou_Face_plugins', 'release', 'licenses'),
        path.join(path.dirname(root), 'Pile_Ou_Face_plugins', 'release', 'licenses'),
      );
    } else if (kind === 'plugins') {
      candidates.push(
        path.join(root, 'release', 'dist'),
        path.join(path.dirname(root), 'Pile_ou_Face_plugins', 'release', 'dist'),
        path.join(path.dirname(root), 'Pile_Ou_Face_plugins', 'release', 'dist'),
      );
    }
    const existing = candidates.find((candidate) => {
      try {
        return fs.existsSync(candidate);
      } catch (_) {
        return false;
      }
    });
    return existing || defaultRoot || root;
  };

  const runPython = (argsWithScript, { timeout = 60000, maxBuffer = 4 * 1024 * 1024 } = {}) =>
    new Promise((resolve, reject) => {
      const [scriptRelPath, ...rest] = argsWithScript;
      const scriptPath = path.join(extensionPath, scriptRelPath);
      cp.execFile(getPythonExecutable(), [scriptPath, ...rest], {
        encoding: 'utf8', cwd: root, maxBuffer, timeout, env: buildPythonEnv(),
      }, (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });

  const buildPluginRuntimeEnv = async () => {
    const base = buildPythonEnv();
    // Injecter le dossier plugins du workspace storage pour que Python le découvre.
    if (storageDir) {
      base['BINHOST_PLUGIN_PATH'] = path.join(storageDir, 'plugins');
    }
    let hasOnlineKeys = false;
    try {
      const authSvc = AuthService.getInstance(
        context.secrets,
        getAuthServerUrl(),
      );
      const { revoked } = await authSvc.refreshKeysIfStale(24 * 3600_000);
      if (revoked) {
        panel.webview.postMessage({ type: 'accountState', loggedIn: false });
      }
      const keys = await authSvc.getContentKeys();
      const entries = Object.entries(keys);
      if (entries.length > 0) {
        hasOnlineKeys = true;
        for (const [pluginId, key] of entries) {
          const varName = 'POF_CONTENT_KEY_' + String(pluginId).toUpperCase().replace(/-/g, '_').replace(/\./g, '_');
          base[varName] = String(key);
        }
      }
    } catch (_e) {
      // AuthService non disponible — aucune clé injectée.
    }

    if (hasOnlineKeys) {
      // MODE 1 — en ligne : bloquer les fichiers licence offline.
      base[AUTH_STRICT_LICENSE_ENV] = '1';
    } else {
      // Pas de clés en ligne : vérifier la présence de fichiers licence offline signés.
      // On cherche dans storageDir/licenses ET dans ~/.pile-ou-face/licenses (même
      // logique que le runtime Python : default_license_search_paths).
      const licenseDirs = [
        ...(storageDir ? [path.join(storageDir, 'licenses')] : []),
        path.join(os.homedir(), '.pile-ou-face', 'licenses'),
      ];
      let hasOfflineLicenses = false;
      for (const licenseDir of licenseDirs) {
        try {
          const files = fs.readdirSync(licenseDir);
          if (files.some((f) => String(f).endsWith('.license.json'))) {
            hasOfflineLicenses = true;
            break;
          }
        } catch (_e) {
          // Répertoire absent → continuer.
        }
      }

      if (!hasOfflineLicenses) {
        // Ni clés en ligne, ni licences offline → plugin verrouillé.
        // BINHOST_DISABLE_LICENSE_FALLBACK=1 empêche tout fallback fichier.
        base[AUTH_STRICT_LICENSE_ENV] = '1';
      }
      // MODE 3 — offline contractuel : hasOfflineLicenses=true, flag absent,
      // le runtime Python lira les fichiers .license.json signés.
    }

    return base;
  };

  const buildAccountStatePayload = async ({ email = '', fallbackError = '' } = {}) => {
    const authSvc = AuthService.getInstance(context.secrets, getAuthServerUrl());
    const resolvedEmail = email || await authSvc.getEmail();
    const keys = await authSvc.getContentKeys();
    const profile = await authSvc.getProfile();
    const activePlugins = Array.isArray(profile?.active_plugin_ids)
      ? profile.active_plugin_ids.map((entry) => String(entry || '').trim()).filter(Boolean)
      : Object.keys(keys);
    return {
      type: 'accountState',
      loggedIn: true,
      email: resolvedEmail,
      plugins: activePlugins,
      error: fallbackError || '',
    };
  };

  const runPluginRuntime = async (runtimeArgs, options = {}) => {
    const pluginEnv = await buildPluginRuntimeEnv();
    const { timeout = 60000, maxBuffer = 4 * 1024 * 1024 } = options;
    const scriptPath = path.join(extensionPath, 'backends/plugins/runtime.py');
    const { stdout } = await new Promise((resolve, reject) => {
      cp.execFile(getPythonExecutable(), [
        scriptPath,
        '--host-version', '0.1.0',
        '--api-version', '1',
        ...runtimeArgs,
      ], {
        encoding: 'utf8', cwd: root, maxBuffer, timeout, env: pluginEnv,
      }, (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });
    return JSON.parse(String(stdout || '{}'));
  };

  const buildPluginRequiredPayload = (feature, extra = {}) => ({
    ok: false,
    error: `Feature plugin requise: ${feature}`,
    plugin_command: '',
    plugin_required: feature,
    feature,
    ...extra,
  });

  const invokePluginFeature = async (featureId, payload, {
    timeout = 120000,
  } = {}) => {
    try {
      const response = await runPluginRuntime([
        'invoke-feature',
        featureId,
        '--payload-json',
        JSON.stringify(payload || {}),
      ], { timeout });
      if (response?.ok === true) {
        return response.result ?? {};
      }
      const available = Array.isArray(response?.available_commands) ? response.available_commands : [];
      if (available.length === 0) {
        return buildPluginRequiredPayload(feature);
      }
      return {
        ok: false,
        error: String(response?.error || `Échec plugin: ${featureId}`),
        plugin_command: String(response?.command || ''),
        plugin_required: featureId,
        feature: featureId,
      };
    } catch (error) {
      return buildPluginRequiredPayload(featureId);
    }
  };

  const buildTypedDataArgs = (message) => {
    const {
      binaryPath, section, valueType, page, structName, structOffset, structAddr,
    } = message || {};
    const typeName = valueType || null;
    const args = ['backends/static/annotations/typed_data.py', '--binary', binaryPath];
    if (section) args.push('--section', section);
    if (typeName) args.push('--type', typeName);
    if (page !== undefined && page !== null) args.push('--page', String(page));
    if (structName) args.push('--struct-name', structName);
    if (structOffset !== undefined && structOffset !== null) args.push('--struct-offset', String(structOffset));
    if (structAddr !== undefined && structAddr !== null && String(structAddr).trim()) {
      args.push('--struct-addr', String(structAddr));
    }
    const rawBaseAddr = message?.binaryMeta?.rawConfig?.baseAddr || message?.rawBaseAddr || null;
    const rawArch = message?.binaryMeta?.rawConfig?.arch || message?.rawArch || null;
    const rawEndian = message?.binaryMeta?.rawConfig?.endian || message?.rawEndian || null;
    if (rawBaseAddr) args.push('--raw-base-addr', String(rawBaseAddr));
    if (rawArch) args.push('--raw-arch', String(rawArch));
    if (rawEndian) args.push('--raw-endian', String(rawEndian));
    return args;
  };

  const listOllamaModels = (baseUrlRaw) => new Promise((resolve, reject) => {
    const fallbackUrl = 'http://127.0.0.1:11434';
    const input = String(baseUrlRaw || '').trim() || fallbackUrl;
    let parsed;
    try {
      parsed = new URL(input);
    } catch (_) {
      reject(new Error(`URL Ollama invalide: ${input}`));
      return;
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        method: 'GET',
        path: '/api/tags',
        timeout: 8000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          if ((res.statusCode || 500) >= 400) {
            reject(new Error(`Ollama a répondu ${res.statusCode}`));
            return;
          }
          try {
            const raw = Buffer.concat(chunks).toString('utf8');
            const payload = JSON.parse(raw);
            const models = Array.isArray(payload.models)
              ? payload.models
                  .map((item) => String(item?.name || '').trim())
                  .filter(Boolean)
              : [];
            models.sort((a, b) => a.localeCompare(b));
            resolve(models);
          } catch (e) {
            reject(new Error(`Réponse Ollama invalide: ${e.message || e}`));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Timeout Ollama')));
    req.on('error', (err) => reject(new Error(`Impossible de joindre Ollama (${input}): ${err.message || err}`)));
    req.end();
  });

  const handlers = {
    hubLoadPluginState: async () => {
      try {
        const payload = await runPluginRuntime(['list', '--attach']);
        panel.webview.postMessage({
          type: 'hubPluginState',
          state: summarizePluginRuntimeState(payload),
        });
      } catch (error) {
        panel.webview.postMessage({
          type: 'hubPluginState',
          state: emptyPluginUiState(String(error?.message || error || 'runtime indisponible')),
        });
      }
    },
    hubPluginInvoke: async (message = {}) => {
      const feature = String(message.feature || message.featureId || '').trim();
      const requestId = String(message.requestId || message.id || '');
      const payload = message.payload && typeof message.payload === 'object'
        ? { ...message.payload }
        : {};
      if (message.binaryPath && payload.binaryPath == null && payload.binary_path == null) {
        payload.binaryPath = message.binaryPath;
      }
      const result = feature
        ? await invokePluginFeature(feature, payload, { timeout: Number(message.timeout || 120000) })
        : {
            ok: false,
            error: 'feature manquante',
            plugin_required: '',
            feature,
          };
      panel.webview.postMessage({
        type: 'hubPluginResult',
        requestId,
        feature,
        result,
      });
    },
    hubOpenPluginDirectory: async (message = {}) => {
      const requestedScope = String(message.scope || 'user').trim() === 'workspace' ? 'workspace' : 'user';
      const pluginDir = getHostArtifactRoot('plugins');
      const scope = storageDir ? 'workspace' : requestedScope;
      try {
        await fs.promises.mkdir(pluginDir, { recursive: true });
        await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(pluginDir));
        panel.webview.postMessage({
          type: 'hubPluginFolderOpened',
          ok: true,
          scope,
          path: pluginDir,
        });
      } catch (error) {
        panel.webview.postMessage({
          type: 'hubPluginFolderOpened',
          ok: false,
          scope,
          path: pluginDir,
          error: String(error?.message || error || `Impossible d'ouvrir le dossier plugins.`),
        });
      }
    },
    hubOpenLicenseDirectory: async () => {
      const licenseDir = getHostArtifactRoot('licenses');
      try {
        await fs.promises.mkdir(licenseDir, { recursive: true });
        await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(licenseDir));
        panel.webview.postMessage({
          type: 'hubLicenseFolderOpened',
          ok: true,
          path: licenseDir,
        });
      } catch (error) {
        panel.webview.postMessage({
          type: 'hubLicenseFolderOpened',
          ok: false,
          path: licenseDir,
          error: String(error?.message || error || `Impossible d'ouvrir le dossier licences.`),
        });
      }
    },
    hubInstallPlugin: async (message = {}) => {
      const requestedScope = String(message.scope || 'user').trim() === 'workspace' ? 'workspace' : 'user';
      const selectedScope = (storageDir || fs.existsSync(path.join(root, '.pile-ou-face'))) ? 'workspace' : requestedScope;
      try {
        const picked = await vscode.window.showOpenDialog({
          canSelectFiles: true,
          canSelectFolders: true,
          canSelectMany: false,
          openLabel: 'Installer le plugin',
          defaultUri: vscode.Uri.file(getPreferredPluginArtifactDir('plugins')),
          filters: {
            'Plugin bundle': ['pofplug', 'zip'],
          },
          title: 'Sélectionner un plugin compilé ou un dossier plugin',
        });
        if (!Array.isArray(picked) || !picked.length) {
          panel.webview.postMessage({
            type: 'hubPluginInstalled',
            ok: false,
            cancelled: true,
          });
          return;
        }
        const sourceUri = picked[0];
        const targetRoot = getHostArtifactRoot('plugins');
        const { stdout } = await runPython([
          'backends/plugins/install_plugin.py',
          '--source', sourceUri.fsPath,
          '--target-root', targetRoot,
          '--workspace', root,
        ], { timeout: 120000 });
        const response = JSON.parse(String(stdout || '{}'));
        panel.webview.postMessage({
          type: 'hubPluginInstalled',
          scope: selectedScope,
          source: sourceUri.fsPath,
          ...response,
        });
      } catch (error) {
        const details = [error?.message || error, error?.stderr].filter(Boolean).join('\n');
        panel.webview.postMessage({
          type: 'hubPluginInstalled',
          ok: false,
          scope: selectedScope || 'workspace',
          error: String(details || 'Installation du plugin impossible.'),
        });
      }
    },
    hubInstallPluginLicense: async () => {
      try {
        const picked = await vscode.window.showOpenDialog({
          canSelectFiles: true,
          canSelectFolders: false,
          canSelectMany: false,
          openLabel: 'Importer la licence',
          defaultUri: vscode.Uri.file(getPreferredPluginArtifactDir('licenses')),
          title: 'Sélectionner un fichier de licence plugin',
        });
        if (!Array.isArray(picked) || !picked.length) {
          panel.webview.postMessage({
            type: 'hubPluginLicenseInstalled',
            ok: false,
            cancelled: true,
          });
          return;
        }
        const sourceUri = picked[0];
        const targetRoot = getHostArtifactRoot('licenses');
        const { stdout } = await runPython([
          'backends/plugins/install_license.py',
          '--source', sourceUri.fsPath,
          '--target-root', targetRoot,
          '--workspace', root,
        ], { timeout: 120000 });
        const response = JSON.parse(String(stdout || '{}'));
        panel.webview.postMessage({
          type: 'hubPluginLicenseInstalled',
          source: sourceUri.fsPath,
          ...response,
        });
      } catch (error) {
        const details = [error?.message || error, error?.stderr].filter(Boolean).join('\n');
        panel.webview.postMessage({
          type: 'hubPluginLicenseInstalled',
          ok: false,
          error: String(details || 'Installation de la licence impossible.'),
        });
      }
    },
    hubOllamaListModels: async (message) => {
      const baseUrl = String(message?.baseUrl || '').trim() || 'http://127.0.0.1:11434';
      const preferredModel = String(context?.globalState?.get('pof.ollamaModel', '') || '').trim();
      try {
        const models = await listOllamaModels(baseUrl);
        panel.webview.postMessage({
          type: 'hubOllamaModels',
          models,
          baseUrl,
          preferredModel,
        });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubOllamaModels',
          models: [],
          baseUrl,
          preferredModel,
          error: String(e?.message || e),
        });
      }
    },
    hubOllamaModelSelected: async (message) => {
      const model = String(message?.model || '').trim();
      if (!model) return;
      await context?.globalState?.update?.('pof.ollamaModel', model);
    },
    hubOllamaPrompt: async (message) => {
      const requestId = String(message?.requestId || '').trim();
      const baseUrl = String(message?.baseUrl || '').trim() || 'http://127.0.0.1:11434';
      const model = String(message?.model || '').trim();
      const prompt = String(message?.prompt || '').trim();
      if (!model) {
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          error: 'Modèle Ollama manquant.',
          output: '',
        });
        return;
      }
      if (!prompt) {
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          error: 'Prompt vide.',
          output: '',
          model,
        });
        return;
      }
      const scriptPath = path.join(extensionPath, 'backends/mcp/ollama_bridge.py');
      const args = [
        scriptPath,
        '--base-url', baseUrl,
        '--model', model,
        '--prompt', prompt,
        '--timeout', '300',
        '--max-steps', '15',
        '--stream-output',
      ];
      const temperature = Number(message.temperature);
      const topP = Number(message.top_p);
      const maxTokens = Number(message.max_tokens);
      if (Number.isFinite(temperature) && temperature >= 0 && temperature <= 2) {
        args.push('--temperature', String(temperature));
      }
      if (Number.isFinite(topP) && topP > 0 && topP <= 1) {
        args.push('--top-p', String(topP));
      }
      if (Number.isInteger(maxTokens) && maxTokens >= 1 && maxTokens <= 131072) {
        args.push('--max-tokens', String(maxTokens));
      }
      const proc = cp.spawn(getPythonExecutable(), args, { cwd: root, env: buildPythonEnv() });

      let resultSent = false;
      let stderrBuf = '';
      let tokenBuffer = '';
      let tokenBufferFragments = 0;
      let tokenFlushTimer = null;
      let rl = null;
      const flushTokenBuffer = () => {
        if (tokenFlushTimer !== null) {
          clearTimeout(tokenFlushTimer);
          tokenFlushTimer = null;
        }
        if (!tokenBuffer) return;
        const content = tokenBuffer;
        const fragments = tokenBufferFragments;
        tokenBuffer = '';
        tokenBufferFragments = 0;
        panel.webview.postMessage({
          type: 'hubOllamaStream',
          event: { type: 'token', content, fragments },
          model,
          ...(requestId ? { requestId } : {}),
        });
      };
      const scheduleTokenFlush = () => {
        if (tokenFlushTimer === null) {
          tokenFlushTimer = setTimeout(flushTokenBuffer, 80);
        }
      };
      proc.stderr.on('data', (chunk) => { stderrBuf += String(chunk); });

      const cancelRequest = () => {
        if (resultSent) return;
        resultSent = true;
        flushTokenBuffer();
        rl?.close?.();
        proc.kill?.('SIGTERM');
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          cancelled: true,
          model,
          output: '',
          ...(requestId ? { requestId } : {}),
        });
      };
      registerAiProcess(requestId, cancelRequest);

      rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
      rl.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        let event;
        try { event = JSON.parse(trimmed); } catch { return; }
        if (event.type === 'done' || event.type === 'error') {
          flushTokenBuffer();
          resultSent = true;
          clearAiProcess(requestId);
          // Leave one paint window after the last token batch before replacing
          // the live bubble with the persisted final conversation.
          setTimeout(() => {
            panel.webview.postMessage({
              type: 'hubOllamaResult',
              ok: event.ok !== false,
              model,
              output: event.response || '',
              usage: event.usage && typeof event.usage === 'object' ? event.usage : {},
              error: event.ok === false ? (event.error || 'Erreur inconnue') : undefined,
              ...(requestId ? { requestId } : {}),
            });
          }, 100);
        } else {
          if (event.type === 'token') {
            tokenBuffer += String(event.content || '');
            tokenBufferFragments += 1;
            scheduleTokenFlush();
          } else {
            if (event.type === 'token_rollback') {
              if (tokenFlushTimer !== null) clearTimeout(tokenFlushTimer);
              tokenFlushTimer = null;
              tokenBuffer = '';
              tokenBufferFragments = 0;
            } else {
              flushTokenBuffer();
            }
          }
          if (event.type !== 'token') {
            panel.webview.postMessage({
              type: 'hubOllamaStream',
              event,
              model,
              ...(requestId ? { requestId } : {}),
            });
          }
        }
      });

      proc.on('close', (code) => {
        if (!resultSent) {
          clearAiProcess(requestId);
          panel.webview.postMessage({
            type: 'hubOllamaResult',
            ok: false,
            model,
            error: stderrBuf.trim() || `Bridge exited with code ${code}`,
            output: '',
            ...(requestId ? { requestId } : {}),
          });
        }
      });

      proc.on('error', (err) => {
        if (!resultSent) {
          resultSent = true;
          clearAiProcess(requestId);
          panel.webview.postMessage({
            type: 'hubOllamaResult',
            ok: false,
            model,
            error: String(err.message || err),
            output: '',
            ...(requestId ? { requestId } : {}),
          });
        }
      });
    },
    hubListDecompilers: async (message = {}) => {
      const provider = message.provider || 'auto';
      _logDecompilerDocker(logChannel, 'list.start', { provider });
      try {
        const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', provider]);
        const result = JSON.parse(stdout);
        const count = Object.keys(result || {}).filter((key) => !key.startsWith('_')).length;
        _logDecompilerDocker(logChannel, 'list.done', { provider, count });
        panel.webview.postMessage({ type: 'hubDecompilerList', result });
        _postDockerRuntimeStatus(panel, { logChannel }).catch(() => {});
        _postDecompilerImageUpdateStatus(panel, result, { logChannel }).catch(() => {});
      } catch (e) {
        _logDecompilerDocker(logChannel, 'list.error', { provider, error: e?.message || String(e) });
        panel.webview.postMessage({
          type: 'hubDecompilerList',
          result: { _meta: { provider, docker_images: {}, local_available: {}, labels: {} } },
        });
      }
    },
    hubPullDecompilerImage: async (message = {}) => {
      const decompiler = String(message.decompiler || '').trim();
      const image = String(message.image || '').trim();
      const mode = String(message.mode || 'pull').trim();
      if (!decompiler || !image) {
        panel.webview.postMessage({ type: 'hubDecompilerPullDone', decompiler, ok: false, error: 'Nom de décompilateur ou image manquant' });
        return;
      }
      const actionLabel = mode === 'update' ? 'Updating' : mode === 'force' ? 'Repulling' : 'Pulling';
      panel.webview.postMessage({ type: 'hubDecompilerPullProgress', decompiler, line: `${actionLabel} ${image}…`, percent: 0 });
      let layersTotal = 0;
      let layersDone = 0;
      let lastError = '';
      const platform = String(message.platform || '').trim() || getKnownOciImagePlatform(image);
      const pullArgs = platform ? ['pull', '--platform', platform, image] : ['pull', image];
      _logDecompilerDocker(logChannel, 'pull.start', { decompiler, mode, image, platform });
      const proc = cp.spawn('docker', pullArgs, { env: process.env });
      let lastUiSummary = '';
      let lastUiSummaryAt = 0;
      const postPullSummary = (force = false) => {
        const summary = _pullProgressSummary(layersDone, layersTotal);
        if (!summary || summary === lastUiSummary) return;
        const now = Date.now();
        if (!force && now - lastUiSummaryAt < 500) return;
        lastUiSummary = summary;
        lastUiSummaryAt = now;
        const percent = layersTotal > 0 ? Math.min(100, Math.round((layersDone / layersTotal) * 100)) : null;
        panel.webview.postMessage({ type: 'hubDecompilerPullProgress', decompiler, line: summary, percent });
      };
      const handlePullChunk = (chunk: Buffer, isError = false) => {
        for (const line of chunk.toString().split('\n').filter(Boolean)) {
          if (/Pulling fs layer/i.test(line)) layersTotal++;
          if (/Pull complete|Already exists|Download complete/i.test(line)) layersDone++;
          const percent = layersTotal > 0 ? Math.min(100, Math.round((layersDone / layersTotal) * 100)) : null;
          const trimmed = line.trim();
          if (/Pulling from|Digest:|Status:|Downloaded newer image|Image is up to date/i.test(trimmed)) {
            panel.webview.postMessage({ type: 'hubDecompilerPullProgress', decompiler, line: trimmed, percent });
          } else {
            postPullSummary(false);
          }
          if (isError) lastError = line.trim();
        }
      };
      proc.stdout.on('data', (chunk: Buffer) => handlePullChunk(chunk, false));
      proc.stderr.on('data', (chunk: Buffer) => handlePullChunk(chunk, true));
      proc.on('close', async (code: number | null) => {
        const ok = code === 0;
        postPullSummary(true);
        _logDecompilerDocker(logChannel, ok ? 'pull.done' : 'pull.error', {
          decompiler,
          mode,
          image,
          platform,
          code,
          layersDone,
          layersTotal,
          error: ok ? '' : lastError,
        });
        panel.webview.postMessage({ type: 'hubDecompilerPullDone', decompiler, ok, error: ok ? null : lastError, mode });
        if (ok) {
          try {
            const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', 'auto']);
            const result = JSON.parse(stdout);
            panel.webview.postMessage({ type: 'hubDecompilerList', result });
            _postDockerRuntimeStatus(panel, { force: true, logChannel }).catch(() => {});
            _postDecompilerImageUpdateStatus(panel, result, { force: true, logChannel }).catch(() => {});
          } catch (_e) {
            _logDecompilerDocker(logChannel, 'pull.refresh.error', { decompiler, error: _e?.message || String(_e) });
          }
        }
      });
    },
    compilerBrowseSource: async (message = {}) => {
      const lang = String(message.lang || 'c');
      const filters: Record<string, string[]> = {
        c:    { 'C source': ['c', 'h'] },
        cpp:  { 'C++ source': ['cpp', 'cc', 'cxx', 'h', 'hpp'] },
        rust: { 'Rust source': ['rs'] },
        go:   { 'Go source': ['go'] },
      }[lang] || { 'Source': ['c', 'cpp', 'rs', 'go'] };
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: true, canSelectFolders: false, canSelectMany: false,
        openLabel: 'Choisir le fichier source',
        defaultUri: vscode.Uri.file(root),
        filters,
      });
      panel.webview.postMessage({
        type: 'compilerBrowseSourceResult',
        path: picked?.[0]?.fsPath || null,
      });
    },
    compilerBrowseOutput: async (message = {}) => {
      const target = String(message.target || 'elf-x64');
      const ext = target.startsWith('pe-') ? 'exe' : target.startsWith('macho-') ? '' : 'elf';
      const src = String(message.src || '');
      const stem = src ? path.basename(src, path.extname(src)) : 'output';
      const suggested = ext ? `${stem}.${ext}` : stem;
      const saved = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(root, suggested)),
        filters: ext ? { 'Binaire': [ext] } : { 'Binaire': ['*'] },
        title: 'Chemin du binaire de sortie',
      });
      panel.webview.postMessage({
        type: 'compilerBrowseOutputResult',
        path: saved?.fsPath || null,
      });
    },
    compilerListRequest: async () => {
      try {
        const { stdout } = await runPython(['backends/static/compile/compile.py', '--list'], { timeout: 30000 });
        const compilers = JSON.parse(stdout);
        panel.webview.postMessage({ type: 'compilerListResult', compilers });
      } catch (err) {
        panel.webview.postMessage({ type: 'compilerListResult', compilers: [], error: String(err) });
      }
    },
    compileRequest: async (message = {}) => {
      const { src, lang, target, output, flags } = message;
      if (!src || !lang || !target) {
        panel.webview.postMessage({ type: 'compileResult', error: 'src, lang et target sont requis.' });
        return;
      }
      try {
        const args: string[] = ['backends/static/compile/compile.py', '--src', src, '--lang', lang, '--target', target];
        if (output) args.push('--output', output);
        if (Array.isArray(flags) && flags.length) args.push('--flags', JSON.stringify(flags));
        const { stdout } = await runPython(args, { timeout: 180000 });
        const result = JSON.parse(stdout);
        panel.webview.postMessage({ type: 'compileResult', ...result });
      } catch (err) {
        panel.webview.postMessage({ type: 'compileResult', error: String(err) });
      }
    },
    hubExecuteCommand: async (message = {}) => {
      // Permet au webview de déclencher une commande VS Code enregistrée
      const commandId = String(message?.command || '').trim();
      const requestId = message?.requestId || null;
      if (!commandId) return;
      logChannel?.appendLine(`[hub] hubExecuteCommand START: ${commandId}`);

      const _sendResult = (status, detail = '') => {
        logChannel?.appendLine(`[hub] hubCommandResult: ${commandId} → ${status}${detail ? ' | ' + detail : ''}`);
        panel.webview.postMessage({ type: 'hubCommandResult', requestId, command: commandId, status, detail });
      };

      // Pour decompilerTest, on peut passer un ID pré-sélectionné depuis le webview
      const args = message?.args ? (Array.isArray(message.args) ? message.args : [message.args]) : [];

      try {
        await vscode.commands.executeCommand(commandId, ...args);
        _sendResult('done');

        // Après add/edit/remove, rafraîchir la liste automatiquement
        const MUTATING = ['pileOuFace.decompilerAdd', 'pileOuFace.decompilerEdit', 'pileOuFace.decompilerRemove'];
        if (MUTATING.includes(commandId)) {
          // Petit délai pour laisser le temps à la config d'être écrite
          await new Promise(r => setTimeout(r, 800));
          try {
            const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', 'auto']);
            panel.webview.postMessage({ type: 'hubDecompilerList', result: JSON.parse(stdout) });
          } catch (_) { /* intentional */ }
        }
        // Après test, pas de refresh liste nécessaire
      } catch (err) {
        _sendResult('error', err.message || String(err));
        // Ne pas afficher showErrorMessage pour les annulations (undefined)
        if (err.message && !err.message.includes('cancelled') && !err.message.includes('cancel')) {
          vscode.window.showErrorMessage(`Erreur commande ${commandId}: ${err.message || err}`);
        }
      }
    },
    hubLoadDecompile: async (message) => {
      const { binaryPath, addr, funcName, full, decompiler, provider, useCache = true } = message;
      const decompilersJsonPath = storageDir ? path.join(storageDir, 'decompilers.json') : '';

      // Build base args (annotation injection preserved)
      const buildArgs = (targetDecompiler) => {
        const args = ['backends/static/decompile/decompile.py', '--binary', binaryPath];
        if (full) args.push('--full');
        else if (addr) { args.push('--addr', addr); if (funcName) args.push('--func-name', funcName); }
        if (targetDecompiler) args.push('--decompiler', targetDecompiler);
        if (provider && provider !== 'auto') args.push('--provider', provider);
        if (!useCache) args.push('--no-cache');
        // annotation injection (keep existing logic)
        const absPath = path.isAbsolute(binaryPath) ? binaryPath : path.join(root, binaryPath);
        const annHash = crypto.createHash('sha256')
          .update(absPath)
          .update(fs.existsSync(absPath) ? String(fs.statSync(absPath).mtimeMs) : '')
          .digest('hex').slice(0, 16);
        const annPath = storageDir ? path.join(storageDir, 'annotations', `${annHash}.json`) : '';
        if (annPath && fs.existsSync(annPath)) args.push('--annotations-json', annPath);
        return args;
      };

      // Determine which decompilers to launch
      let targets = [];
      let decompilerTimeouts: Record<string, number> = {};
      if (decompiler && decompiler !== 'auto') {
        targets = [decompiler];
      } else {
        try {
          const listArgs = ['backends/static/decompile/decompile.py', '--list', '--provider', provider || 'auto', '--binary', binaryPath];
          if (full) listArgs.push('--full');
          const { stdout } = await runPython(listArgs);
          const available = JSON.parse(stdout);
          targets = Object.entries(available || {})
            .filter(([key, value]) => !String(key).startsWith('_') && value === true)
            .map(([key]) => key);
          decompilerTimeouts = available?._meta?.timeouts || {};
        } catch (_) {
          try {
            const cfg = JSON.parse(fs.readFileSync(decompilersJsonPath, 'utf8'));
            const decompilerMap = cfg.decompilers || cfg;
            targets = Object.keys(decompilerMap).filter(k => decompilerMap[k].enabled !== false);
            decompilerTimeouts = Object.fromEntries(
              Object.entries(decompilerMap).map(([k, v]: [string, any]) => [k, v.timeout || 120])
            );
          } catch (_) {
            targets = ['']; // fallback: single auto subprocess
          }
        }
      }

      // Post running status for each target
      for (const t of targets) {
        panel.webview.postMessage({ type: 'hubDecompileStatus', decompiler: t, status: 'running' });
      }

      let bestScore = -Infinity;
      let bestIndex = Infinity;
      let firstResult = true;

      const runOne = (t, targetIndex) => new Promise((resolve) => {
        const args = buildArgs(t || '');
        const timeoutMs = ((decompilerTimeouts[t] || 120) + 30) * 1000;
        runPython(args, { timeout: timeoutMs }).then(({ stdout }) => {
          let result;
          try { result = JSON.parse(stdout); } catch (_) { result = { ok: false, error: 'parse error' }; }
          const score = typeof result.score === 'number' ? result.score :
            (result.quality_details ? result.quality_details.selected_score : 0);
          if (result.error) {
            panel.webview.postMessage({ type: 'hubDecompileStatus', decompiler: t, status: 'error', errorReason: result.error || '' });
            if (firstResult) {
              firstResult = false;
              panel.webview.postMessage({
                type: 'hubDecompile',
                result,
                binaryPath,
                addr: addr || '',
                funcName: funcName || '',
                full: !!full,
                decompiler: t,
                score: 0,
                isSilentUpdate: false,
                provider: provider || 'auto',
              });
            }
          } else {
            panel.webview.postMessage({ type: 'hubDecompileStatus', decompiler: t, status: 'done', score });
            // Mirror Python's _select_best_function_candidate: higher score wins;
            // equal scores → prefer earlier entry in config order (lower targetIndex).
            const isBetter = score > bestScore || (score === bestScore && targetIndex < bestIndex);
            if (isBetter) { bestScore = score; bestIndex = targetIndex; }
            const isSilentUpdate = !firstResult;
            firstResult = false;
            panel.webview.postMessage({
              type: 'hubDecompile',
              result,
              binaryPath,
              addr: addr || '',
              funcName: funcName || '',
              full: !!full,
              decompiler: t,
              score,
              isSilentUpdate,
              isBetter,
              provider: provider || 'auto',
            });
          }
          resolve();
        }).catch((e) => {
          panel.webview.postMessage({ type: 'hubDecompileStatus', decompiler: t, status: 'error' });
          if (firstResult) {
            firstResult = false;
            panel.webview.postMessage({
              type: 'hubDecompile',
              result: { error: String(e) },
              binaryPath,
              addr: addr || '',
              funcName: funcName || '',
              full: !!full,
              decompiler: t,
              score: 0,
              isSilentUpdate: false,
              provider: provider || 'auto',
            });
          }
          resolve();
        });
      });

      if (targets.length === 0) {
        panel.webview.postMessage({
          type: 'hubDecompile',
          result: { error: 'Aucun décompilateur disponible' },
          binaryPath,
          addr: addr || '',
          funcName: funcName || '',
          full: !!full,
          decompiler: '',
          score: 0,
          isSilentUpdate: false,
          provider: provider || 'auto',
        });
      } else {
        await Promise.all(targets.map((t, i) => runOne(t, i)));
      }
    },
    hubLoadImports: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/binary/imports_analysis.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubImportsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubImportsDone', data: { error: String(e) } });
      }
    },
    hubLoadExports: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/binary/binary_exports.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubExportsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubExportsDone', data: { error: String(e) } });
      }
    },
    hubLoadImportXrefs: async (message) => {
      const { binaryPath, fnName } = message;
      try {
        const { stdout } = await runPython(['backends/static/disasm/import_xrefs.py', '--binary', binaryPath, '--function', fnName]);
        panel.webview.postMessage({ type: 'hubImportXrefsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubImportXrefsDone', data: { function: fnName, callsites: [], error: String(e) } });
      }
    },
    hubLoadHexView: async (message) => {
      const { binaryPath, offset = 0, length = 512 } = message;
      try {
        const args = [
          'backends/static/search/hex_view.py',
          '--binary', binaryPath,
          '--offset', String(offset),
          '--length', String(length),
        ];
        const rawBaseAddr = message?.binaryMeta?.rawConfig?.baseAddr || message?.rawBaseAddr || null;
        const rawArch = message?.binaryMeta?.rawConfig?.arch || message?.rawArch || null;
        const rawEndian = message?.binaryMeta?.rawConfig?.endian || message?.rawEndian || null;
        if (rawBaseAddr) args.push('--raw-base-addr', String(rawBaseAddr));
        if (rawArch) args.push('--raw-arch', String(rawArch));
        if (rawEndian) args.push('--raw-endian', String(rawEndian));
        const { stdout } = await runPython(args);
        panel.webview.postMessage({ type: 'hubHexView', result: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubHexView',
          result: { error: String(e), rows: [], sections: [] },
        });
      }
    },
    hubPatchBytes: async (message) => {
      const { binaryPath, offset, bytesHex } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/patch/patch_manager.py', 'apply',
          '--binary', binaryPath, '--offset', String(offset), '--bytes', bytesHex,
        ]);
        const result = JSON.parse(stdout);
        // Map to the shape the webview expects for hubPatchResult
        panel.webview.postMessage({
          type: 'hubPatchResult',
          result: {
            ok: result.ok,
            written: result.patch ? result.patch.patched_bytes.split(' ').length : 0,
            offset,
            error: result.error || null,
            patch: result.patch || null,
          },
        });
        if (result.ok) {
          const { stdout: ls } = await runPython(['backends/static/patch/patch_manager.py', 'list', '--binary', binaryPath]);
          panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        }
      } catch (e) {
        panel.webview.postMessage({ type: 'hubPatchResult', result: { ok: false, error: String(e) } });
      }
    },
    hubLoadPatches: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/patch/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubPatchesDone', data: { patches: [], error: String(e) } });
      }
    },
    hubRevertPatch: async (message) => {
      const { binaryPath, patchId } = message;
      try {
        const { stdout } = await runPython(['backends/static/patch/patch_manager.py', 'revert', '--binary', binaryPath, '--id', patchId]);
        const result = JSON.parse(stdout);
        const { stdout: ls } = await runPython(['backends/static/patch/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: true, patch: result.patch || null });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: false, error: String(e) });
      }
    },
    hubRedoPatch: async (message) => {
      const { binaryPath, patchId } = message;
      try {
        const args = ['backends/static/patch/patch_manager.py', 'redo', '--binary', binaryPath];
        if (patchId) args.push('--id', patchId);
        const { stdout } = await runPython(args);
        const result = JSON.parse(stdout);
        const { stdout: ls } = await runPython(['backends/static/patch/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        panel.webview.postMessage({ type: 'hubRedoPatchDone', ok: true, patch: result.patch || null });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRedoPatchDone', ok: false, error: String(e) });
      }
    },
    hubRevertAllPatches: async (message) => {
      const { binaryPath } = message;
      try {
        await runPython(['backends/static/patch/patch_manager.py', 'revert-all', '--binary', binaryPath]);
        const { stdout: ls } = await runPython(['backends/static/patch/patch_manager.py', 'list', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPatchesDone', data: JSON.parse(ls) });
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: true });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubRevertPatchDone', ok: false, error: String(e) });
      }
    },
    hubLoadStackFrame: async (message) => {
      const { binaryPath, addr } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/disasm/stack_frame.py',
          '--binary', binaryPath,
          '--addr', String(addr),
        ]);
        panel.webview.postMessage({
          type: 'hubStackFrame',
          binaryPath,
          addr: String(addr),
          result: JSON.parse(stdout),
        });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubStackFrame',
          binaryPath,
          addr: String(addr),
          result: { error: String(e), vars: [], args: [], frame_size: 0 },
        });
      }
    },
    hubRunScript: async (message) => {
      const { code, binaryPath } = message;
      try {
        const { stdout } = await runPython([
          'backends/static/repl/repl.py',
          '--code', code,
          '--binary', binaryPath || '',
        ]);
        panel.webview.postMessage({ type: 'hubScriptResult', result: JSON.parse(stdout) });
      } catch (e) {
        const stderr = e.stderr || String(e);
        panel.webview.postMessage({
          type: 'hubScriptResult',
          result: { ok: false, stdout: '', stderr, duration_ms: 0 },
        });
      }
    },
    hubLoadFunctions: async (message) => {
      const { binaryPath } = message;
      try {
        const [symRes, ccRes, radarRes] = await Promise.all([
          runPython(['backends/static/binary/symbols.py', '--binary', binaryPath, '--all']),
          runPython(['backends/static/disasm/calling_convention.py', '--binary', binaryPath]),
          runPython(['backends/static/analysis/function_radar.py', '--binary', binaryPath]),
        ]);
        const symbols = JSON.parse(symRes.stdout);
        const cc = JSON.parse(ccRes.stdout);
        const radar = JSON.parse(radarRes.stdout);
        panel.webview.postMessage({ type: 'hubFunctionsDone', data: { symbols, cc, radar } });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubFunctionsDone', data: { error: String(e) } });
      }
    },
    hubLoadPeResources: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/binary/pe_resources.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubPeResourcesDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubPeResourcesDone', data: { error: String(e), resources: [], count: 0 } });
      }
    },
    hubLoadExceptionHandlers: async (message) => {
      const { binaryPath } = message;
      try {
        const { stdout } = await runPython(['backends/static/exception_handlers.py', '--binary', binaryPath]);
        panel.webview.postMessage({ type: 'hubExceptionHandlersDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubExceptionHandlersDone', data: { error: String(e), entries: [], count: 0 } });
      }
    },
    hubLoadTypedData: async (message) => {
      const args = buildTypedDataArgs(message);
      try {
        const { stdout } = await runPython(args);
        panel.webview.postMessage({ type: 'hubTypedDataDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubTypedDataDone', data: { error: String(e), entries: [], sections: [] } });
      }
    },
    hubPreviewTypedStruct: async (message) => {
      const args = buildTypedDataArgs(message);
      try {
        const { stdout } = await runPython(args);
        panel.webview.postMessage({
          type: 'hubTypedStructPreviewDone',
          data: JSON.parse(stdout),
          request: {
            structName: message.structName || '',
            structAddr: message.structAddr || '',
            binaryPath: message.binaryPath || '',
          },
        });
      } catch (e) {
        panel.webview.postMessage({
          type: 'hubTypedStructPreviewDone',
          data: { error: String(e), entries: [], sections: [] },
          request: {
            structName: message.structName || '',
            structAddr: message.structAddr || '',
            binaryPath: message.binaryPath || '',
          },
        });
      }
    },
    hubLoadStructs: async () => {
      try {
        const { stdout } = await runPython(['backends/static/annotations/structs.py', 'list']);
        panel.webview.postMessage({ type: 'hubStructsDone', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubStructsDone', data: { error: String(e), structs: [], source: '' } });
      }
    },
    hubSaveStructs: async (message) => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'pof-structs-'));
      const sourceFile = path.join(tmpDir, 'structs.c');
      try {
        await fs.promises.writeFile(sourceFile, String(message.sourceText || ''), 'utf8');
        const { stdout } = await runPython(['backends/static/annotations/structs.py', 'save', '--source-file', sourceFile]);
        panel.webview.postMessage({ type: 'hubStructsSaved', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubStructsSaved', data: { error: String(e), structs: [], source: '' } });
      } finally {
        fs.rm(tmpDir, { recursive: true, force: true }, () => {});
      }
    },
    hubSaveTypedStructRef: async (message) => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'pof-typed-struct-ref-'));
      const structJson = path.join(tmpDir, 'applied-struct.json');
      try {
        await fs.promises.writeFile(structJson, JSON.stringify(message.appliedStruct || {}, null, 2), 'utf8');
        const { stdout } = await runPython([
          'backends/static/annotations/typed_struct_refs.py',
          'save',
          '--binary',
          String(message.binaryPath || ''),
          '--struct-json',
          structJson,
        ]);
        panel.webview.postMessage({ type: 'hubTypedStructRefSaved', data: JSON.parse(stdout) });
      } catch (e) {
        panel.webview.postMessage({ type: 'hubTypedStructRefSaved', data: { error: String(e), entries: [] } });
      } finally {
        fs.rm(tmpDir, { recursive: true, force: true }, () => {});
      }
    },
    'pof.auth.getState': async (_message) => {
      const authSvc = AuthService.getInstance(context.secrets, getAuthServerUrl());
      const loggedIn = await authSvc.isAuthenticated();
      if (loggedIn) {
        panel.webview.postMessage(await buildAccountStatePayload());
      } else {
        panel.webview.postMessage({ type: 'accountState', loggedIn: false });
      }
    },
    'pof.auth.login': async (message) => {
      const authSvc = AuthService.getInstance(
        context.secrets,
        getAuthServerUrl(),
      );
      const email = String(message?.email || '').trim();
      const password = String(message?.password || '').replace(/\r?\n/g, '');
      const passwordLength = password.length;
      if (logChannel?.appendLine) {
        logChannel.appendLine(`[auth] Login attempt email="${email}" passwordLength=${passwordLength} url=${getAuthServerUrl()}`);
      }
      try {
        await authSvc.login(email, password);
        panel.webview.postMessage(await buildAccountStatePayload({ email }));
        if (logChannel?.appendLine) {
          const profile = await authSvc.getProfile();
          const activeCount = Array.isArray(profile?.active_plugin_ids) ? profile.active_plugin_ids.length : 0;
          logChannel.appendLine(`[auth] Login success email="${email}" activePlugins=${activeCount}`);
        }
      } catch (err) {
        const detail = err instanceof Error ? err.message : 'Connexion échouée';
        if (logChannel?.appendLine) {
          logChannel.appendLine(`[auth] Login failed email="${email}" passwordLength=${passwordLength} url=${getAuthServerUrl()} detail=${detail}`);
        }
        panel.webview.postMessage({
          type: 'accountState',
          loggedIn: false,
          error: `${detail} (${getAuthServerUrl()}) [email=${email || 'empty'}, passwordLength=${passwordLength}]`,
        });
      }
    },
    'pof.auth.logout': async (_message) => {
      const authSvc = AuthService.getInstance(
        context.secrets,
        getAuthServerUrl(),
      );
      await authSvc.logout();
      panel.webview.postMessage({ type: 'accountState', loggedIn: false });
      await handlers.hubLoadPluginState();
    },
  };
  return handlers;
}

module.exports = staticHandlers;
