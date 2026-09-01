// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file decompilerCommands.js
 * @brief Commandes VS Code pour gérer les décompilateurs dynamiquement.
 *
 * Commandes enregistrées :
 *   pileOuFace.decompilerAdd        — Wizard complet d'ajout (Docker / local / les deux)
 *   pileOuFace.decompilerEdit       — Modifier un décompilateur custom existant
 *   pileOuFace.decompilerRemove     — Supprimer un décompilateur custom
 *   pileOuFace.decompilerList       — Lister tous les décompilateurs (avec statut dispo)
 *   pileOuFace.decompilerTest       — Tester un décompilateur sur un binaire
 *   pileOuFace.decompilerOpenConfig — Ouvrir storageDir/decompilers.json dans l'éditeur
 */

'use strict';

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildRuntimeEnv, resolveDockerExecutable, getExtensionPath } = require('../shared/utils');
const { recordRuntimeEvent } = require('../shared/runtimeAudit');

// ─── Constantes ───────────────────────────────────────────────────────────────

/** Tokens disponibles dans les commandes */
const TOKEN_HELP = 'Tokens : {binary} {addr} {func_name} {mode} {out}';

/** Formats de sortie supportés */
const OUTPUT_FORMATS = [
  { label: 'JSON (recommended)', description: 'JSON output {code, addr, functions…}', value: 'json' },
  { label: 'Raw C', description: 'Direct C code, automatically parsed into blocks', value: 'c' },
  { label: 'Raw text', description: 'Arbitrary output returned as-is', value: 'text' },
];

function _compareSemver(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

/** Ne garde que les tags de version X.Y.Z (exclut latest/develops/sha-*), triés décroissant. */
function _filterOciVersionTags(tags) {
  const semver = /^\d+\.\d+\.\d+$/;
  return (Array.isArray(tags) ? tags : [])
    .map((t) => String(t).trim())
    .filter((t) => semver.test(t))
    .sort((a, b) => _compareSemver(b, a));
}

/**
 * Liste les versions disponibles sur ghcr pour une image OCI PileOuFaces publique
 * (token anonyme du registre OCI → /tags/list). Retourne [] si hors-ligne / privé /
 * échec — l'appelant retombe alors sur la version épinglée du catalogue.
 */
async function _fetchOciVersions(imageRepo) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const tokenUrl = `https://ghcr.io/token?service=ghcr.io&scope=repository:${imageRepo}:pull`;
    const tokRes = await fetch(tokenUrl, { signal: controller.signal });
    if (!tokRes.ok) return [];
    const tok = await tokRes.json();
    const token = tok.token || tok.access_token;
    if (!token) return [];
    const tagsRes = await fetch(`https://ghcr.io/v2/${imageRepo}/tags/list`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });
    if (!tagsRes.ok) return [];
    const data = await tagsRes.json();
    return _filterOciVersionTags(data && data.tags);
  } catch (_) {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Métadonnées des décompilateurs OCI officiels PileOuFaces (« utiliser le nôtre »).
 * PAS de version ici : le tag est choisi au moment de l'ajout parmi les versions
 * publiées sur ghcr (fetch dynamique). On ne stocke que label/commandes/plateforme.
 */
let _ociDecompilersCache = null;
function ociDecompilers() {
  if (_ociDecompilersCache) return _ociDecompilersCache;
  _ociDecompilersCache = {
    ghidra: {
      label: 'Ghidra',
      description: 'Comprehensive open-source decompiler from the NSA',
      docker_command: ['/opt/pof-venv/bin/python3', '/opt/pof/decompile.py', '--binary', '{binary}', '--addr', '{addr}'],
      docker_full_command: ['/opt/pof-venv/bin/python3', '/opt/pof/decompile.py', '--binary', '{binary}', '--full'],
      output_format: 'json',
      timeout: 180,
      env: { GHIDRA_INSTALL_DIR: '/opt/ghidra' },
    },
    retdec: {
      label: 'RetDec',
      description: 'Lightweight and fast C decompiler from Avast',
      docker_command: ['retdec-decompiler', '--select-decode-only', '--select-functions', '{func_name}', '-o', '{out}', '{binary}'],
      docker_full_command: ['retdec-decompiler', '-o', '{out}', '{binary}'],
      output_format: 'c',
      timeout: 120,
      env: null,
      platform: 'linux/amd64', // binaire pré-compilé amd64-only
    },
    angr: {
      label: 'Angr',
      description: 'Symbolic Python binary-analysis framework',
      docker_command: ['/opt/pof-venv/bin/python3', '/opt/pof/decompile.py', '--binary', '{binary}', '--addr', '{addr}'],
      docker_full_command: ['/opt/pof-venv/bin/python3', '/opt/pof/decompile.py', '--binary', '{binary}', '--full'],
      output_format: 'json',
      timeout: 180,
      env: null,
    },
  };
  return _ociDecompilersCache;
}

// ─── Helpers config ───────────────────────────────────────────────────────────

function _configPath(storageDir) {
  return path.join(storageDir, 'decompilers.json');
}

function _readConfig(storageDir) {
  const p = _configPath(storageDir);
  try {
    if (!fs.existsSync(p)) return { decompilers: {} };
    const raw = fs.readFileSync(p, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.decompilers || typeof parsed.decompilers !== 'object') return { decompilers: {} };
    return parsed;
  } catch (_) {
    return { decompilers: {} };
  }
}

function _writeConfig(storageDir, config) {
  if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir, { recursive: true });
  fs.writeFileSync(_configPath(storageDir), JSON.stringify(config, null, 2), 'utf8');
}

function _normalizeId(id) {
  return String(id || '').toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '');
}

/** Vérifie si une image Docker est disponible localement (synchrone, rapide). */
function _checkDockerImageSync(image) {
  try {
    const dockerExe = resolveDockerExecutable();
    const r = cp.spawnSync(dockerExe, ['image', 'inspect', image], {
      encoding: 'utf8',
      timeout: 4000,
      env: buildRuntimeEnv(''),
    });
    return r.status === 0;
  } catch (_) {
    return false;
  }
}

/** Retourne les images Docker locales dont le nom contient `hint` */
function _suggestDockerImages(hint) {
  try {
    const dockerExe = resolveDockerExecutable();
    const r = cp.spawnSync(
      dockerExe, ['images', '--format', '{{.Repository}}:{{.Tag}}'],
      { encoding: 'utf8', timeout: 4000, env: buildRuntimeEnv('') }
    );
    if (r.status !== 0) return [];
    return r.stdout.split('\n').map(s => s.trim()).filter(s => s && s !== '<none>:<none>');
  } catch (_) {
    return [];
  }
}

function _dockerMissingImageHint(id, image) {
  const normalizedImage = String(image || '').trim().toLowerCase();
  if (normalizedImage.startsWith('ghcr.io/pileoufaces/')) {
    return `Run \`docker pull ${image}\` or use the Download button in Settings.`;
  }
  return `Run 'docker pull ${image}' or use a valid registry image.`;
}

// ─── Auto-check silencieux (partagé) ─────────────────────────────────────────

/**
 * Lance --list en arrière-plan et notifie l'utilisateur du résultat.
 * Appelé après chaque ajout/modification de décompilateur.
 */
async function _autoCheckDecompiler(root, storageDir, id, label) {
  let result = null;
  let timedOut = false;

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Checking "${label || id}"…`, cancellable: true },
    async (_progress, token) => {
      const pythonExe = _findPythonExe(root);
      const child = cp.spawn(
        pythonExe,
        [path.join(getExtensionPath() || root, 'backends/static/decompile/decompile.py'), '--list', '--provider', 'auto'],
        { encoding: 'utf8', cwd: root, env: buildRuntimeEnv(root, storageDir) },
      );
      let stdout = '';
      let killed = false;
      child.stdout.on('data', (d) => { stdout += d; });

      const killTimer = setTimeout(() => {
        killed = true;
        timedOut = true;
        child.kill('SIGTERM');
      }, 12000);

      token.onCancellationRequested(() => {
        killed = true;
        clearTimeout(killTimer);
        child.kill('SIGTERM');
      });

      await new Promise((resolve) => child.on('close', resolve));
      clearTimeout(killTimer);

      if (!killed && stdout.trim()) {
        try { result = JSON.parse(stdout.trim()); } catch (_e) { /* intentional */ }
      }
    }
  );

  if (timedOut) {
    const action = await vscode.window.showWarningMessage(
      `"${label || id}" was added, but the check took too long (slow Docker?). Test it manually.`,
      'Test manually', 'OK'
    );
    if (action === 'Test manually') await cmdDecompilerTest(root, storageDir, null, id);
    return;
  }
  if (!result) return;

  const isAvailable = !!result[id];
  const meta = result._meta || {};
  const localOk = !!(meta.local_available || {})[id];
  const dockerOk = !!(meta.docker_images_available || {})[id];
  const dockerImage = (meta.docker_images || {})[id] || '';

  if (isAvailable) {
    const via = localOk ? 'local' : dockerOk ? `Docker (${dockerImage})` : 'auto';
    const action = await vscode.window.showInformationMessage(
      `"${label || id}" is ready — available through ${via}.`,
      'Test a decompilation', 'OK'
    );
    if (action === 'Test a decompilation') await cmdDecompilerTest(root, storageDir, null, id);
  } else {
    const why = !dockerImage
      ? 'No Docker image is configured and the tool was not found locally.'
      : !dockerOk
        ? `Docker image "${dockerImage}" not found — use the Download button in Settings.`
        : 'Tool not detected locally (executable not found in PATH).';
    const action = await vscode.window.showWarningMessage(
      `"${label || id}" is configured but unavailable. ${why}`,
      'Test anyway', 'Open JSON config', 'OK'
    );
    if (action === 'Test anyway') await cmdDecompilerTest(root, storageDir, null, id);
    else if (action === 'Open JSON config') await cmdDecompilerOpenConfig(storageDir);
  }
}

/**
 * Lance `docker pull <image>` avec une barre de progression VS Code.
 * Retourne true si le pull a réussi.
 */
async function _pullOciImageWithProgress(image, label, platform = '') {
  let ok = false;
  let lastError = '';
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Downloading ${label}…`, cancellable: true },
    async (progress, token) => {
      const dockerExe = resolveDockerExecutable();
      const pullArgs = platform ? ['pull', '--platform', platform, image] : ['pull', image];
      const proc = cp.spawn(dockerExe, pullArgs, { env: buildRuntimeEnv('') });
      let layersTotal = 0;
      let layersDone = 0;
      let killed = false;

      token.onCancellationRequested(() => { killed = true; proc.kill('SIGTERM'); });

      proc.stdout.on('data', (chunk) => {
        for (const line of chunk.toString().split('\n').filter(Boolean)) {
          if (/Pulling fs layer/i.test(line)) layersTotal++;
          if (/Pull complete/i.test(line)) layersDone++;
          const pct = layersTotal > 0 ? Math.round((layersDone / layersTotal) * 100) : undefined;
          progress.report({ message: line.trim(), increment: pct });
        }
      });

      proc.stderr.on('data', (chunk) => {
        lastError = chunk.toString().trim();
      });

      await new Promise((resolve) => proc.on('close', (code) => {
        if (!killed) ok = code === 0;
        resolve(undefined);
      }));
    }
  );
  if (ok) {
    vscode.window.showInformationMessage(`Image "${image}" downloaded successfully.`);
  } else {
    const hint = /not found|manifest unknown|does not exist/i.test(lastError)
      ? 'Image not found in the registry — the PileOuFaces images may not have been published yet.'
      : /unauthorized|denied/i.test(lastError)
        ? 'Access denied — run `docker login ghcr.io` if the registry is private.'
        : lastError || 'Unknown error.';
    vscode.window.showErrorMessage(`Failed to download "${image}": ${hint}`);
  }
  return ok;
}

// ─── Wizard d'ajout / modification ───────────────────────────────────────────

/**
 * Wizard structuré en étapes claires.
 * @param {string} root
 * @param {string} storageDir
 * @param {string|null} editId — ID existant à modifier (null = ajout)
 */
async function cmdDecompilerAdd(root, storageDir, editId = null) {
  const cfg = _readConfig(storageDir);
  const isEdit = editId !== null;
  const existing = isEdit ? (cfg.decompilers[editId] || {}) : {};

  // ── ÉTAPE 1 : Mode d'exécution ────────────────────────────────────────────
  const modeChoice = await vscode.window.showQuickPick(
    [
      {
        label: '$(cloud) Container Docker',
        description: 'Official PileOuFaces Docker images or a custom image',
        detail: 'Ideal for Ghidra, RetDec, and Angr — no local installation required',
        value: 'docker',
      },
      {
        label: '$(terminal) Local only',
        description: 'The tool is installed on your machine',
        detail: 'Faster and does not require Docker',
        value: 'local',
      },
      {
        label: '$(repo-sync) Local + Container (fallback)',
        description: 'Try locally first, then Docker if unavailable',
        detail: 'Pile ou Face auto mode manages fallback automatically',
        value: 'both',
      },
    ],
    {
      title: isEdit ? `Edit "${editId}" — Mode` : 'Add a decompiler — Execution mode',
      placeHolder: 'How should this decompiler run?',
    }
  );
  if (!modeChoice) return;
  const mode = modeChoice.value;

  let id = isEdit ? editId : null;
  let label = isEdit ? (existing.label || editId) : '';
  const config = {};

  // ── ÉTAPE 2 : Source de l'image Docker ───────────────────────────────────
  if (mode === 'docker' || mode === 'both') {
    let dockerSource = 'custom';

    if (!isEdit) {
      const sourceChoice = await vscode.window.showQuickPick(
        [
          {
            label: '$(package) PileOuFaces images',
            description: 'Ghidra, RetDec, and Angr — official images maintained by PileOuFaces',
            detail: 'Automatic one-click configuration',
            value: 'oci',
          },
          {
            label: '$(tools) Custom image',
            description: 'Your own registry, custom image, or third-party image',
            detail: 'Enter the image and commands manually',
            value: 'custom',
          },
        ],
        {
          title: 'Add a decompiler — Image source',
          placeHolder: 'Which type of Docker image?',
        }
      );
      if (!sourceChoice) return;
      dockerSource = sourceChoice.value;
    }

    // ── ÉTAPE 3a : Image OCI PileOuFaces ─────────────────────────────────
    if (dockerSource === 'oci') {
      const ociChoices = Object.entries(ociDecompilers()).map(([key, d]) => {
        const alreadyHere = !!cfg.decompilers[key];
        const localAvail = _checkDockerImageSync(`ghcr.io/pileoufaces/pile-ou-face/decompiler-${key}:latest`);
        const statusIcon = localAvail ? '$(check)' : '$(cloud-download)';
        const statusDetail = localAvail
          ? 'Image available locally'
          : 'Image must be downloaded from ghcr.io/pileoufaces';
        return {
          label: `${statusIcon} ${d.label}${alreadyHere ? ' (already configured)' : ''}`,
          description: d.description,
          detail: statusDetail,
          value: key,
        };
      });

      const ociPicked = await vscode.window.showQuickPick(ociChoices, {
        title: 'PileOuFaces images — Choose a decompiler',
        placeHolder: 'Select the decompiler to install',
      });
      if (!ociPicked) return;

      const ociKey = ociPicked.value;
      const ociDef = ociDecompilers()[ociKey];

      // Confirmer si déjà présent
      if (cfg.decompilers[ociKey]) {
        const overwrite = await vscode.window.showWarningMessage(
          `Decompiler "${ociKey}" already exists in your configuration. Overwrite it?`,
          { modal: true },
          'Overwrite'
        );
        if (overwrite !== 'Overwrite') return;
      }

      // ── Choix de la version (toutes les versions publiées sur ghcr) ──────
      const imageRepo = `pileoufaces/pile-ou-face/decompiler-${ociKey}`;
      // Liste 100 % dynamique : uniquement les versions publiées sur ghcr, plus
      // récente en tête (= recommandée ; les breaking changes vont au CHANGELOG).
      const versions = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `Looking up ${ociDef.label} versions on ghcr…`,
          cancellable: false,
        },
        () => _fetchOciVersions(imageRepo),
      );
      let chosenVersion;
      if (versions.length >= 1) {
        const versionPick = await vscode.window.showQuickPick(
          versions.map((v, i) => ({
            label: i === 0 ? `$(star-full) ${v}` : v,
            description: i === 0 ? 'latest (recommended)' : '',
            value: v,
          })),
          {
            title: `${ociDef.label} — Choose a version`,
            placeHolder: `${versions.length} version(s) published on ghcr`,
          },
        );
        if (!versionPick) return;
        chosenVersion = versionPick.value;
      } else {
        const fallback = await vscode.window.showWarningMessage(
          `Unable to list ${ociDef.label} versions on ghcr (offline or no published versions). Use the "latest" tag?`,
          { modal: true },
          'Use latest',
        );
        if (fallback !== 'Use latest') return;
        chosenVersion = 'latest';
      }
      const chosenImage = `ghcr.io/pileoufaces/pile-ou-face/decompiler-${ociKey}:${chosenVersion}`;

      // Auto-configuration complète depuis le catalogue OCI
      id = ociKey;
      label = ociDef.label;
      const ociConfig: Record<string, unknown> = {
        label: ociDef.label,
        docker_image: chosenImage,
        docker_command: ociDef.docker_command,
        docker_full_command: ociDef.docker_full_command,
        supports_full: true,
        output_format: ociDef.output_format,
        timeout: ociDef.timeout,
      };
      if (ociDef.env) ociConfig.env = ociDef.env;
      if (ociDef.platform) ociConfig.docker_platform = ociDef.platform;

      // Si mode === 'both', on demande quand même la commande locale
      if (mode === 'both') {
        const localCmd = await vscode.window.showInputBox({
          title: `"${id}" — Local command (function decompilation)`,
          prompt: TOKEN_HELP,
          value: existing.command ? existing.command.join(' ') : `${id} --json {binary} --addr {addr}`,
          validateInput: (v) => (v.trim() ? null : 'A command is required'),
        });
        if (localCmd === undefined) return;
        ociConfig.command = _splitCommand(localCmd.trim());

        const localFullCmd = await vscode.window.showInputBox({
          title: `"${id}" — Local command (whole binary, optional)`,
          prompt: TOKEN_HELP + '  •  Leave blank to disable --full locally',
          value: '',
        });
        if (localFullCmd === undefined) return;
        if (localFullCmd.trim()) ociConfig.full_command = _splitCommand(localFullCmd.trim());
      }

      // Enregistrement immédiat — le wizard se termine ici
      cfg.decompilers[id] = ociConfig;
      _writeConfig(storageDir, cfg);
      _autoCheckDecompiler(root, storageDir, id, label);

      // Proposer de télécharger l'image si absente — fire-and-forget (non-bloquant)
      const imageReady = _checkDockerImageSync(ociDef.image);
      if (!imageReady) {
        (async () => {
          const pullNow = await vscode.window.showInformationMessage(
            `"${ociDef.label}" has not been downloaded yet (${ociDef.image}).`,
            'Download now', 'Later'
          );
          if (pullNow === 'Download now') {
            await _pullOciImageWithProgress(ociDef.image, ociDef.label, ociDef.platform || '');
          }
        })().catch(() => {});
      }

      return;
    }

    // ── ÉTAPE 3b : Image personnalisée ───────────────────────────────────
    // Demander l'ID si pas encore connu
    if (!id) {
      const rawId = await vscode.window.showInputBox({
        title: 'New decompiler — Identifier',
        prompt: 'Unique identifier (letters, digits, and hyphens). For example: binja, idalite, my-tool',
        value: '',
        validateInput: (v) => {
          const n = _normalizeId(v);
          if (!n) return 'Invalid ID (use letters, digits, and hyphens)';
          if (cfg.decompilers[n]) return `"${n}" already exists — use Edit to change it`;
          return null;
        },
      });
      if (rawId === undefined) return;
      id = _normalizeId(rawId);

      const labelInput = await vscode.window.showInputBox({
        title: `"${id}" — Display name`,
        prompt: 'Label displayed in the Pile ou Face interface',
        value: id,
      });
      if (labelInput === undefined) return;
      label = labelInput || id;
    }

    const localImages = _suggestDockerImages(id);
    const defaultImage = existing.docker_image
      || localImages.find(i => i.includes(id))
      || `ghcr.io/myregistry/decompiler-${id}:latest`;

    const dockerImage = await vscode.window.showInputBox({
      title: `"${id}" — Image Docker`,
      prompt: localImages.length
        ? `Available images: ${localImages.slice(0, 3).join(', ')}`
        : 'Ex: ghcr.io/myregistry/decompiler-mytool:latest',
      value: defaultImage,
      validateInput: (v) => {
        if (!v.trim()) return 'An image is required';
        if (v.includes(' ')) return 'The image name must not contain spaces';
        return null;
      },
    });
    if (dockerImage === undefined) return;
    config.docker_image = dockerImage.trim();

    const imageOk = _checkDockerImageSync(config.docker_image);
    if (!imageOk) {
      const cont = await vscode.window.showWarningMessage(
        `Image "${config.docker_image}" is not available locally. ${_dockerMissingImageHint(id, config.docker_image)}`,
        { modal: false },
        'Continue anyway', 'Cancel'
      );
      if (cont !== 'Continue anyway') return;
    }

    const dockerCmd = await vscode.window.showInputBox({
      title: `"${id}" — Docker command (function decompilation)`,
      prompt: TOKEN_HELP + '  •  Leave blank if unsupported',
      value: existing.docker_command ? existing.docker_command.join(' ') : `/usr/bin/${id} --json {binary} --addr {addr}`,
      validateInput: (v) => {
        if (!v.trim() && mode === 'docker') return 'A command is required for Docker-only mode';
        return null;
      },
    });
    if (dockerCmd === undefined) return;
    if (dockerCmd.trim()) config.docker_command = _splitCommand(dockerCmd.trim());

    const dockerFullCmd = await vscode.window.showInputBox({
      title: `"${id}" — Docker command (whole binary, optional)`,
      prompt: TOKEN_HELP + '  •  Leave blank to disable --full',
      value: existing.docker_full_command ? existing.docker_full_command.join(' ') : '',
    });
    if (dockerFullCmd === undefined) return;
    if (dockerFullCmd.trim()) {
      config.docker_full_command = _splitCommand(dockerFullCmd.trim());
      config.supports_full = true;
    }
  }

  // ── ÉTAPE 4 : Configuration locale ───────────────────────────────────────
  if (mode === 'local' || mode === 'both') {
    // Demander l'ID si on n'est pas passé par le chemin Docker
    if (!id) {
      const rawId = await vscode.window.showInputBox({
        title: isEdit ? `Edit "${editId}" — ID` : 'New decompiler — Identifier',
        prompt: 'Unique identifier (letters, digits, and hyphens). For example: binja, idalite, my-tool',
        value: isEdit ? editId : '',
        validateInput: (v) => {
          const n = _normalizeId(v);
          if (!n) return 'Invalid ID (use letters, digits, and hyphens)';
          if (!isEdit && cfg.decompilers[n]) return `"${n}" already exists`;
          return null;
        },
      });
      if (rawId === undefined) return;
      id = _normalizeId(rawId);

      const labelInput = await vscode.window.showInputBox({
        title: `"${id}" — Display name`,
        prompt: 'Label displayed in the Pile ou Face interface',
        value: existing.label || id,
      });
      if (labelInput === undefined) return;
      label = labelInput || id;
    }

    const localCmd = await vscode.window.showInputBox({
      title: `"${id}" — Local command (function decompilation)`,
      prompt: TOKEN_HELP,
      value: existing.command ? existing.command.join(' ') : `${id} --json {binary} --addr {addr}`,
      validateInput: (v) => (v.trim() ? null : 'A command is required'),
    });
    if (localCmd === undefined) return;
    config.command = _splitCommand(localCmd.trim());

    const localFullCmd = await vscode.window.showInputBox({
      title: `"${id}" — Local command (whole binary, optional)`,
      prompt: TOKEN_HELP + '  •  Leave blank to disable --full locally',
      value: existing.full_command ? existing.full_command.join(' ') : '',
    });
    if (localFullCmd === undefined) return;
    if (localFullCmd.trim()) {
      config.full_command = _splitCommand(localFullCmd.trim());
      config.supports_full = true;
    }
  }

  if (!id) return;
  config.label = label || id;

  // ── ÉTAPE 5 : Options avancées (optionnel) ────────────────────────────────
  const advanced = await vscode.window.showQuickPick(
    [
      { label: '$(check) Save now', description: 'Use default values', value: 'save' },
      { label: '$(settings-gear) Configure advanced options', description: 'Output format, timeout, environment variables, Docker network…', value: 'advanced' },
    ],
    { title: `"${id}" — Finish` }
  );
  if (!advanced) return;

  if (advanced.value === 'advanced') {
    const fmtChoice = await vscode.window.showQuickPick(OUTPUT_FORMATS, {
      title: `"${id}" — Output format`,
      placeHolder: 'How the decompiler returns its results',
    });
    if (!fmtChoice) return;
    if (fmtChoice.value !== 'json') config.output_format = fmtChoice.value;

    const timeoutStr = await vscode.window.showInputBox({
      title: `"${id}" — Timeout (seconds)`,
      prompt: 'Maximum execution time. Defaults to 120 for a function and 300 for --full.',
      value: existing.timeout ? String(existing.timeout) : '',
      placeHolder: 'Leave blank to use the default value',
      validateInput: (v) => {
        if (!v.trim()) return null;
        const n = parseInt(v, 10);
        if (isNaN(n) || n < 5) return 'Entier ≥ 5';
        return null;
      },
    });
    if (timeoutStr === undefined) return;
    if (timeoutStr.trim()) config.timeout = parseInt(timeoutStr.trim(), 10);

    if (mode !== 'docker') {
      const envStr = await vscode.window.showInputBox({
        title: `"${id}" — Environment variables (optional)`,
        prompt: 'Format: KEY=value,KEY2=value2. These variables are injected during local execution.',
        value: existing.env ? Object.entries(existing.env).map(([k, v]) => `${k}=${v}`).join(',') : '',
        placeHolder: 'Ex: TOOL_HOME=/opt/mytool,JAVA_OPTS=-Xmx2g',
      });
      if (envStr === undefined) return;
      if (envStr.trim()) config.env = _parseEnvString(envStr.trim());
    }

    if (mode !== 'local') {
      const networkChoice = await vscode.window.showQuickPick(
        [
          { label: 'none (recommended)', description: 'No network access — maximum isolation', value: 'none' },
          { label: 'bridge', description: 'Internet access through the Docker bridge', value: 'bridge' },
          { label: 'host', description: 'Share the host network', value: 'host' },
        ],
        { title: `"${id}" — Docker network` }
      );
      if (!networkChoice) return;
      if (networkChoice.value !== 'none') config.network = networkChoice.value;

      const dockerEnvStr = await vscode.window.showInputBox({
        title: `"${id}" — Docker environment variables (optional)`,
        prompt: 'Injected through -e in docker run. Format: KEY=value,KEY2=value2',
        value: existing.env ? Object.entries(existing.env).map(([k, v]) => `${k}=${v}`).join(',') : '',
        placeHolder: 'Ex: TOOL_HOME=/opt/tool,LICENSE_KEY=xxx',
      });
      if (dockerEnvStr === undefined) return;
      if (dockerEnvStr.trim()) config.env = _parseEnvString(dockerEnvStr.trim());

      const extraArgs = await vscode.window.showInputBox({
        title: `"${id}" — Additional docker run arguments (optional)`,
        prompt: 'Added before the image name. For example: --memory 2g --cpus 2',
        value: existing.docker_extra_args ? existing.docker_extra_args.join(' ') : '',
        placeHolder: 'Leave blank if unnecessary',
      });
      if (extraArgs === undefined) return;
      if (extraArgs.trim()) config.docker_extra_args = _splitCommand(extraArgs.trim());
    }
  }

  // ── ÉTAPE 6 : Enregistrement ──────────────────────────────────────────────
  if (isEdit) delete cfg.decompilers[editId];
  cfg.decompilers[id] = config;
  _writeConfig(storageDir, cfg);

  _autoCheckDecompiler(root, storageDir, id, label);
}

// ─── Helpers wizard ───────────────────────────────────────────────────────────

/** Découpe une commande en tenant compte des guillemets simples/doubles. */
function _splitCommand(str) {
  const parts = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  for (const ch of str) {
    if (ch === "'" && !inDouble) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; continue; }
    if (ch === ' ' && !inSingle && !inDouble) {
      if (current) { parts.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current) parts.push(current);
  return parts;
}

/** Parse "KEY=value,KEY2=value2" → { KEY: "value", KEY2: "value2" } */
function _parseEnvString(str) {
  const result = {};
  for (const pair of str.split(',')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) result[k] = v;
    }
  }
  return result;
}

/** Génère un résumé texte de la config */
function _buildSummary(id, config, mode) {
  const lines = [`ID: ${id}`, `Mode: ${mode}`];
  if (config.docker_image) lines.push(`Image Docker: ${config.docker_image}`);
  if (config.docker_command) lines.push(`Cmd Docker: ${config.docker_command.join(' ')}`);
  if (config.command) lines.push(`Local command: ${config.command.join(' ')}`);
  if (config.output_format) lines.push(`Format: ${config.output_format}`);
  if (config.timeout) lines.push(`Timeout: ${config.timeout}s`);
  return lines.join('\n');
}

// ─── Commande : modifier ──────────────────────────────────────────────────────

async function cmdDecompilerEdit(root, storageDir, preselectedId = null) {
  const cfg = _readConfig(storageDir);
  const ids = Object.keys(cfg.decompilers);
  if (ids.length === 0) {
    vscode.window.showInformationMessage('No custom decompiler to edit.');
    return;
  }
  if (preselectedId && ids.includes(preselectedId)) {
    await cmdDecompilerAdd(root, storageDir, preselectedId);
    return;
  }
  const picked = await vscode.window.showQuickPick(
    ids.map((id) => {
      const d = cfg.decompilers[id];
      const badges = [];
      if (d.docker_image) badges.push('🐳 Docker');
      if (d.command) badges.push('💻 Local');
      return { label: d.label || id, description: id, detail: badges.join('  '), value: id };
    }),
    { title: 'Edit a custom decompiler', placeHolder: 'Choose…' }
  );
  if (!picked) return;
  await cmdDecompilerAdd(root, storageDir, picked.value);
}

// ─── Commande : supprimer ─────────────────────────────────────────────────────

async function cmdDecompilerRemove(root, storageDir, preselectedId = null) {
  const cfg = _readConfig(storageDir);
  const ids = Object.keys(cfg.decompilers).filter(id => !id.startsWith('_'));
  if (ids.length === 0) {
    vscode.window.showInformationMessage('No decompiler is configured.');
    return;
  }
  if (preselectedId && ids.includes(preselectedId)) {
    const direct = cfg.decompilers[preselectedId];
    const confirmDirect = await vscode.window.showWarningMessage(
      `Delete decompiler "${direct.label || preselectedId}" (${preselectedId})?`,
      { modal: true },
      'Delete'
    );
    if (confirmDirect !== 'Delete') return;
    delete cfg.decompilers[preselectedId];
    _writeConfig(storageDir, cfg);
    vscode.window.showInformationMessage(`Decompiler "${direct.label || preselectedId}" deleted.`);
    return;
  }
  const picked = await vscode.window.showQuickPick(
    ids.map((id) => ({
      label: cfg.decompilers[id].label || id,
      description: id,
      detail: [
        cfg.decompilers[id].docker_image ? `🐳 ${cfg.decompilers[id].docker_image}` : '',
        cfg.decompilers[id].command ? '💻 local' : '',
      ].filter(Boolean).join('  '),
    })),
    { title: 'Delete a decompiler', placeHolder: 'Choose the decompiler to delete' }
  );
  if (!picked) return;
  const confirm = await vscode.window.showWarningMessage(
    `Delete decompiler "${picked.label}" (${picked.description})?`,
    { modal: true },
    'Delete'
  );
  if (confirm !== 'Delete') return;
  delete cfg.decompilers[picked.description];
  _writeConfig(storageDir, cfg);
  vscode.window.showInformationMessage(`Decompiler "${picked.label}" deleted.`);
}

// ─── Commande : ouvrir config JSON ───────────────────────────────────────────

async function cmdDecompilerOpenConfig(storageDir) {
  const p = _configPath(storageDir);
  if (!fs.existsSync(p)) {
    _writeConfig(storageDir, {
      decompilers: {
        '_example': {
          label: 'My tool (example)',
          docker_image: 'registry/mon-outil:latest',
          docker_command: ['/usr/bin/mon-outil', '--json', '{binary}', '--addr', '{addr}'],
          docker_full_command: ['/usr/bin/mon-outil', '--json', '{binary}', '--full'],
          command: ['mon-outil', '--json', '{binary}', '--addr', '{addr}'],
          full_command: ['mon-outil', '--json', '{binary}', '--full'],
          supports_full: true,
          output_format: 'json',
          timeout: 120,
          network: 'none',
        },
      },
    });
    vscode.window.showInformationMessage('decompilers.json was created with an example — customize it as needed.');
  }
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(p));
  await vscode.window.showTextDocument(doc);
}

// ─── Commande : lister ────────────────────────────────────────────────────────

async function cmdDecompilerList(root, runPython, logChannel) {
  try {
    const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', 'auto'], { cwd: root });
    const data = JSON.parse(stdout.trim());
    const meta = data._meta || {};
    const dockerImages = meta.docker_images || {};
    const dockerAvail = meta.docker_images_available || {};
    const lines = ['', '═══ Available decompilers ═══', ''];
    const allIds = Object.keys(data).filter(k => !k.startsWith('_'));

    for (const key of allIds) {
      const avail = !!data[key];
      const label = (meta.labels || {})[key] || key;
      const image = dockerImages[key] || '';
      const dockerOk = image ? (dockerAvail[key] ? '🐳✓' : '🐳✗') : '  ';
      const localOk = avail ? '💻✓' : '💻✗';
      const imagePart = image ? `  (${image})` : '';
      lines.push(`  ${avail ? '✅' : '❌'} ${label.padEnd(18)} ${localOk}  ${dockerOk}${imagePart}`);
    }
    lines.push('');
    lines.push(`Provider: ${meta.provider || 'auto'}`);
    lines.push('');
    logChannel.appendLine(lines.join('\n'));
    logChannel.show(true);
  } catch (e) {
    vscode.window.showErrorMessage(`Failed to list decompilers: ${e.message || e}`);
  }
}

// ─── Commande : tester ────────────────────────────────────────────────────────

async function cmdDecompilerTest(root, storageDir, runPython, preselectedId = null) {
  // 1. Récupérer la liste
  let decompilerData = {};
  if (runPython) {
    try {
      const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', 'auto'], { cwd: root });
      decompilerData = JSON.parse(stdout.trim());
    } catch (_) { /* intentional */ }
  }

  // 2. Choisir le décompilateur
  let targetId = preselectedId;
  if (!targetId) {
    const allIds = Object.keys(decompilerData).filter(k => !k.startsWith('_'));
    const choices = allIds.map(id => {
      const avail = !!decompilerData[id];
      const meta = decompilerData._meta || {};
      const label = (meta.labels || {})[id] || id;
      const image = (meta.docker_images || {})[id] || '';
      const dockerOk = image ? !!(meta.docker_images_available || {})[id] : null;
      const localOk = !!(meta.local_available || {})[id];
      return {
        label: `${avail ? '$(check)' : '$(x)'} ${label}`,
        description: 'configured',
        detail: [
          localOk ? '💻 local backend ready' : '💻 local backend unavailable',
          dockerOk === true ? `🐳 image ready (${image})` : dockerOk === false ? `🐳 image missing` : '🐳 no Docker runtime declared',
        ].filter(Boolean).join('  '),
        value: id,
      };
    });
    const picked = await vscode.window.showQuickPick(choices, {
      title: 'Test a decompiler — choose the backend',
      placeHolder: 'All backends are listed, including unavailable ones',
    });
    if (!picked) return;
    targetId = picked.value;
  }

  // 3. Choisir le provider
  const providerChoice = await vscode.window.showQuickPick(
    [
      { label: 'auto', description: 'Local if available, otherwise Docker', value: 'auto' },
      { label: 'local', description: 'Force local execution', value: 'local' },
      { label: 'docker', description: 'Force Docker execution', value: 'docker' },
    ],
    { title: `Test "${targetId}" — Provider` }
  );
  if (!providerChoice) return;

  // 4. Choisir le binaire
  const uris = await vscode.window.showOpenDialog({
    title: `Test "${targetId}" — Choose a binary`,
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false,
    openLabel: 'Select',
  });
  if (!uris || !uris[0]) return;
  const binaryPath = uris[0].fsPath;

  // 5. Mode décompilation
  const modeChoice = await vscode.window.showQuickPick(
    [
      { label: '$(symbol-function) Decompile a function', description: 'By hexadecimal address', value: 'function' },
      { label: '$(file-code) Decompile the whole binary', description: '--full mode (slower)', value: 'full' },
    ],
    { title: `Test "${targetId}" — Mode` }
  );
  if (!modeChoice) return;

  let addr = '';
  if (modeChoice.value === 'function') {
    const addrInput = await vscode.window.showInputBox({
      title: `Test "${targetId}" — Function address`,
      prompt: 'Hexadecimal address. Leave blank to try 0x1000 by default.',
      placeHolder: '0x401000',
      validateInput: (v) => {
        if (!v.trim()) return null;
        if (!/^0x[0-9a-fA-F]+$|^\d+$/.test(v.trim())) return 'Invalid format (for example: 0x401000)';
        return null;
      },
    });
    if (addrInput === undefined) return;
    addr = addrInput.trim() || '0x1000';
  }

  // 6. Lancer le test
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Test ${targetId} via ${providerChoice.value}…`,
      cancellable: false,
    },
    async (progress) => {
      const testMode = providerChoice.value === 'docker'
        ? 'Starting the temporary Docker container…'
        : providerChoice.value === 'auto'
          ? 'Testing the backend (local, then Docker if necessary)…'
          : 'Testing the local backend…';
      progress.report({ message: testMode });
      try {
        const pythonExe = _findPythonExe(root);
        const scriptPath = path.join(getExtensionPath() || root, 'backends/static/decompile/decompile.py');
        const args = [scriptPath, '--binary', binaryPath, '--decompiler', targetId, '--provider', providerChoice.value];
        if (modeChoice.value === 'full') {
          args.push('--full');
        } else {
          args.push('--addr', addr);
        }
        const result = await _runPythonDirect(pythonExe, args, root, 120000, storageDir);
        if (result.error) {
          const provider = result.provider || providerChoice.value;
          const rawError = String(result.error || '');
          vscode.window.showErrorMessage(`❌ ${targetId} (${provider}) — ${rawError}`);
          return;
        }
        const provider = result.provider || providerChoice.value;
        if (modeChoice.value === 'full') {
          const fnCount = (result.functions || []).length;
          vscode.window.showInformationMessage(
            `✅ ${targetId} (${provider}) — ${fnCount} function(s) decompiled${provider === 'docker' ? ' • container removed automatically' : ''}`
          );
        } else {
          const preview = (result.code || '').slice(0, 200).replace(/\n/g, ' ');
          vscode.window.showInformationMessage(
            `✅ ${targetId} (${provider}) — ${preview || '(empty output)'}…${provider === 'docker' ? ' • container removed automatically' : ''}`
          );
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Test "${targetId}" failed: ${e.message || e}`);
      }
    }
  );
}

// ─── Helpers exécution Python ─────────────────────────────────────────────────

function _findPythonExe(root) {
  const base = getExtensionPath() || root;
  const candidates = [
    path.join(base, 'backends', '.venv', 'bin', 'python3'),
    path.join(base, 'backends', '.venv', 'bin', 'python'),
    'python3',
    'python',
  ];
  for (const c of candidates) {
    if (c.includes(path.sep) && !fs.existsSync(c)) continue;
    return c;
  }
  return 'python3';
}

function _runPythonDirect(pythonExe, args, root, timeout = 60000, storageDir = '') {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const auditName = args?.[0] || '';
    const auditArgc = Array.isArray(args) ? Math.max(0, args.length - 1) : 0;
    cp.execFile(
      pythonExe, args,
      { encoding: 'utf8', cwd: root, timeout, maxBuffer: 8 * 1024 * 1024, env: buildRuntimeEnv(root, storageDir) },
      (err, stdout, stderr) => {
        recordRuntimeEvent('python', auditName, {
          source: 'decompilerCommands._runPythonDirect',
          argc: auditArgc,
          durationMs: Date.now() - startedAt,
          ok: !err || Boolean(stdout),
          stdoutBytes: Buffer.byteLength(String(stdout || ''), 'utf8'),
          stderrBytes: Buffer.byteLength(String(stderr || ''), 'utf8'),
        });
        if (err && !stdout) { err.stderr = stderr; reject(err); return; }
        try {
          resolve(JSON.parse(stdout.trim()));
        } catch (_) {
          resolve({ code: stdout.trim(), error: err ? (stderr || err.message) : null });
        }
      }
    );
  });
}

// ─── Enregistrement ───────────────────────────────────────────────────────────

function registerDecompilerCommands(context, deps, root, storageDir) {
  const { runPython, logChannel } = deps;
  const subs = [];

  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerAdd',        () => cmdDecompilerAdd(root, storageDir)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerEdit',       (preselectedId) => cmdDecompilerEdit(root, storageDir, preselectedId || null)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerRemove',     (preselectedId) => cmdDecompilerRemove(root, storageDir, preselectedId || null)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerOpenConfig', () => cmdDecompilerOpenConfig(storageDir)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerList',       () => cmdDecompilerList(root, runPython, logChannel)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerTest',       (preselectedId) => cmdDecompilerTest(root, storageDir, runPython, preselectedId || null)));

  return subs;
}

/** Retourne la platform docker requise pour une image OCI connue (ex: 'linux/amd64'), ou '' si aucune contrainte. */
function getKnownOciImagePlatform(image: string): string {
  const img = String(image || '').trim();
  const repo = img.split(':')[0]; // tolérant au tag (:latest, :1.0.0, …)
  for (const key of Object.keys(ociDecompilers())) {
    const defRepo = `ghcr.io/pileoufaces/pile-ou-face/decompiler-${key}`;
    const platform = (ociDecompilers()[key] as { platform?: string }).platform;
    if (defRepo === repo && platform) return platform;
  }
  return '';
}

module.exports = { registerDecompilerCommands, getKnownOciImagePlatform, _filterOciVersionTags };
