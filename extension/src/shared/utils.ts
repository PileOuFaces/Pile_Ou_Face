// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file utils.js
 * @brief Utilitaires partagés (temp, Python, runCommand, etc.)
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const logger = require('./logger');

const logChannel = vscode.window.createOutputChannel('Pile ou Face');

function logAt(level, message) {
  if (!logger.shouldLog(level)) return;
  logChannel.appendLine(logger.formatLine(level, logger.redact(message)));
}

const logDebug = (message) => logAt('debug', message);
const logInfo = (message) => logAt('info', message);
const logWarning = (message) => logAt('warning', message);
const logError = (message) => logAt('error', message);

const TEMP_DIR_NAME = '.pile-ou-face';

// Singleton initialisé au démarrage avec context.extensionPath.
// Sépare "où vivent les backends" (extensionPath) de "workspace utilisateur" (root).
let _extensionPath = '';

function setExtensionPath(p) {
  _extensionPath = String(p || '').trim();
}

function getExtensionPath() {
  return _extensionPath;
}

function resolveProjectRoot(root) {
  const value = String(root || '').trim();
  if (!value) return value;
  const absValue = path.resolve(value);
  if (fs.existsSync(path.join(absValue, 'extension', 'package.json'))) {
    return absValue;
  }
  try {
    const entries = fs.readdirSync(absValue, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const candidate = path.join(absValue, entry.name);
      if (fs.existsSync(path.join(candidate, 'extension', 'package.json'))) {
        return candidate;
      }
    }
  } catch (err) {
    logDebug(`[resolveProjectRoot] readdirSync(${absValue}) a échoué: ${err.message || err}`);
  }
  return absValue;
}

function findGitRoot(dir) {
  if (!dir) return dir;
  if (fs.existsSync(path.join(dir, '.git'))) return dir;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const gitSubs = entries.filter(e => e.isDirectory() && fs.existsSync(path.join(dir, e.name, '.git')));
    if (gitSubs.length === 1) return path.join(dir, gitSubs[0].name);
  } catch (err) {
    logDebug(`[findGitRoot] readdirSync(${dir}) a échoué: ${err.message || err}`);
  }
  return dir;
}

function getTempDir(root) {
  return path.resolve(findGitRoot(resolveProjectRoot(root)), TEMP_DIR_NAME);
}

function ensureTempDir(root) {
  const dir = getTempDir(root);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    logChannel.appendLine(`[temp] Dossier créé: ${dir}`);
  }
  return dir;
}

// Returns '' when both workspace and global storage are unavailable — check before use.
function getStorageDir(context) {
  return String(context?.storageUri?.fsPath || context?.globalStorageUri?.fsPath || '');
}

// Returns '' when context.globalStorageUri is unavailable — check before use.
function getGlobalStorageDir(context) {
  return String(context?.globalStorageUri?.fsPath || '');
}

function ensureStorageDir(context) {
  const dir = getStorageDir(context);
  if (!dir) throw new Error('[storage] context.storageUri/globalStorageUri non disponible');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    logChannel.appendLine(`[storage] Dossier créé: ${dir}`);
  }
  return dir;
}

async function ensurePythonDependencies(pythonExe, root, options = {}) {
  const { quiet = false } = options || {};
  const backendBase = _extensionPath || path.resolve(String(root || '').trim());
  const requirementsPath = path.join(backendBase, 'backends', 'requirements.txt');
  if (!fs.existsSync(requirementsPath)) {
    logChannel.appendLine('[pip] requirements.txt introuvable.');
    return;
  }
  if (pythonExe === 'python3' || pythonExe === 'python') {
    const venvPath = path.join(backendBase, 'backends', '.venv');
    if (!fs.existsSync(venvPath)) {
      logChannel.appendLine('[venv] Création du venv…');
      try {
        await new Promise((resolve, reject) => {
          cp.exec(`${pythonExe} -m venv ${venvPath}`, (error, stdout, stderr) =>
            error ? reject(new Error(stderr)) : resolve());
        });
        const candidates = [
          path.join(venvPath, 'bin', 'python3'),
          path.join(venvPath, 'Scripts', 'python.exe'),
          path.join(venvPath, 'Scripts', 'python')
        ];
        for (const c of candidates) {
          if (fs.existsSync(c)) {
            pythonExe = c;
            logChannel.appendLine(`[venv] Utilisation: ${pythonExe}`);
            break;
          }
        }
    } catch (venvErr) {
      logChannel.appendLine(`[venv] Erreur: ${venvErr.message}`);
      if (!quiet) {
        vscode.window.showWarningMessage(`Impossible de créer backends/.venv: ${venvErr.message}`);
      }
      return;
    }
  }
  }
  const coreDeps = ['unicorn', 'capstone'];
  let needInstall = false;
  for (const dep of coreDeps) {
    try {
      await new Promise((resolve, reject) => {
        cp.exec(`${pythonExe} -c "import ${dep}"`, (error) => (error ? reject(error) : resolve()));
      });
    } catch {
      needInstall = true;
      break;
    }
  }
  if (!needInstall) {
    logChannel.appendLine('[pip] Dépendances OK.');
    return;
  }
  logChannel.appendLine('[pip] Installation des dépendances…');
  try {
    await new Promise((resolve, reject) => {
      cp.execFile(pythonExe, ['-m', 'pip', 'install', '-r', requirementsPath, '--quiet', '--break-system-packages'], (error, stdout, stderr) =>
        error ? reject(new Error(stderr || error.message)) : resolve());
    });
    logChannel.appendLine('[pip] Installation terminée.');
  } catch (installErr) {
    const msg = installErr.message || '';
    logChannel.appendLine(`[pip] Erreur: ${msg}`);
    if (!quiet) {
      vscode.window.showWarningMessage(
        `Dépendances manquantes. Exécutez: ${pythonExe} -m pip install -r requirements.txt`
      );
    }
  }
}

function detectPythonExecutable(root, settingsPythonPath) {
  if (settingsPythonPath) return settingsPythonPath;
  const backendBase = _extensionPath || path.resolve(String(root || '').trim());
  const venvPaths = [
    path.join(backendBase, 'backends', '.venv', 'bin', 'python3'),
    path.join(backendBase, 'backends', '.venv', 'Scripts', 'python.exe'),
    path.join(backendBase, 'backends', '.venv', 'Scripts', 'python')
  ];
  for (const p of venvPaths) {
    if (fs.existsSync(p)) return p;
  }
  return 'python3';
}

function resolveDockerExecutable() {
  const envCandidate = String(process.env.POF_DOCKER_BIN || '').trim();
  const candidates = [
    envCandidate,
    'docker',
    '/usr/local/bin/docker',
    '/opt/homebrew/bin/docker',
    path.join(process.env.HOME || '', '.orbstack', 'bin', 'docker'),
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      if (candidate === 'docker') {
        const found = cp.spawnSync('which', ['docker'], { encoding: 'utf8', timeout: 1500 });
        const resolved = String(found.stdout || '').trim();
        if (found.status === 0 && resolved) return resolved;
        continue;
      }
      if (fs.existsSync(candidate)) return candidate;
    } catch (_) { /* intentional */ }
  }
  return 'docker';
}

/**
 * Build the runtime env for Python/Docker processes.
 * Accepts two call patterns (backward-compatible):
 *   buildRuntimeEnv(root, storageDir)           — new style: storageDir is a string path
 *   buildRuntimeEnv(root, extraEnv)             — legacy: extraEnv is a plain object
 *   buildRuntimeEnv(root, storageDir, extraEnv) — new style with extra overrides
 * When storageDir is provided, injects POF_STORAGE_DIR, DECOMPILERS_CONFIG, COMPILERS_CONFIG.
 */
function buildRuntimeEnv(root, storageDirOrExtra, extraEnv = {}) {
  let storageDir = '';
  let mergedExtra = extraEnv;
  if (typeof storageDirOrExtra === 'string') {
    storageDir = storageDirOrExtra;
  } else if (storageDirOrExtra && typeof storageDirOrExtra === 'object') {
    mergedExtra = { ...storageDirOrExtra, ...extraEnv };
  }
  const backendBase = _extensionPath || path.resolve(String(root || '').trim());
  const env = { ...process.env, ...mergedExtra };
  if (!mergedExtra.BINHOST_LOG_LEVEL) {
    env.BINHOST_LOG_LEVEL = logger.mapLevelToEnv(logger.getLevel());
  }
  if (storageDir) {
    env.POF_STORAGE_DIR    = storageDir;
    env.DECOMPILERS_CONFIG = path.join(storageDir, 'decompilers.json');
    env.COMPILERS_CONFIG   = path.join(storageDir, 'compilers.json');
  }
  if (backendBase) env.PYTHONPATH = mergedExtra.PYTHONPATH || backendBase;
  // On macOS, VS Code launched from Dock/Finder has a minimal PATH that omits
  // Homebrew and other user-installed tool directories. Augment with common paths
  // so subprocesses (e.g. yara, capa) are found via shutil.which().
  if (process.platform === 'darwin') {
    const extraDirs = ['/opt/homebrew/bin', '/usr/local/bin', '/opt/homebrew/sbin', '/usr/local/sbin'];
    const currentPath = String(env.PATH || '');
    const parts = currentPath ? currentPath.split(path.delimiter) : [];
    const augmented = [...new Set([...extraDirs.filter(d => !parts.includes(d)), ...parts])].filter(Boolean);
    env.PATH = augmented.join(path.delimiter);
  }
  const dockerExe = resolveDockerExecutable();
  if (dockerExe && dockerExe.includes(path.sep)) {
    const dockerDir = path.dirname(dockerExe);
    const currentPath = String(env.PATH || '');
    const parts = currentPath ? currentPath.split(path.delimiter) : [];
    if (!parts.includes(dockerDir)) {
      env.PATH = [dockerDir, ...parts].filter(Boolean).join(path.delimiter);
    }
    env.POF_DOCKER_BIN = dockerExe;
  }
  return env;
}

function check32BitToolchain(output) {
  if (process.platform !== 'linux') {
    return { ok: false, message: '32-bit only on Linux. Use 64-bit.' };
  }
  const candidates = [
    '/usr/include/gnu/stubs-32.h',
    '/usr/include/x86_64-linux-gnu/gnu/stubs-32.h',
    '/usr/include/i386-linux-gnu/gnu/stubs-32.h'
  ];
  if (candidates.some((p) => fs.existsSync(p))) return { ok: true };
  return {
    ok: false,
    message: 'Missing 32-bit headers. Install: sudo apt install gcc-multilib libc6-dev-i386'
  };
}

function runCommand(command, args, cwd, output, envOverrides = {}, streamHooks = {}) {
  const env = buildRuntimeEnv(cwd, envOverrides);
  output.appendLine(`[cmd] ${command} ${args.join(' ')}`);
  return new Promise((resolve, reject) => {
    let settled = false;
    let cancelled = false;
    let cancelSubscription = null;
    let forceKillTimer = null;
    const child = cp.spawn(command, args, { cwd, env });
    const cleanup = () => {
      if (forceKillTimer) {
        clearTimeout(forceKillTimer);
        forceKillTimer = null;
      }
      if (cancelSubscription && typeof cancelSubscription.dispose === 'function') {
        cancelSubscription.dispose();
        cancelSubscription = null;
      }
    };
    const finish = (err = null) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    };
    const cancel = () => {
      if (settled || cancelled) return;
      cancelled = true;
      output.appendLine(`[cmd] cancelled: ${command}`);
      try {
        child.kill('SIGTERM');
      } catch (_) { /* process may already be gone */ }
      forceKillTimer = setTimeout(() => {
        if (settled) return;
        try {
          child.kill('SIGKILL');
        } catch (_) { /* process may already be gone */ }
      }, 2000);
    };
    const token = streamHooks?.cancelToken;
    if (token?.isCancellationRequested) {
      cancel();
    } else if (typeof token?.onCancellationRequested === 'function') {
      cancelSubscription = token.onCancellationRequested(cancel);
    }
    const handleChunk = (hook, chunk) => {
      const text = chunk.toString();
      if (typeof hook !== 'function') {
        output.append(text);
        return;
      }
      try {
        const transformed = hook(text);
        if (transformed === false) return;
        if (typeof transformed === 'string') {
          if (transformed) output.append(transformed);
          return;
        }
      } catch (err) {
        output.append(`[runCommand] stream hook error: ${err.message || err}\n`);
      }
      output.append(text);
    };
    child.stdout.on('data', (d) => handleChunk(streamHooks.onStdoutData, d));
    child.stderr.on('data', (d) => handleChunk(streamHooks.onStderrData, d));
    child.on('error', (err) => finish(err));
    child.on('close', (code) => {
      if (cancelled) {
        finish(new Error(`${command} cancelled`));
        return;
      }
      finish(code === 0 ? null : new Error(`${command} exited with code ${code}`));
    });
  });
}

function escapeHtml(s) {
  if (typeof s !== 'string') return String(s);
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

module.exports = {
  logChannel,
  logDebug,
  logInfo,
  logWarning,
  logError,
  TEMP_DIR_NAME,
  getTempDir,
  ensureTempDir,
  getStorageDir,
  getGlobalStorageDir,
  ensureStorageDir,
  ensurePythonDependencies,
  detectPythonExecutable,
  resolveProjectRoot,
  resolveDockerExecutable,
  buildRuntimeEnv,
  check32BitToolchain,
  runCommand,
  escapeHtml,
  setExtensionPath,
  getExtensionPath,
};
