// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file pythonDependencies.ts
 * @brief Installation des dépendances Python du backend : consentement explicite,
 * venv de l'extension uniquement et versions vérifiées par hash (POF-P1-001).
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

/** Fichier de versions figées avec hashes, généré depuis requirements.txt (voir README). */
const LOCK_FILE_NAME = 'requirements.lock.txt';
const VENV_DIR_NAME = '.venv';
const CORE_IMPORTS = ['unicorn', 'capstone'];
const DEFAULT_PYTHON_NAMES = ['python3', 'python'];
const INSTALL_ACTION = 'Installer';
const DECLINE_ACTION = 'Plus tard';
const UNAVAILABLE_NOTE = 'Les fonctions Python de Pile ou Face restent indisponibles.';
// Signatures d'erreurs réseau de pip / urllib3 sur Linux, macOS et Windows.
const NETWORK_ERROR_PATTERN = /NewConnectionError|Failed to establish a new connection|Temporary failure in name resolution|Name or service not known|nodename nor servname|getaddrinfo failed|Network is unreachable|ConnectTimeoutError|ProxyError/i;

type DependencyStatus = 'ok' | 'installed' | 'declined' | 'offline' | 'failed' | 'unavailable';
type DependencyOptions = { backendBase: string; quiet?: boolean; log: (message: string) => void };
type ExecResult = { ok: boolean; output: string };

function execFileResult(file: string, args: string[]): Promise<ExecResult> {
  return new Promise((resolve) => {
    cp.execFile(file, args, (error, _stdout, stderr) => {
      resolve({ ok: !error, output: String(stderr || error?.message || '').trim() });
    });
  });
}

function venvPythonCandidates(venvPath: string): string[] {
  return [
    path.join(venvPath, 'bin', 'python3'),
    path.join(venvPath, 'Scripts', 'python.exe'),
    path.join(venvPath, 'Scripts', 'python'),
  ];
}

function findVenvPython(venvPath: string): string {
  return venvPythonCandidates(venvPath).find((candidate) => fs.existsSync(candidate)) || '';
}

function isExtensionVenvPython(pythonExe: string, venvPath: string): boolean {
  const resolved = path.resolve(pythonExe);
  return venvPythonCandidates(venvPath).some((candidate) => path.resolve(candidate) === resolved);
}

async function hasCoreImports(pythonExe: string): Promise<boolean> {
  for (const dep of CORE_IMPORTS) {
    if (!(await execFileResult(pythonExe, ['-c', `import ${dep}`])).ok) return false;
  }
  return true;
}

function manualInstallCommand(pythonExe: string, lockPath: string): string {
  return `"${pythonExe}" -m pip install --require-hashes -r "${lockPath}"`;
}

async function askConsent(): Promise<boolean> {
  const choice = await vscode.window.showInformationMessage(
    'Pile ou Face : des dépendances Python (unicorn, capstone, lief…) manquent. '
      + 'Les installer dans le venv de l\'extension (backends/.venv) depuis PyPI, versions vérifiées par hash ?',
    INSTALL_ACTION,
    DECLINE_ACTION
  );
  return choice === INSTALL_ACTION;
}

async function ensureExtensionVenv(basePython: string, venvPath: string, log): Promise<string> {
  const existing = findVenvPython(venvPath);
  if (existing) return existing;
  log('[venv] Création du venv…');
  const result = await execFileResult(basePython, ['-m', 'venv', venvPath]);
  if (!result.ok) throw new Error(result.output || 'python -m venv a échoué');
  const created = findVenvPython(venvPath);
  if (!created) throw new Error(`interpréteur introuvable dans ${venvPath}`);
  log(`[venv] Utilisation: ${created}`);
  return created;
}

function reportInstallFailure(output: string, venvPython: string, lockPath: string, log): DependencyStatus {
  const offline = NETWORK_ERROR_PATTERN.test(output);
  log(`[pip] Erreur${offline ? ' (réseau indisponible)' : ''}: ${output}`);
  const reason = offline
    ? 'PyPI est injoignable (hors ligne ?). Réessayez une fois connecté'
    : 'L\'installation a échoué (détails dans le canal « Pile ou Face »)';
  vscode.window.showWarningMessage(
    `${reason}. ${UNAVAILABLE_NOTE} Commande manuelle : ${manualInstallCommand(venvPython, lockPath)}`
  );
  return offline ? 'offline' : 'failed';
}

async function installInExtensionVenv(basePython: string, venvPath: string, lockPath: string, log): Promise<DependencyStatus> {
  let venvPython;
  try {
    venvPython = await ensureExtensionVenv(basePython, venvPath, log);
  } catch (venvErr) {
    log(`[venv] Erreur: ${venvErr.message}`);
    vscode.window.showWarningMessage(`Impossible de créer backends/.venv : ${venvErr.message}. ${UNAVAILABLE_NOTE}`);
    return 'failed';
  }
  log('[pip] Installation des dépendances (versions vérifiées par hash)…');
  const result = await execFileResult(venvPython, [
    '-m', 'pip', 'install', '--require-hashes', '--no-input', '--disable-pip-version-check', '--quiet',
    '-r', lockPath,
  ]);
  if (!result.ok) return reportInstallFailure(result.output, venvPython, lockPath, log);
  log('[pip] Installation terminée.');
  vscode.window.showInformationMessage('Pile ou Face : dépendances Python installées.');
  return 'installed';
}

function reportUnavailable(message: string, quiet: boolean, log): DependencyStatus {
  log(`[pip] ${message} ${UNAVAILABLE_NOTE}`);
  if (!quiet) vscode.window.showWarningMessage(`${message} ${UNAVAILABLE_NOTE}`);
  return 'unavailable';
}

/**
 * Vérifie les imports de base ; s'ils manquent, propose l'installation et ne lance pip
 * qu'après un clic sur « Installer », dans backends/.venv, avec --require-hashes.
 * Ne lève jamais d'exception : le statut retourné décrit l'issue.
 */
async function ensurePythonDependencies(pythonExe: string, options: DependencyOptions): Promise<DependencyStatus> {
  const { backendBase, quiet = false, log } = options;
  const venvPath = path.join(backendBase, 'backends', VENV_DIR_NAME);
  const lockPath = path.join(backendBase, 'backends', LOCK_FILE_NAME);
  if (await hasCoreImports(pythonExe)) {
    log('[pip] Dépendances OK.');
    return 'ok';
  }
  if (!DEFAULT_PYTHON_NAMES.includes(pythonExe) && !isExtensionVenvPython(pythonExe, venvPath)) {
    return reportUnavailable(
      `Dépendances Python manquantes pour l'interpréteur configuré ${pythonExe}. `
        + `Installez-les vous-même : ${manualInstallCommand(pythonExe, lockPath)}.`,
      quiet, log
    );
  }
  if (!fs.existsSync(lockPath)) {
    return reportUnavailable(`Fichier de versions vérifiées introuvable : ${lockPath}.`, quiet, log);
  }
  if (!(await askConsent())) {
    log(`[pip] Installation refusée par l'utilisateur. ${UNAVAILABLE_NOTE}`);
    return 'declined';
  }
  return installInExtensionVenv(pythonExe, venvPath, lockPath, log);
}

module.exports = {
  LOCK_FILE_NAME,
  INSTALL_ACTION,
  ensurePythonDependencies,
};
