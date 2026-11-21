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
/**
 * Outils de construction figés (setuptools, wheel), installés d'abord dans le venv : certaines
 * dépendances n'existent qu'en sdist, et l'isolation de build de pip téléchargerait sinon ces
 * outils sans version ni hash. L'installation principale tourne ensuite avec --no-build-isolation.
 */
const BUILD_LOCK_FILE_NAME = 'requirements-build.lock.txt';
/**
 * Options pip (fichiers de configuration ou variables PIP_*) qui déplaceraient l'installation hors
 * du venv. Les autres (index-url, proxy, cert…) restent permises : les hashes garantissent le contenu.
 */
// `python` (PIP_PYTHON) fait agir pip sur un autre interpréteur, donc un autre environnement.
const REDIRECTING_PIP_OPTIONS = new Set(['target', 'prefix', 'root', 'user', 'python']);
// Seul `user` est booléen ; pour les autres, toute valeur est un chemin (« off » compris).
const BOOLEAN_PIP_OPTIONS = new Set(['user']);
const DISABLED_VALUES = new Set(['', '0', 'false', 'no', 'off']);
const PIP_INSTALL_ARGS = ['-m', 'pip', 'install', '--require-hashes', '--no-input', '--disable-pip-version-check', '--quiet'];
const VENV_DIR_NAME = '.venv';
const CORE_IMPORTS = ['unicorn', 'capstone'];
const DEFAULT_PYTHON_NAMES = ['python3', 'python'];
const INSTALL_ACTION = 'Install';
const DECLINE_ACTION = 'Later';
const UNAVAILABLE_NOTE = 'Pile ou Face Python features stay unavailable.';
// Signatures d'erreurs réseau de pip / urllib3 sur Linux, macOS et Windows.
const NETWORK_ERROR_PATTERN = /NewConnectionError|Failed to establish a new connection|Temporary failure in name resolution|Name or service not known|nodename nor servname|getaddrinfo failed|Network is unreachable|ConnectTimeoutError|ProxyError/i;

type DependencyStatus = 'ok' | 'installed' | 'declined' | 'offline' | 'failed' | 'unavailable' | 'unsupported';
type DependencyOptions = { backendBase: string; quiet?: boolean; log: (message: string) => void };
type ExecResult = { ok: boolean; output: string };
type LockFiles = { build: string; main: string };

function execFileResult(file: string, args: string[]): Promise<ExecResult & { stdout: string }> {
  return new Promise((resolve) => {
    cp.execFile(file, args, (error, stdout, stderr) => {
      resolve({ ok: !error, output: String(stderr || error?.message || '').trim(), stdout: String(stdout || '') });
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

function isDefaultPython(pythonExe: string): boolean {
  return DEFAULT_PYTHON_NAMES.includes(pythonExe);
}

/**
 * Interpréteur dont on vérifie les imports. Un nom par défaut (python3/python) n'est
 * qu'un interpréteur de base pour créer backends/.venv : seul ce venv compte, car le
 * Python système peut n'avoir qu'une partie des dépendances (ex. sans lief).
 */
function interpreterToCheck(pythonExe: string, venvPath: string): string {
  return isDefaultPython(pythonExe) ? findVenvPython(venvPath) : pythonExe;
}

async function hasCoreImports(pythonExe: string): Promise<boolean> {
  if (!pythonExe) return false;
  for (const dep of CORE_IMPORTS) {
    if (!(await execFileResult(pythonExe, ['-c', `import ${dep}`])).ok) return false;
  }
  return true;
}

/** Deux commandes distinctes : `&&` n'existe pas dans Windows PowerShell 5.1, et un chemin entre guillemets y exige `&`. */
function manualInstallCommand(pythonExe: string, locks: LockFiles, platform: string = process.platform): string {
  const call = platform === 'win32' ? `& "${pythonExe}"` : `"${pythonExe}"`;
  const pip = `${call} -m pip install --require-hashes`;
  return `(1) ${pip} -r "${locks.build}" (2) ${pip} --no-build-isolation -r "${locks.main}"`;
}

/** Clés de `pip config list` (ex. `install.target`, `:env:.prefix`) qui redirigeraient l'installation. */
function redirectingPipOptions(configList: string): string[] {
  return configList.split(/\r?\n/).flatMap((line) => {
    const match = /^(.+?)=(.*)$/.exec(line.trim());
    if (!match) return [];
    const option = match[1].slice(match[1].lastIndexOf('.') + 1).toLowerCase();
    const value = match[2].replace(/^'(.*)'$/, '$1').trim().toLowerCase();
    if (!REDIRECTING_PIP_OPTIONS.has(option)) return [];
    return BOOLEAN_PIP_OPTIONS.has(option) && DISABLED_VALUES.has(value) ? [] : [match[1]];
  });
}

async function askConsent(): Promise<boolean> {
  const choice = await vscode.window.showInformationMessage(
    'Pile ou Face: Python dependencies (unicorn, capstone, lief…) are missing. '
      + 'Install them from PyPI into the extension venv (backends/.venv), with hash-verified versions?',
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
  if (!result.ok) throw new Error(result.output || 'python -m venv failed');
  const created = findVenvPython(venvPath);
  if (!created) throw new Error(`no interpreter found in ${venvPath}`);
  log(`[venv] Utilisation: ${created}`);
  return created;
}

function reportInstallFailure(output: string, venvPython: string, locks: LockFiles, log): DependencyStatus {
  const offline = NETWORK_ERROR_PATTERN.test(output);
  log(`[pip] Erreur${offline ? ' (réseau indisponible)' : ''}: ${output}`);
  const reason = offline
    ? 'PyPI is unreachable (offline?). Retry once connected'
    : 'Installation failed (details in the "Pile ou Face" output channel)';
  vscode.window.showWarningMessage(
    `${reason}. ${UNAVAILABLE_NOTE} Manual commands: ${manualInstallCommand(venvPython, locks)}`
  );
  return offline ? 'offline' : 'failed';
}

async function installInExtensionVenv(basePython: string, venvPath: string, locks: LockFiles, log): Promise<DependencyStatus> {
  let venvPython;
  try {
    venvPython = await ensureExtensionVenv(basePython, venvPath, log);
  } catch (venvErr) {
    log(`[venv] Erreur: ${venvErr.message}`);
    vscode.window.showWarningMessage(`Cannot create backends/.venv: ${venvErr.message}. ${UNAVAILABLE_NOTE}`);
    return 'failed';
  }
  if (!(await pipStaysInVenv(venvPython, locks, log))) return 'failed';
  log('[pip] Installation des outils de construction (versions vérifiées par hash)…');
  const build = await execFileResult(venvPython, [...PIP_INSTALL_ARGS, '-r', locks.build]);
  if (!build.ok) return reportInstallFailure(build.output, venvPython, locks, log);
  log('[pip] Installation des dépendances (versions vérifiées par hash)…');
  const result = await execFileResult(venvPython, [...PIP_INSTALL_ARGS, '--no-build-isolation', '-r', locks.main]);
  if (!result.ok) return reportInstallFailure(result.output, venvPython, locks, log);
  // pip can exit 0 without installing anything (PIP_DRY_RUN, constraints…): trust the imports only.
  if (!(await hasCoreImports(venvPython))) {
    return reportInstallFailure('pip succeeded but unicorn/capstone are still not importable', venvPython, locks, log);
  }
  log('[pip] Installation terminée.');
  vscode.window.showInformationMessage('Pile ou Face: Python dependencies installed.');
  return 'installed';
}

/**
 * Le consentement porte sur backends/.venv : refuse une configuration pip (fichier ou PIP_*)
 * qui redirigerait l'installation (PIP_TARGET, install.prefix…).
 */
async function pipStaysInVenv(venvPython: string, locks: LockFiles, log): Promise<boolean> {
  const config = await execFileResult(venvPython, ['-m', 'pip', 'config', 'list']);
  const redirecting = config.ok ? redirectingPipOptions(config.stdout) : [];
  if (config.ok && !redirecting.length) return true;
  const reason = config.ok
    ? `pip configuration would install outside backends/.venv (${redirecting.join(', ')})`
    : `cannot read the pip configuration (${config.output})`;
  log(`[pip] Installation annulée : ${reason}`);
  vscode.window.showWarningMessage(
    `Install cancelled: ${reason}. ${UNAVAILABLE_NOTE} Manual commands: ${manualInstallCommand(venvPython, locks)}`
  );
  return false;
}

/**
 * macOS Intel : cryptography (version verrouillée) ne publie plus de wheel x86_64 macOS, et
 * aucune compilation implicite n'est faite. Le critère est l'interpréteur qui recevra les
 * paquets (sous Rosetta, l'architecture de VS Code peut différer de celle de Python).
 */
const PLATFORM_PROBE = 'import platform, sys; print(sys.platform, platform.machine())';
const UNSUPPORTED_AUTO_INSTALL = new Set(['darwin x86_64']);

async function isAutoInstallUnsupported(pythonExe: string): Promise<boolean> {
  const probe = await execFileResult(pythonExe, ['-c', PLATFORM_PROBE]);
  // Sonde impossible : pas de conclusion ici ; la création du venv signalera un Python absent.
  return probe.ok && UNSUPPORTED_AUTO_INSTALL.has(probe.stdout.trim().toLowerCase());
}

function reportUnsupportedPlatform(log): DependencyStatus {
  const message = 'Pile ou Face: automatic installation of the Python dependencies is not supported on Intel macOS '
    + '(the pinned cryptography release publishes no macOS x86_64 wheel, and building from source is not done '
    + 'automatically). The rest of the extension still works. To use the Python features, install the dependencies '
    + 'of backends/requirements.txt yourself in a Python environment and select it with the pythonPath setting.';
  log(`[pip] Installation automatique non prise en charge sur macOS Intel. ${UNAVAILABLE_NOTE}`);
  // Limitation de plateforme, pas un choix utilisateur : toujours visible, même à l'activation.
  vscode.window.showWarningMessage(message);
  return 'unsupported';
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
  const locks = {
    build: path.join(backendBase, 'backends', BUILD_LOCK_FILE_NAME),
    main: path.join(backendBase, 'backends', LOCK_FILE_NAME),
  };
  if (await hasCoreImports(interpreterToCheck(pythonExe, venvPath))) {
    log('[pip] Dépendances OK.');
    return 'ok';
  }
  if (!isDefaultPython(pythonExe) && !isExtensionVenvPython(pythonExe, venvPath)) {
    return reportUnavailable(
      `Python dependencies are missing for the configured interpreter ${pythonExe}. `
        + `Install them yourself: ${manualInstallCommand(pythonExe, locks)}.`,
      quiet, log
    );
  }
  const missingLock = [locks.build, locks.main].find((lockPath) => !fs.existsSync(lockPath));
  if (missingLock) {
    // Défaut de packaging, pas un choix utilisateur : toujours visible, même à l'activation.
    return reportUnavailable(`Hash-verified requirements file not found: ${missingLock}.`, false, log);
  }
  if (await isAutoInstallUnsupported(findVenvPython(venvPath) || pythonExe)) return reportUnsupportedPlatform(log);
  if (!(await askConsent())) {
    log(`[pip] Installation refusée par l'utilisateur. ${UNAVAILABLE_NOTE}`);
    return 'declined';
  }
  return installInExtensionVenv(pythonExe, venvPath, locks, log);
}

module.exports = {
  LOCK_FILE_NAME,
  BUILD_LOCK_FILE_NAME,
  manualInstallCommand,
  redirectingPipOptions,
  INSTALL_ACTION,
  ensurePythonDependencies,
};
