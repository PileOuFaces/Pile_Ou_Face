// SPDX-License-Identifier: AGPL-3.0-only
// Sonde exécutée dans l'hôte d'extensions de VS Code par run-vsix-recette.js.
// Elle observe l'extension réellement installée depuis le VSIX (et non les
// sources) et écrit ses constats dans POF_RECETTE_OUT. Elle n'échoue jamais
// silencieusement : toute exception est écrite dans le rapport.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const vscode = require('vscode');

const EXTENSION_ID = 'PileOuFaces.stack-visualizer';
const POLL_MS = 2000;
// Sans consentement, aucune installation ne doit démarrer dans ce délai.
const NO_CONSENT_OBSERVATION_MS = 20000;
// Installation réelle depuis PyPI (wheels lief, unicorn…) sur un runner lent.
const INSTALL_TIMEOUT_MS = 15 * 60 * 1000;
// Paquets compilés du verrou, dont yara et flirt (#549) : une installation partielle ne passe pas.
const CORE_IMPORTS = 'import unicorn, capstone, lief, yara, flirt';
// La notification n'apparaît qu'après la recherche d'interpréteur (sondes jusqu'à 15 s chacune) :
// cliquer à intervalle régulier pendant cette fenêtre, jusqu'au démarrage de l'installation.
const CONSENT_WINDOW_MS = 120000;
const CONSENT_RETRY_MS = 5000;
const INSTALL_LOG_TIMEOUT_MS = 120000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function venvPython(extensionPath) {
  const venv = path.join(extensionPath, 'backends', '.venv');
  const candidates = process.platform === 'win32'
    ? [path.join(venv, 'Scripts', 'python.exe')]
    : [path.join(venv, 'bin', 'python3'), path.join(venv, 'bin', 'python')];
  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function importsOk(python) {
  if (!python) return false;
  try {
    execFileSync(python, ['-c', CORE_IMPORTS], { stdio: 'ignore', timeout: 60000 });
    return true;
  } catch {
    return false;
  }
}

// Clique « Install » par la commande native des notifications de VS Code.
async function acceptFirstNotification() {
  await vscode.commands.executeCommand('notifications.focusToasts');
  await vscode.commands.executeCommand('notification.acceptPrimaryAction');
}

/** Clique toutes les CONSENT_RETRY_MS jusqu'à ce que le venv existe (installation démarrée). */
function consentClicker(extensionPath) {
  const started = Date.now();
  let lastClick = 0;
  let clicks = 0;
  return {
    get clicks() { return clicks; },
    async tick() {
      const now = Date.now();
      if (venvPython(extensionPath) || now - started > CONSENT_WINDOW_MS || now - lastClick < CONSENT_RETRY_MS) return;
      lastClick = now;
      clicks += 1;
      await acceptFirstNotification();
    },
  };
}

// Journal « Pile ou Face » du profil de recette (user-data-dir transmis par le lanceur).
function extensionLogText() {
  const logs = path.join(process.env.POF_RECETTE_USER_DATA || '', 'logs');
  if (!process.env.POF_RECETTE_USER_DATA || !fs.existsSync(logs)) return '';
  let text = '';
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/Pile ou Face/.test(entry.name)) text += fs.readFileSync(full, 'utf8');
  });
  walk(logs);
  return text;
}

const INSTALL_END_PATTERN = /\[pip\] (Installation terminée|Erreur)/;

async function waitFor(predicate, timeoutMs, onTick = async () => {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await onTick();
    await sleep(POLL_MS);
  }
  return predicate();
}

async function common(report) {
  const extension = vscode.extensions.getExtension(EXTENSION_ID);
  report.installed = Boolean(extension);
  if (!extension) throw new Error(`${EXTENSION_ID} absent de l'installation`);
  report.version = extension.packageJSON.version;
  report.extensionPath = extension.extensionPath;
  report.fromVsixInstall = !extension.extensionPath.includes(`${path.sep}src${path.sep}`);
  await extension.activate();
  report.activated = extension.isActive;
  const commands = await vscode.commands.getCommands(true);
  report.openCommandRegistered = commands.includes('pileOuFace.open');
  await vscode.commands.executeCommand('pileOuFace.open');
  report.hubOpened = true;
  report.workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || null;
  return extension;
}

const SCENARIOS = {
  async fresh(report, extension) {
    await sleep(NO_CONSENT_OBSERVATION_MS);
    report.venvCreatedWithoutConsent = fs.existsSync(path.join(extension.extensionPath, 'backends', '.venv'));
  },
  async consent(report, extension) {
    const clicker = consentClicker(extension.extensionPath);
    const done = await waitFor(
      () => importsOk(venvPython(extension.extensionPath)),
      INSTALL_TIMEOUT_MS,
      () => clicker.tick(),
    );
    report.consentClicks = clicker.clicks;
    // Les imports peuvent réussir avant que l'extension ait fini (et journalisé) l'installation :
    // attendre sa ligne de fin ou d'erreur avant de fermer VS Code.
    report.installEndLogged = await waitFor(() => INSTALL_END_PATTERN.test(extensionLogText()), INSTALL_LOG_TIMEOUT_MS);
    report.venvPython = venvPython(extension.extensionPath);
    report.dependenciesInstalled = done;
  },
  async offline(report, extension) {
    // Le venv est créé localement ; l'échec réseau survient ensuite dans pip.
    // La notification n'apparaît qu'après la recherche d'un interpréteur : cliquer jusqu'à ce qu'elle soit là.
    const clicker = consentClicker(extension.extensionPath);
    await waitFor(() => Boolean(venvPython(extension.extensionPath)), CONSENT_WINDOW_MS + 30000, () => clicker.tick());
    report.consentClicks = clicker.clicks;
    await sleep(30000);
    report.venvPython = venvPython(extension.extensionPath);
    report.dependenciesInstalled = importsOk(report.venvPython);
    await vscode.commands.executeCommand('pileOuFace.open');
    report.hubStillOpensAfterFailure = true;
  },
  async update(report) {
    const config = vscode.workspace.getConfiguration('pileOuFace');
    report.preservedLogLevel = config.get('logLevel');
  },
};

async function run() {
  const scenario = process.env.POF_RECETTE_SCENARIO || 'fresh';
  const report = { scenario, platform: process.platform, arch: process.arch, vscode: vscode.version };
  try {
    const extension = await common(report);
    await SCENARIOS[scenario](report, extension);
    report.ok = true;
  } catch (error) {
    report.ok = false;
    report.error = String(error?.stack || error);
  } finally {
    fs.writeFileSync(process.env.POF_RECETTE_OUT, JSON.stringify(report, null, 2));
  }
}

module.exports = { run };
