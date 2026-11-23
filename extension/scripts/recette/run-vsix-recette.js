#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Recette d'installation du VSIX candidat (mission 5, release candidate V1).
//
// Chaque scénario part d'un profil VS Code vierge (user-data-dir et
// extensions-dir propres), installe le VSIX par la CLI officielle de VS Code,
// puis lance la sonde (probe/) dans l'hôte d'extensions.
//
//   node scripts/recette/run-vsix-recette.js --vsix <fichier.vsix> --out <dossier>
//        [--scenarios fresh,consent,offline,update] [--previous 0.3.2]
//
// « offline » simule l'absence de réseau pour pip uniquement (index injoignable).
// Une vraie coupure réseau se teste dans un conteneur --network none.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  downloadAndUnzipVSCode,
  resolveCliArgsFromVSCodeExecutablePath,
  runTests,
} = require('@vscode/test-electron');

const EXTENSION_ID = 'PileOuFaces.stack-visualizer';
// Port réservé (discard) : aucune écoute, connexion refusée immédiatement.
const UNREACHABLE_INDEX = 'http://127.0.0.1:9/simple/';
const PRESERVED_SETTING = { 'pileOuFace.logLevel': 'debug' };
const ALL_SCENARIOS = ['fresh', 'consent', 'offline', 'update'];

function parseArgs(argv) {
  const args = { scenarios: ALL_SCENARIOS.join(','), previous: '0.3.2' };
  for (let i = 0; i < argv.length; i += 2) args[argv[i].replace(/^--/, '')] = argv[i + 1];
  if (!args.vsix || !args.out) throw new Error('usage: --vsix <file> --out <dir>');
  args.vsix = path.resolve(args.vsix);
  args.out = path.resolve(args.out);
  args.scenarios = args.scenarios.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = args.scenarios.filter((s) => !ALL_SCENARIOS.includes(s));
  // Pas de succès sans scénario exécuté : nom inconnu ou sélection vide = erreur.
  if (unknown.length || !args.scenarios.length) {
    throw new Error(`unknown or empty --scenarios (${unknown.join(',') || 'none'}); allowed: ${ALL_SCENARIOS.join(',')}`);
  }
  return args;
}

function cli(vscodeExecutable, profile, extraArgs) {
  const [command, ...baseArgs] = resolveCliArgsFromVSCodeExecutablePath(vscodeExecutable);
  const result = spawnSync(command, [
    ...baseArgs,
    `--user-data-dir=${profile.userData}`,
    `--extensions-dir=${profile.extensions}`,
    ...extraArgs,
  ], { encoding: 'utf8', shell: process.platform === 'win32' });
  return { status: result.status, output: `${result.stdout || ''}${result.stderr || ''}`.trim() };
}

function freshProfile(root, scenario) {
  const base = fs.mkdtempSync(path.join(root, `${scenario}-`));
  const profile = {
    userData: path.join(base, 'user-data'),
    extensions: path.join(base, 'extensions'),
    workspace: path.join(base, 'workspace'),
  };
  Object.values(profile).forEach((dir) => fs.mkdirSync(dir, { recursive: true }));
  fs.writeFileSync(path.join(profile.workspace, 'README.txt'), 'Dossier de travail de recette.\n');
  return profile;
}

function extensionLogLines(userData) {
  const logs = path.join(userData, 'logs');
  if (!fs.existsSync(logs)) return [];
  const found = [];
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/Pile ou Face/.test(entry.name)) found.push(...fs.readFileSync(full, 'utf8').split(/\r?\n/));
  });
  walk(logs);
  // Une erreur pip s'étend sur plusieurs lignes (traceback) : garder la suite.
  const ERROR_CONTEXT_LINES = 80;
  const kept = [];
  let context = 0;
  for (const line of found) {
    if (/\[pip\] Erreur/.test(line)) context = ERROR_CONTEXT_LINES;
    if (context > 0 || /\[pip\]|\[venv\]|Python setup/.test(line)) kept.push(line);
    if (context > 0) context -= 1;
  }
  return kept;
}

async function runScenario(vscodeExecutable, args, scenario, root) {
  const profile = freshProfile(root, scenario);
  const report = { scenario, steps: [] };
  if (scenario === 'update') {
    const previous = cli(vscodeExecutable, profile, ['--install-extension', `${EXTENSION_ID}@${args.previous}`]);
    report.steps.push({ step: `install ${args.previous} from the marketplace`, ...previous });
    fs.mkdirSync(path.join(profile.userData, 'User'), { recursive: true });
    fs.writeFileSync(path.join(profile.userData, 'User', 'settings.json'), JSON.stringify(PRESERVED_SETTING));
  }
  const install = cli(vscodeExecutable, profile, ['--install-extension', args.vsix, '--force']);
  report.steps.push({ step: 'install candidate VSIX', ...install });
  const listed = cli(vscodeExecutable, profile, ['--list-extensions', '--show-versions']);
  // La CLI affiche l'identifiant en minuscules.
  report.listedExtensions = listed.output.split(/\r?\n/)
    .filter((line) => line.toLowerCase().startsWith(`${EXTENSION_ID.toLowerCase()}@`));

  const probeOut = path.join(root, `${scenario}-probe.json`);
  const env = { POF_RECETTE_SCENARIO: scenario, POF_RECETTE_OUT: probeOut };
  if (scenario === 'offline') env.PIP_INDEX_URL = UNREACHABLE_INDEX;
  try {
    await runTests({
      vscodeExecutablePath: vscodeExecutable,
      extensionDevelopmentPath: path.join(__dirname, 'probe'),
      extensionTestsPath: path.join(__dirname, 'probe', 'suite.js'),
      extensionTestsEnv: env,
      launchArgs: [
        profile.workspace,
        `--user-data-dir=${profile.userData}`,
        `--extensions-dir=${profile.extensions}`,
        '--disable-workspace-trust',
      ],
    });
  } catch (error) {
    report.runTestsError = String(error);
  }
  report.probe = fs.existsSync(probeOut) ? JSON.parse(fs.readFileSync(probeOut, 'utf8')) : null;
  report.extensionLog = extensionLogLines(profile.userData);
  return report;
}

function verdict(report) {
  const p = report.probe || {};
  const candidate = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  // Une erreur de l'hôte de tests invalide le scénario, même si la sonde a écrit un rapport.
  const base = !report.runTestsError && p.ok === true && p.activated === true && p.hubOpened === true
    && report.listedExtensions.length === 1
    && report.listedExtensions[0].toLowerCase() === `${EXTENSION_ID}@${candidate}`.toLowerCase()
    && p.version === candidate;
  const checks = {
    fresh: () => p.venvCreatedWithoutConsent === false,
    consent: () => p.dependenciesInstalled === true,
    offline: () => p.dependenciesInstalled === false && p.hubStillOpensAfterFailure === true
      && report.extensionLog.some((line) => line.includes('réseau indisponible')),
    update: () => p.preservedLogLevel === PRESERVED_SETTING['pileOuFace.logLevel']
      && report.steps[0].status === 0,
  };
  return base && checks[report.scenario]() ? 'PASS' : 'FAIL';
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  fs.mkdirSync(args.out, { recursive: true });
  // macOS limite les chemins de socket Unix à 104 caractères : le dossier
  // temporaire par défaut (/var/folders/…) est trop long pour le socket de VS Code.
  const tmpBase = process.platform === 'win32' ? os.tmpdir() : '/tmp';
  const root = fs.mkdtempSync(path.join(tmpBase, 'pofr-'));
  const vscodeExecutable = await downloadAndUnzipVSCode('stable');
  const results = [];
  for (const scenario of args.scenarios) {
    const report = await runScenario(vscodeExecutable, args, scenario, root);
    report.verdict = verdict(report);
    results.push(report);
    console.log(`${process.platform}-${process.arch} ${scenario}: ${report.verdict}`);
  }
  const summary = { platform: process.platform, arch: process.arch, node: process.version, results };
  fs.writeFileSync(path.join(args.out, `recette-${process.platform}-${process.arch}.json`), JSON.stringify(summary, null, 2));
  process.exitCode = results.length === args.scenarios.length && results.every((r) => r.verdict === 'PASS') ? 0 : 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 2;
});
