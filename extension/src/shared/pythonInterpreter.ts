// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file pythonInterpreter.ts
 * @brief Interpréteurs utilisables pour créer backends/.venv (#549).
 *
 * Les dépendances verrouillées n'ont de paquets précompilés (wheels) que pour
 * CPython 3.10 à 3.13 : `yara-python` s'arrête à 3.13. Un `python3` plus
 * récent (Homebrew, python.org) ferait échouer pip en tentant une compilation.
 * On cherche donc un interpréteur de cette plage avant de créer le venv, et on
 * refuse proprement, avant pip, s'il n'y en a aucun.
 */
const cp = require('child_process');
const path = require('path');

const SUPPORTED_MIN = { major: 3, minor: 10 };
const SUPPORTED_MAX = { major: 3, minor: 13 };
const SUPPORTED_RANGE_LABEL = `${SUPPORTED_MIN.major}.${SUPPORTED_MIN.minor}–${SUPPORTED_MAX.major}.${SUPPORTED_MAX.minor}`;
// Octets UTF-8 écrits directement : sous Windows, l'encodage des pipes suit la page de code
// (CP1252…), et execFile décode en UTF-8 ; un chemin accentué serait sinon corrompu.
const PROBE_SCRIPT = 'import sys, platform; sys.stdout.buffer.write(("%d %d %s %s %s\\n" % (sys.version_info[0], '
  + 'sys.version_info[1], sys.platform, platform.machine(), sys.executable)).encode("utf-8", "surrogateescape"))';
// Variables passées à la sonde : sortie UTF-8, et aucune installation de Python avant le
// consentement. Le gestionnaire d'installation Python de Windows peut installer un runtime
// manquant via les alias python/python3 (activé par défaut) : on le désactive explicitement.
const PROBE_ENV_OVERRIDES = { PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8', PYTHON_MANAGER_AUTOMATIC_INSTALL: 'false' };
const PROBE_ENV_REMOVED = ['PYLAUNCHER_ALLOW_INSTALL'];
const PROBE_TIMEOUT_MS = 15000;

type Exec = (file: string, args: string[], env?: Record<string, string | undefined>) => Promise<{ ok: boolean; stdout: string }>;
type InterpreterProbe = { major: number; minor: number; platform: string; machine: string; executable: string };
type Candidate = { command: string; args: string[] };

function probeEnv(base: Record<string, string | undefined> = process.env): Record<string, string | undefined> {
  const env = { ...base, ...PROBE_ENV_OVERRIDES };
  for (const name of PROBE_ENV_REMOVED) delete env[name];
  return env;
}

function defaultExec(file: string, args: string[], env = probeEnv()): Promise<{ ok: boolean; stdout: string }> {
  return new Promise((resolve) => {
    cp.execFile(file, args, { timeout: PROBE_TIMEOUT_MS, env }, (error, stdout) => {
      resolve({ ok: !error, stdout: String(stdout || '') });
    });
  });
}

async function probeInterpreter(candidate: Candidate, exec: Exec = defaultExec): Promise<InterpreterProbe | null> {
  const result = await exec(candidate.command, [...candidate.args, '-c', PROBE_SCRIPT], probeEnv());
  if (!result.ok) return null;
  const match = /^(\d+) (\d+) (\S+) (\S*) (.+)$/.exec(result.stdout.trim());
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    platform: match[3],
    machine: match[4],
    executable: match[5].trim(),
  };
}

function isSupportedVersion(probe: Pick<InterpreterProbe, 'major' | 'minor'>): boolean {
  const version = probe.major * 100 + probe.minor;
  return version >= SUPPORTED_MIN.major * 100 + SUPPORTED_MIN.minor
    && version <= SUPPORTED_MAX.major * 100 + SUPPORTED_MAX.minor;
}

/** macOS Intel (ou Python x86_64 sous Rosetta) : pas de wheel cryptography verrouillé pour cette plateforme. */
function isIntelMac(probe: Pick<InterpreterProbe, 'platform' | 'machine'>): boolean {
  return probe.platform === 'darwin' && probe.machine.toLowerCase() === 'x86_64';
}

/** Interpréteur utilisable pour le venv : version de la plage et plateforme qui a ses wheels. */
function isUsableBase(probe: InterpreterProbe): boolean {
  return isSupportedVersion(probe) && !isIntelMac(probe);
}

function supportedMinors(): number[] {
  const minors: number[] = [];
  for (let minor = SUPPORTED_MAX.minor; minor >= SUPPORTED_MIN.minor; minor -= 1) minors.push(minor);
  return minors;
}

/**
 * Ordre de recherche : versions explicites de la plage (la plus récente d'abord), puis les noms
 * génériques. Sous Windows, pas de lanceur `py -3.x` : il peut installer une version manquante
 * (installation à la demande). On essaie les dossiers d'installation standard de python.org.
 */
function baseCandidates(platform: string = process.platform, env: Record<string, string | undefined> = process.env): Candidate[] {
  if (platform === 'win32') {
    const roots = [
      env.LOCALAPPDATA ? path.win32.join(env.LOCALAPPDATA, 'Programs', 'Python') : '',
      env.ProgramFiles || '',
    ].filter(Boolean);
    return [
      ...supportedMinors().flatMap((minor) => roots.map((root) => ({
        command: path.win32.join(root, `Python3${minor}`, 'python.exe'),
        args: [],
      }))),
      { command: 'python', args: [] },
      { command: 'python3', args: [] },
    ];
  }
  return [
    ...supportedMinors().map((minor) => ({ command: `python3.${minor}`, args: [] })),
    { command: 'python3', args: [] },
    { command: 'python', args: [] },
  ];
}

function describeInterpreter(probe: InterpreterProbe): string {
  return `${probe.executable} (Python ${probe.major}.${probe.minor})`;
}

/** Premier interpréteur de la plage supportée, et la liste de tous ceux qui ont répondu (diagnostic). */
async function findCompatibleBase(platform: string = process.platform, exec: Exec = defaultExec, env = process.env) {
  const seen: InterpreterProbe[] = [];
  for (const candidate of baseCandidates(platform, env)) {
    const probe = await probeInterpreter(candidate, exec);
    if (!probe) continue;
    if (!seen.some((other) => other.executable === probe.executable)) seen.push(probe);
    // Un Python x86_64 sous Rosetta ne bloque pas la recherche : un arm64 peut suivre.
    if (isUsableBase(probe)) return { found: probe, seen };
  }
  return { found: null, seen };
}

module.exports = {
  SUPPORTED_RANGE_LABEL,
  PROBE_SCRIPT,
  probeEnv,
  probeInterpreter,
  isSupportedVersion,
  isIntelMac,
  baseCandidates,
  describeInterpreter,
  findCompatibleBase,
};
