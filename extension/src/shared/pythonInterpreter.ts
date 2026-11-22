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

const SUPPORTED_MIN = { major: 3, minor: 10 };
const SUPPORTED_MAX = { major: 3, minor: 13 };
const SUPPORTED_RANGE_LABEL = `${SUPPORTED_MIN.major}.${SUPPORTED_MIN.minor}–${SUPPORTED_MAX.major}.${SUPPORTED_MAX.minor}`;
const PROBE_SCRIPT = 'import sys, platform; print(sys.version_info[0], sys.version_info[1], sys.platform, platform.machine(), sys.executable)';
const PROBE_TIMEOUT_MS = 15000;

type Exec = (file: string, args: string[]) => Promise<{ ok: boolean; stdout: string }>;
type InterpreterProbe = { major: number; minor: number; platform: string; machine: string; executable: string };
type Candidate = { command: string; args: string[] };

function defaultExec(file: string, args: string[]): Promise<{ ok: boolean; stdout: string }> {
  return new Promise((resolve) => {
    cp.execFile(file, args, { timeout: PROBE_TIMEOUT_MS }, (error, stdout) => {
      resolve({ ok: !error, stdout: String(stdout || '') });
    });
  });
}

async function probeInterpreter(candidate: Candidate, exec: Exec = defaultExec): Promise<InterpreterProbe | null> {
  const result = await exec(candidate.command, [...candidate.args, '-c', PROBE_SCRIPT]);
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

function supportedMinors(): number[] {
  const minors: number[] = [];
  for (let minor = SUPPORTED_MAX.minor; minor >= SUPPORTED_MIN.minor; minor -= 1) minors.push(minor);
  return minors;
}

/** Ordre de recherche : versions explicites de la plage (la plus récente d'abord), puis les noms génériques. */
function baseCandidates(platform: string = process.platform): Candidate[] {
  if (platform === 'win32') {
    return [
      ...supportedMinors().map((minor) => ({ command: 'py', args: [`-3.${minor}`] })),
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
async function findCompatibleBase(platform: string = process.platform, exec: Exec = defaultExec) {
  const seen: InterpreterProbe[] = [];
  for (const candidate of baseCandidates(platform)) {
    const probe = await probeInterpreter(candidate, exec);
    if (!probe) continue;
    if (!seen.some((other) => other.executable === probe.executable)) seen.push(probe);
    if (isSupportedVersion(probe)) return { found: probe, seen };
  }
  return { found: null, seen };
}

module.exports = {
  SUPPORTED_RANGE_LABEL,
  probeInterpreter,
  isSupportedVersion,
  baseCandidates,
  describeInterpreter,
  findCompatibleBase,
};
