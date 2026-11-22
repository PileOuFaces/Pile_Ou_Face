// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file decompilerLocalPaths.ts
 * @brief Host-side selection and checks of local decompiler folders (#531).
 *
 * Two distinct things (see decompilerPathsSchema.ts for the trust model):
 * - TRUST comes only from the user choosing the folder in the host's native dialog;
 * - STRUCTURE (expected files present) only catches a wrong folder. A folder holding a
 *   file named analyzeHeadless is not proven to be a genuine Ghidra: it is accepted
 *   because the user chose it, and it is re-checked before every use.
 */

const fs = require('fs');
const path = require('path');
const { isSupportedDecompilerId, pathShapeProblem } = require('./decompilerPathsSchema');

type Platform = string;
type FsDeps = { statSync?: typeof fs.statSync; realpathSync?: typeof fs.realpathSync };
type CheckResult = { ok: boolean; path?: string; error?: string; cancelled?: boolean };

// Files a Ghidra installation folder must contain, per platform family.
const STRUCTURE: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>> = Object.freeze({
  ghidra: Object.freeze({
    posix: ['support/analyzeHeadless', 'Ghidra/application.properties'],
    win32: ['support/analyzeHeadless.bat', 'Ghidra/application.properties'],
  }),
});
// Environment variable the backend reads for each decompiler.
const ENV_VARIABLE: Readonly<Record<string, string>> = Object.freeze({ ghidra: 'GHIDRA_INSTALL_DIR' });

function requiredFiles(decompilerId: string, platform: Platform): readonly string[] {
  const spec = STRUCTURE[decompilerId];
  return platform === 'win32' ? spec.win32 : spec.posix;
}

function isFile(candidate: string, statSync): boolean {
  try {
    return statSync(candidate).isFile();
  } catch {
    return false;
  }
}

/**
 * Structural check only. Returns the canonical folder (symlinks resolved) so that the
 * attested value is the folder actually used.
 */
function checkInstallFolder(
  decompilerId: string,
  folder: unknown,
  { platform = process.platform, statSync = fs.statSync, realpathSync = fs.realpathSync }: FsDeps & { platform?: Platform } = {},
): CheckResult {
  if (!isSupportedDecompilerId(decompilerId)) return { ok: false, error: `Unsupported decompiler: ${String(decompilerId)}.` };
  const shapeProblem = pathShapeProblem(folder);
  if (shapeProblem) return { ok: false, error: `Invalid folder (${shapeProblem}).` };
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  if (!pathApi.isAbsolute(folder as string)) return { ok: false, error: 'Invalid folder (expected an absolute path).' };
  let canonical: string;
  try {
    canonical = realpathSync(folder as string);
    if (!statSync(canonical).isDirectory()) return { ok: false, error: 'The selected path is not a folder.' };
  } catch (err) {
    return { ok: false, error: `The selected folder cannot be read: ${err?.message || err}` };
  }
  const missing = requiredFiles(decompilerId, platform).filter((relative) => (
    !isFile(pathApi.join(canonical, ...relative.split('/')), statSync)
  ));
  if (missing.length) {
    return { ok: false, error: `This folder does not look like a ${decompilerId} installation (missing: ${missing.join(', ')}).` };
  }
  return { ok: true, path: canonical };
}

/** Native folder dialog, then structural check. Never reads a path from the webview. */
async function selectInstallFolder(vscode, decompilerId: string, { defaultPath = '', ...deps }: FsDeps & { defaultPath?: string; platform?: Platform } = {}): Promise<CheckResult> {
  if (!isSupportedDecompilerId(decompilerId)) return { ok: false, error: `Unsupported decompiler: ${String(decompilerId)}.` };
  const picked = await vscode.window.showOpenDialog({
    title: `Pile ou Face — Select the ${decompilerId} installation folder`,
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
    ...(defaultPath ? { defaultUri: vscode.Uri.file(defaultPath) } : {}),
  });
  if (!picked || !picked[0]) return { ok: false, cancelled: true };
  return checkInstallFolder(decompilerId, picked[0].fsPath, deps);
}

/**
 * Environment for the backend from attested, migrated paths (readStoredSettings). The
 * structure is checked again: a folder that changed since its selection is not used.
 */
function decompilerEnvFromPaths(paths: unknown, { log = (_message: string) => {}, ...deps }: FsDeps & { platform?: Platform; log?: (message: string) => void } = {}): Record<string, string> {
  const env: Record<string, string> = {};
  if (!paths || typeof paths !== 'object') return env;
  for (const [decompilerId, folder] of Object.entries(paths as Record<string, unknown>)) {
    if (!ENV_VARIABLE[decompilerId]) continue;
    const check = checkInstallFolder(decompilerId, folder, deps);
    if (check.ok) env[ENV_VARIABLE[decompilerId]] = check.path;
    else log(`[decompiler] ${decompilerId} folder ignored: ${check.error}`);
  }
  return env;
}

module.exports = { checkInstallFolder, selectInstallFolder, decompilerEnvFromPaths };
