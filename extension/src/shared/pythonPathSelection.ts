// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file pythonPathSelection.ts
 * @brief Sélection native de l'interpréteur Python (POF-P1-002) : seul un fichier
 *        choisi via showOpenDialog et vérifié comme Python 3 peut devenir pythonPath.
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { isPythonExecutableName } = require('./settingsSchema');

const PYTHON_PROBE_TIMEOUT_MS = 5000;
const REQUIRED_PYTHON_MAJOR = '3';
const PYTHON_PROBE_SCRIPT = 'import sys; print(sys.version_info[0])';

type SelectionResult = { ok: boolean; path?: string; cancelled?: boolean; error?: string };

function probePythonMajor(executable: string, execFile = cp.execFile): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      executable,
      ['-c', PYTHON_PROBE_SCRIPT],
      { encoding: 'utf8', timeout: PYTHON_PROBE_TIMEOUT_MS, windowsHide: true },
      (err, stdout) => (err ? reject(err) : resolve(String(stdout || '').trim())),
    );
  });
}

/** Vérifie qu'un chemin désigne un interpréteur Python 3 exécutable. */
async function verifyPythonExecutable(candidate: string, { execFile = cp.execFile, statSync = fs.statSync } = {}): Promise<SelectionResult> {
  if (typeof candidate !== 'string' || !path.isAbsolute(candidate)) {
    return { ok: false, error: 'The selected path is not absolute.' };
  }
  if (!isPythonExecutableName(candidate)) {
    return { ok: false, error: `${path.basename(candidate)} is not a Python executable name (python, python3, python3.x).` };
  }
  try {
    if (!statSync(candidate).isFile()) return { ok: false, error: 'The selected path is not a file.' };
    const major = await probePythonMajor(candidate, execFile);
    if (major !== REQUIRED_PYTHON_MAJOR) {
      return { ok: false, error: `The selected interpreter is not Python ${REQUIRED_PYTHON_MAJOR} (reported ${major || 'nothing'}).` };
    }
  } catch (err) {
    return { ok: false, error: `The selected file could not be run as Python: ${err?.message || err}` };
  }
  return { ok: true, path: candidate };
}

/** Ouvre le sélecteur natif puis vérifie le fichier choisi. */
async function selectPythonExecutable(vscode, { defaultPath = '', execFile = cp.execFile, statSync = fs.statSync } = {}): Promise<SelectionResult> {
  const picked = await vscode.window.showOpenDialog({
    title: 'Pile ou Face — Select a Python 3 interpreter',
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false,
    ...(defaultPath ? { defaultUri: vscode.Uri.file(defaultPath) } : {}),
  });
  if (!picked || !picked[0]) return { ok: false, cancelled: true };
  return verifyPythonExecutable(picked[0].fsPath, { execFile, statSync });
}

module.exports = { selectPythonExecutable, verifyPythonExecutable, PYTHON_PROBE_TIMEOUT_MS };
