// SPDX-License-Identifier: AGPL-3.0-only
const cp = require('child_process');
const path = require('path');
const { recordRuntimeEvent } = require('./runtimeAudit');

/**
 * Crée une fonction runPython(argsWithScript, opts) qui exécute un script Python en subprocess.
 * @param {string} root - cwd du subprocess.
 * @param {string} [extensionPath] - base de résolution des chemins de script ; retombe sur `root` si omis.
 * @param {function} [getPythonExecutable] - résout l'exécutable python à utiliser (défaut: 'python3').
 * @param {function} [buildPythonEnv] - résout les variables d'env passées au subprocess (défaut: process.env).
 *
 * argsWithScript : [scriptRelPath, ...cliArgs] — scriptRelPath est relatif à extensionPath/root,
 * le reste est passé tel quel comme arguments CLI au script.
 */
function makeRunPython({ root, extensionPath, getPythonExecutable, buildPythonEnv }) {
  const resolveExe = getPythonExecutable || (() => 'python3');
  const resolveEnv = buildPythonEnv || (() => process.env);
  return (argsWithScript, { timeout = 60000, maxBuffer = 4 * 1024 * 1024 } = {}) =>
    new Promise((resolve, reject) => {
      const [scriptRelPath, ...rest] = argsWithScript;
      const scriptPath = path.join(extensionPath || root, scriptRelPath);
      recordRuntimeEvent('python', scriptRelPath, { source: 'pythonRunner', argc: rest.length });
      cp.execFile(resolveExe(), [scriptPath, ...rest], {
        encoding: 'utf8', cwd: root, maxBuffer, timeout, env: resolveEnv(),
      }, (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });
}

module.exports = { makeRunPython };
