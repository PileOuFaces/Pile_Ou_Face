// SPDX-License-Identifier: AGPL-3.0-only
const cp = require('child_process');
const path = require('path');

function makeRunPython({ root, extensionPath, getPythonExecutable, buildPythonEnv }) {
  const resolveExe = getPythonExecutable || (() => 'python3');
  const resolveEnv = buildPythonEnv || (() => process.env);
  return (argsWithScript, { timeout = 60000, maxBuffer = 4 * 1024 * 1024 } = {}) =>
    new Promise((resolve, reject) => {
      const [scriptRelPath, ...rest] = argsWithScript;
      const scriptPath = path.join(extensionPath || root, scriptRelPath);
      cp.execFile(resolveExe(), [scriptPath, ...rest], {
        encoding: 'utf8', cwd: root, maxBuffer, timeout, env: resolveEnv(),
      }, (err, stdout, stderr) => {
        if (err) { err.stderr = stderr; reject(err); } else resolve({ stdout });
      });
    });
}

module.exports = { makeRunPython };
