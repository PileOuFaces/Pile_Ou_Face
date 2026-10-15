// SPDX-License-Identifier: AGPL-3.0-only
const { makeRunPython } = require('./pythonRunner');

const SCRIPT = 'backends/static/patch/patch_manager.py';

function makePatchHistoryBridge(ctx) {
  const runPython = ctx.runPython || makeRunPython(ctx);

  async function invoke(args) {
    const { stdout } = await runPython([SCRIPT, ...args]);
    return JSON.parse(stdout);
  }

  return {
    deleteHistory: (binaryPath) => invoke(['delete', '--binary', binaryPath]),
    purgeMissing: (workspacePath) => invoke(['purge-missing', '--workspace', workspacePath]),
  };
}

module.exports = { makePatchHistoryBridge };
