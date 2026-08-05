// SPDX-License-Identifier: AGPL-3.0-only
const { makeRunPython } = require('./pythonRunner');

const SCRIPT = 'backends/shared/chat_history.py';

function makeChatHistoryBridge(ctx) {
  const runPython = ctx.runPython || makeRunPython(ctx);
  const dbArgs = ctx.dbPathOverride ? ['--db', ctx.dbPathOverride] : [];
  let pendingMutation = Promise.resolve();

  async function invoke(command, payload = null) {
    const options = payload === null ? {} : { input: JSON.stringify(payload) };
    const { stdout } = await runPython(
      [SCRIPT, command, '--workspace', ctx.workspacePath, ...dbArgs],
      options,
    );
    return JSON.parse(stdout);
  }

  return {
    loadHistory: () => pendingMutation.catch(() => undefined).then(() => invoke('load')),
    saveHistory: (payload) => {
      pendingMutation = pendingMutation
        .catch(() => undefined)
        .then(() => invoke('save', payload));
      return pendingMutation;
    },
  };
}

module.exports = { makeChatHistoryBridge };
