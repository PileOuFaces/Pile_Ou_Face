// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Bridge from the VS Code extension (commands, status bar, "Connect Agents"
 * webview) to backends/mcp/setup_cli.py. Each method spawns the CLI via
 * pythonRunner with --json and parses its structured output — callers never
 * need to parse the CLI's human-readable text output.
 */
const { makeRunPython } = require('./pythonRunner');

const SCRIPT = 'backends/mcp/setup_cli.py';

function makeMcpSetupBridge(ctx) {
  const runPython = ctx.runPython || makeRunPython(ctx);

  async function invoke(args) {
    const { stdout } = await runPython([SCRIPT, '--json', ...args]);
    return JSON.parse(stdout);
  }

  function installArgs(agent, projectDir, scope) {
    const args = ['--agent', agent, '--project-dir', projectDir];
    if (scope) args.push('--scope', scope);
    return args;
  }

  return {
    preview: (agent, projectDir, scope) =>
      invoke([...installArgs(agent, projectDir, scope), '--dry-run']),
    apply: (agent, projectDir, scope) =>
      invoke(installArgs(agent, projectDir, scope)),
    rollback: (agent, projectDir, scope) =>
      invoke([...installArgs(agent, projectDir, scope), '--rollback']),
    doctor: (projectDir) =>
      invoke(['--project-dir', projectDir, '--doctor']),
  };
}

module.exports = { makeMcpSetupBridge };
