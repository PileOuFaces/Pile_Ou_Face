// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file hubCommandPolicy.ts
 * @brief Commands the hub webview may run through `hubExecuteCommand` (#535).
 *
 * The webview is untrusted: without this list it could run any VS Code command with
 * any arguments (e.g. send text to a terminal), bypassing every host-side check.
 * Only the commands the front really uses are allowed, with validated arguments.
 */

// Same shape as decompilers.json keys (e.g. "ghidra", "retdec", "my-tool").
const DECOMPILER_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

type ArgsRule = 'none' | 'optionalDecompilerId';
type PolicyResult = { ok: true; args: string[] } | { ok: false; reason: string };

const ALLOWED_HUB_COMMANDS: Readonly<Record<string, ArgsRule>> = Object.freeze({
  'pileOuFace.decompilerAdd': 'none',
  'pileOuFace.decompilerEdit': 'optionalDecompilerId',
  'pileOuFace.decompilerRemove': 'optionalDecompilerId',
  'pileOuFace.decompilerTest': 'optionalDecompilerId',
  'pileOuFace.decompilerOpenConfig': 'none',
  'pileOuFace.showLogs': 'none',
});

function normalizeArgs(rawArgs: unknown): unknown[] {
  if (rawArgs === undefined || rawArgs === null) return [];
  return Array.isArray(rawArgs) ? rawArgs : [rawArgs];
}

/** Validates a `hubExecuteCommand` request; never throws. */
function checkHubCommand(commandId: unknown, rawArgs: unknown): PolicyResult {
  const id = typeof commandId === 'string' ? commandId.trim() : '';
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_HUB_COMMANDS, id)) {
    return { ok: false, reason: `command not allowed from the hub: ${id || '<empty>'}` };
  }
  const args = normalizeArgs(rawArgs);
  if (ALLOWED_HUB_COMMANDS[id] === 'none') {
    return args.length === 0 ? { ok: true, args: [] } : { ok: false, reason: `${id} takes no arguments` };
  }
  if (args.length === 0) return { ok: true, args: [] };
  if (args.length === 1 && typeof args[0] === 'string' && DECOMPILER_ID.test(args[0])) {
    return { ok: true, args: [args[0]] };
  }
  return { ok: false, reason: `${id} accepts at most one decompiler identifier` };
}

module.exports = { ALLOWED_HUB_COMMANDS, checkHubCommand };
