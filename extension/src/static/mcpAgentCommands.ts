// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file mcpAgentCommands.js
 * @brief Commandes VS Code pour la connexion des agents (Claude Code/Codex) au MCP.
 *
 * Commandes enregistrées :
 *   pileOuFace.mcpOpenAgentsPanel — Ouvre le panneau "Connect Agents"
 *   pileOuFace.mcpDoctor          — Lance le handshake MCP et affiche le diagnostic
 *   pileOuFace.mcpRollback        — Restaure la config d'un agent depuis son .bak
 */

'use strict';

const vscode = require('vscode');

const STATUS_BAR_COMMAND = 'pileOuFace.mcpOpenAgentsPanel';
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;

async function cmdMcpDoctor(bridge, getProjectDir, logChannel) {
  try {
    const diagnosis = await bridge.doctor(getProjectDir());
    if (diagnosis.handshake_ok) {
      vscode.window.showInformationMessage(
        `MCP handshake OK (interpreter: ${diagnosis.interpreter}, protocol: ${diagnosis.protocol_version}).`
      );
    } else {
      vscode.window.showErrorMessage(`MCP handshake failed: ${diagnosis.error || 'unknown error'}`);
    }
    logChannel?.appendLine?.(`[mcpDoctor] ${JSON.stringify(diagnosis)}`);
  } catch (err) {
    vscode.window.showErrorMessage(`MCP doctor failed to run: ${(err && err.message) || err}`);
  }
}

async function cmdMcpRollback(bridge, getProjectDir) {
  const picked = await vscode.window.showQuickPick(
    [
      { label: 'Claude Code', value: 'claude' },
      { label: 'Codex', value: 'codex' },
    ],
    { title: 'Rollback MCP agent config', placeHolder: 'Which agent config should be restored from backup?' }
  );
  if (!picked) return;
  try {
    const result = await bridge.rollback(picked.value, getProjectDir(), 'project');
    if (result.errors && result.errors.length) {
      vscode.window.showErrorMessage(`Rollback failed: ${result.errors.map((e) => e.error).join('; ')}`);
    } else {
      vscode.window.showInformationMessage(`Restored config for ${picked.label} from backup.`);
    }
  } catch (err) {
    vscode.window.showErrorMessage(`Rollback failed: ${(err && err.message) || err}`);
  }
}

function registerMcpAgentCommands(context, deps) {
  const { bridge, getProjectDir, panel, logChannel } = deps;
  const subs = [];

  subs.push(vscode.commands.registerCommand('pileOuFace.mcpOpenAgentsPanel', () => panel.open()));
  subs.push(vscode.commands.registerCommand('pileOuFace.mcpDoctor', () => cmdMcpDoctor(bridge, getProjectDir, logChannel)));
  subs.push(vscode.commands.registerCommand('pileOuFace.mcpRollback', () => cmdMcpRollback(bridge, getProjectDir)));

  return subs;
}

/**
 * Status bar indicator of MCP connection health, refreshed via a doctor handshake
 * on creation and every REFRESH_INTERVAL_MS. Caller is responsible for pushing the
 * returned disposable(s) into context.subscriptions.
 */
function createMcpStatusBarItem({ bridge, getProjectDir, extensionMode }) {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  item.command = STATUS_BAR_COMMAND;
  item.text = '$(plug) MCP';
  item.tooltip = 'Checking MCP agent connection…';
  item.show();

  async function refresh() {
    item.text = '$(sync~spin) MCP';
    item.tooltip = 'Checking MCP agent connection…';
    try {
      const diagnosis = await bridge.doctor(getProjectDir());
      if (diagnosis.handshake_ok) {
        item.text = '$(check) MCP';
        item.tooltip = `MCP handshake OK (${diagnosis.interpreter}).`;
      } else {
        item.text = '$(warning) MCP';
        item.tooltip = `MCP handshake failed: ${diagnosis.error || 'unknown error'}.`;
      }
    } catch (err) {
      item.text = '$(warning) MCP';
      item.tooltip = `MCP doctor failed to run: ${(err && err.message) || err}`;
    }
  }

  // The handshake spawns a real Python subprocess; under the automated E2E
  // runner (ExtensionMode.Test) that competes with the extension host for
  // CPU and can push unrelated webview-rendering tests past their timeout.
  // Background polling stays off there — the doctor command is still
  // reachable manually via pileOuFace.mcpDoctor.
  const isTestMode = extensionMode === vscode.ExtensionMode.Test;
  let timer = null;
  if (!isTestMode) {
    timer = setInterval(refresh, REFRESH_INTERVAL_MS);
    refresh();
  }

  return {
    item,
    refresh,
    dispose() {
      if (timer) clearInterval(timer);
      item.dispose();
    },
  };
}

module.exports = { registerMcpAgentCommands, createMcpStatusBarItem };
