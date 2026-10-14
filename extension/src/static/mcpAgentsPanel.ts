// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file mcpAgentsPanel.js
 * @brief Webview "Connect Agents" — preview/apply/rollback MCP agent configs
 * (Claude Code, Codex, ...) and run the doctor handshake, backed by
 * backends/mcp/setup_cli.py via mcpSetupBridge.
 */

'use strict';

const vscode = require('vscode');
const fs = require('fs');

const VIEW_TYPE = 'pileOuFaceMcpAgents';

const RESULT_TYPE_BY_REQUEST = {
  mcpPreview: 'mcpPreviewResult',
  mcpApply: 'mcpApplyResult',
  mcpRollback: 'mcpRollbackResult',
  mcpRunDoctor: 'mcpDoctorResult',
};

function getMcpAgentsContent(webview, extensionUri) {
  const html = fs.readFileSync(
    vscode.Uri.joinPath(extensionUri, 'front', 'mcpAgents.html').fsPath, 'utf8'
  );
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'mcpAgents.js'));
  const messageBusUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messageBus.js'));
  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    .replace(/{{messageBusUri}}/g, messageBusUri.toString())
    .replace(/{{cspSource}}/g, webview.cspSource);
}

/**
 * @param {object} config - { context, bridge, getProjectDir }
 *   bridge: mcpSetupBridge instance ({preview, apply, rollback, doctor})
 *   getProjectDir: () => string, resolves the target workspace root
 * @returns {{ open: () => vscode.WebviewPanel }}
 */
function createMcpAgentsPanel(config) {
  const { context, bridge, getProjectDir } = config;
  let panelRef = null;

  async function dispatch(msg) {
    const resultType = RESULT_TYPE_BY_REQUEST[msg.type];
    if (!resultType) return;
    const projectDir = msg.projectDir || getProjectDir();
    try {
      let result;
      if (msg.type === 'mcpRunDoctor') {
        result = await bridge.doctor(projectDir);
      } else if (msg.type === 'mcpPreview') {
        result = await bridge.preview(msg.agent, projectDir, msg.scope);
      } else if (msg.type === 'mcpApply') {
        result = await bridge.apply(msg.agent, projectDir, msg.scope);
      } else if (msg.type === 'mcpRollback') {
        result = await bridge.rollback(msg.agent, projectDir, msg.scope);
      }
      panelRef.webview.postMessage({ type: resultType, requestId: msg.requestId, result });
    } catch (err) {
      panelRef.webview.postMessage({
        type: resultType,
        requestId: msg.requestId,
        error: String((err && err.message) || err),
      });
    }
  }

  function open() {
    if (panelRef) {
      panelRef.reveal(vscode.ViewColumn.Beside);
      return panelRef;
    }
    const panel = vscode.window.createWebviewPanel(
      VIEW_TYPE,
      'Connect Agents (MCP)',
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [context.extensionUri],
      }
    );
    panelRef = panel;
    panel.onDidDispose(() => { panelRef = null; });
    panel.webview.html = getMcpAgentsContent(panel.webview, context.extensionUri);
    panel.webview.onDidReceiveMessage(dispatch);
    return panel;
  }

  return { open };
}

module.exports = { createMcpAgentsPanel, getMcpAgentsContent };
