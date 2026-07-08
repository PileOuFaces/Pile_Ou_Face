// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file commands.js
 * @brief Commandes VS Code partagées (navigation, calculette).
 * @see docs/ARCHITECTURE_AUDIT_PLAN.md Phase 2.1
 */

const vscode = require('vscode');
const fs = require('fs');
const { escapeHtml } = require('./utils');
const { getRecentBinaries, describeRecentBinaryMeta } = require('./recentBinaries');

/**
 * @brief Enregistre les commandes partagées (open, goToAddress, calculator).
 * @param {object} context - Contexte VS Code
 * @param {object} deps - { logChannel, openHub }
 * @returns {vscode.Disposable[]}
 */
function registerSharedCommands(context, deps) {
  const { logChannel, openHub } = deps;
  const subs = [];

  const openCmd = vscode.commands.registerCommand('pileOuFace.open', async () => {
    logChannel.show(true);
    const recent = getRecentBinaries(context).filter((e) => e?.path && fs.existsSync(e.path));
    if (!recent.length) {
      openHub('static', { requestBinarySelection: true });
      return;
    }

    const separator = typeof vscode.QuickPickItemKind?.Separator === 'number'
      ? { kind: vscode.QuickPickItemKind.Separator, label: 'Récents' }
      : { label: '────────── Récents', action: '__separator__' };
    const items = [
      {
        label: 'Choisir un fichier à analyser',
        description: 'Binaire natif ou blob brut',
        action: 'pick',
      },
      {
        label: 'Ouvrir le hub',
        description: 'Sans changer la sélection courante',
        action: 'hub',
      },
      separator,
      ...recent.map((entry, index) => ({
        label: index === 0
          ? `Reprendre ${entry.path.split(/[\\/]/).pop() || entry.path}`
          : (entry.path.split(/[\\/]/).pop() || entry.path),
        description: describeRecentBinaryMeta(entry.meta),
        detail: entry.path,
        action: 'recent',
        binaryPath: entry.path,
        binaryMeta: entry.meta,
      })),
    ];

    const picked = await vscode.window.showQuickPick(items, {
      title: 'Pile ou Face',
      placeHolder: 'Choisissez votre point d’entrée',
      matchOnDescription: true,
      matchOnDetail: true,
    });
    if (!picked || picked.action === '__separator__') return;
    if (picked.action === 'hub') {
      openHub('dashboard');
      return;
    }
    if (picked.action === 'pick') {
      openHub('static', { requestBinarySelection: true });
      return;
    }
    if (picked.action === 'recent' && picked.binaryPath) {
      openHub('static', {
        binaryPath: picked.binaryPath,
        binaryMeta: picked.binaryMeta || null,
      });
      return;
    }
    openHub('dashboard');
  });
  subs.push(openCmd);

  const goToAddressCmd = vscode.commands.registerCommand('pileOuFace.goToAddress', () => {
    logChannel.show(true);
    openHub('static', { focusGoToAddr: true });
  });
  subs.push(goToAddressCmd);

  const calculator = vscode.commands.registerCommand('pileOuFace.calculator', async () => {
    const input = await vscode.window.showInputBox({
      prompt: 'Valeur (hex: 0x40, dec: 64, offset: -64 ou -0x40)',
      placeHolder: '0x40 ou 64 ou -64',
      value: '0x40'
    });
    if (!input) return;
    const trimmed = input.trim();
    let n;
    if (/^-?0x[0-9a-fA-F]+$/.test(trimmed)) {
      n = parseInt(trimmed, 16);
    } else if (/^-?\d+$/.test(trimmed)) {
      n = parseInt(trimmed, 10);
    } else if (/^0x[0-9a-fA-F]+$/.test(trimmed) || /^[0-9a-fA-F]+h?$/i.test(trimmed)) {
      n = parseInt(trimmed.replace(/^0x|h$/gi, ''), 16);
    } else {
      vscode.window.showWarningMessage('Format: décimal (64), hex (0x40), ou offset (-64, -0x40)');
      return;
    }
    const hexUnsigned = (n >>> 0).toString(16);
    const hexSigned = n < 0 ? (n >>> 0).toString(16) : n.toString(16);
    const decSigned = n > 0x7fffffff ? n - 0x100000000 : n;
    const panel = vscode.window.createWebviewPanel(
      'pileOuFaceCalc',
      'Calculette d\'offset',
      vscode.ViewColumn.Beside,
      { enableScripts: false }
    );
    panel.webview.html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
      body{font-family:var(--vscode-font-family);padding:16px;font-size:14px;line-height:1.6;}
      .row{margin:8px 0;}
      .label{color:#888;font-size:12px;}
      .value{font-family:monospace;color:#4ec9b0;font-size:16px;}
    </style></head><body>
      <h3>Résultat pour ${escapeHtml(trimmed)}</h3>
      <div class="row"><span class="label">Décimal:</span><br><span class="value">${n}</span></div>
      <div class="row"><span class="label">Décimal (signé 32b si applicable):</span><br><span class="value">${decSigned}</span></div>
      <div class="row"><span class="label">Hex (non signé):</span><br><span class="value">0x${hexUnsigned}</span></div>
      <div class="row"><span class="label">Hex (signé 32b si négatif):</span><br><span class="value">0x${hexSigned}</span></div>
    </body></html>`;
  });
  subs.push(calculator);

  const showLogsCmd = vscode.commands.registerCommand('pileOuFace.showLogs', () => {
    logChannel.show(true);
  });
  subs.push(showLogsCmd);

  return subs;
}

module.exports = { registerSharedCommands };
