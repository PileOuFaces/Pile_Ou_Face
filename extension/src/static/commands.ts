// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file commands.js
 * @brief Commandes VS Code liées au mode statique (désassemblage, xrefs, sidebar).
 * @see docs/ARCHITECTURE_AUDIT_PLAN.md Phase 2.1
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { getDisasmScript, getXrefsScript } = require('../shared/paths');
const { getExtensionPath } = require('../shared/utils');
const { recordRuntimeEvent } = require('../shared/runtimeAudit');

/**
 * @brief Enregistre les commandes statiques et retourne les subscriptions.
 * @param {object} context - Contexte VS Code
 * @param {object} deps - { ensureTempDir, runCommand, detectPythonExecutable, logChannel }
 * @param {object} providers - { root, pythonExe, ensureStaticAsm, refreshSidebar }
 * @returns {vscode.Disposable[]}
 */
function readMappingBinary(mappingPath) {
  try {
    const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
    return mapping.binary || '';
  } catch (_) {
    return '';
  }
}

function getDisasmSelectionContext(document, selection) {
  const activeLine = selection?.active?.line ?? 0;
  const lineText = document.lineAt(activeLine).text;
  const selectedText = document.getText(selection).trim();
  const instructionText = selectedText || lineText.trim();
  const addrMatch = lineText.match(/^\s*(0x[0-9a-fA-F]+)\s*:/);
  let functionName = '';
  for (let lineIndex = activeLine - 1; lineIndex >= Math.max(0, activeLine - 250); lineIndex -= 1) {
    const candidate = document.lineAt(lineIndex).text.match(/^\s*([^:\s][^:]*)\s*:\s*$/);
    if (candidate) {
      functionName = candidate[1].trim();
      break;
    }
  }
  return {
    addr: addrMatch?.[1] || '',
    functionName,
    instructionText: instructionText.slice(0, 6000),
  };
}

function buildDisasmAiPrompt({ binaryPath = '', addr = '', functionName = '', instructionText = '' }) {
  const lines = [
    'Analyse ce code désassemblé et explique précisément son comportement.',
    binaryPath ? `Binaire : ${binaryPath}` : '',
    functionName ? `Fonction : ${functionName}` : '',
    addr ? `Adresse active : ${addr}` : '',
    '',
    'Code sélectionné :',
    '```asm',
    instructionText,
    '```',
    '',
    'Décris les effets sur les registres et la mémoire, les branchements ou appels, puis signale les risques de sécurité éventuels.',
  ];
  return lines.filter((line, index) => line || index >= 4).join('\n').trim();
}

function registerStaticCommands(context, deps, providers) {
  const {
    ensureTempDir,
    storageDir,
    runCommand,
    logChannel,
  } = deps;
  const { root, pythonExe, refreshSidebar, openHub } = providers;

  const subs = [];

  const askAiAboutDisasm = vscode.commands.registerCommand('pileOuFace.askAiAboutDisasm', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor?.document?.uri?.fsPath?.match(/\.asm$/i)) {
      vscode.window.showWarningMessage('Ouvrez un fichier de désassemblage (.asm).');
      return;
    }
    const contextData = getDisasmSelectionContext(editor.document, editor.selection);
    if (!contextData.instructionText || !contextData.addr) {
      vscode.window.showWarningMessage('Placez le curseur sur une instruction du désassemblage.');
      return;
    }
    const docPath = editor.document.uri.fsPath;
    const baseName = path.basename(docPath, '.asm').replace(/\.disasm$/, '');
    const mappingPath = path.join(path.dirname(docPath), `${baseName}.disasm.mapping.json`);
    const binaryPath = fs.existsSync(mappingPath) ? readMappingBinary(mappingPath) : '';
    const prompt = buildDisasmAiPrompt({ ...contextData, binaryPath });
    if (typeof openHub === 'function') {
      openHub('dashboard', { aiPrompt: prompt });
    }
  });
  subs.push(askAiAboutDisasm);

  const exportDisasm = vscode.commands.registerCommand('pileOuFace.exportDisasm', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !editor.document) {
      vscode.window.showWarningMessage('Ouvrez un fichier de désassemblage (.asm) pour l\'exporter.');
      return;
    }
    const doc = editor.document;
    const uri = doc.uri;
    if (!uri.fsPath.match(/\.(asm|disasm\.asm)$/)) {
      vscode.window.showWarningMessage('Le fichier actuel n\'est pas un désassemblage (.asm).');
      return;
    }
    const defaultName = path.basename(uri.fsPath, path.extname(uri.fsPath))
      .replace(/\.disasm$/, '') + '.disasm.txt';
    const defaultPath = path.join(path.dirname(uri.fsPath), defaultName);
    const saveUri = await vscode.window.showSaveDialog({
      title: 'Exporter le désassemblage',
      defaultUri: vscode.Uri.file(defaultPath),
      filters: { 'Texte': ['txt'], 'Tous': ['*'] }
    });
    if (!saveUri) return;
    try {
      const text = doc.getText();
      await fs.promises.writeFile(saveUri.fsPath, text, 'utf8');
      vscode.window.showInformationMessage(`Exporté: ${path.basename(saveUri.fsPath)}`);
    } catch (err) {
      vscode.window.showErrorMessage(`Export échoué: ${err.message}`);
    }
  });
  subs.push(exportDisasm);

  const xrefsTo = vscode.commands.registerCommand('pileOuFace.xrefsTo', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    const doc = editor.document;
    let addr = doc.getText(editor.selection).trim();
    if (!addr) {
      const wordRange = doc.getWordRangeAtPosition(editor.selection.active, /0x[0-9a-fA-F]+|[0-9a-fA-F]{6,}/);
      addr = wordRange ? doc.getText(wordRange).trim() : '';
    }
    if (!addr) {
      const line = doc.lineAt(editor.selection.active.line);
      const m = line.text.match(/^\s*([0-9a-fA-F]+):/);
      addr = m ? (m[1].startsWith('0x') ? m[1] : `0x${m[1]}`) : '';
    }
    if (!addr) {
      vscode.window.showWarningMessage('Placez le curseur sur une adresse.');
      return;
    }
    if (!root) return;
    const r = root;
    const docPath = doc.uri.fsPath;
    const baseName = path.basename(docPath, '.asm').replace(/\.disasm/, '');
    const mappingPath = path.join(path.dirname(docPath), `${baseName}.disasm.mapping.json`);
    if (!fs.existsSync(mappingPath)) {
      vscode.window.showErrorMessage('Fichier de mapping introuvable. Ouvrez d\'abord le désassemblage.');
      return;
    }
    try {
      const binaryPath = readMappingBinary(mappingPath);
      const xrefsArgs = [getXrefsScript(r), '--mapping', mappingPath, '--addr', addr, '--mode', 'to'];
      if (binaryPath) xrefsArgs.push('--binary', binaryPath);
      const backendRoot = getExtensionPath() || r;
      const out = await new Promise((resolve, reject) => {
        cp.execFile(pythonExe, xrefsArgs, { encoding: 'utf8', cwd: r, maxBuffer: 4 * 1024 * 1024, timeout: 30000, env: { ...process.env, PYTHONPATH: backendRoot } }, (err, stdout) => {
          if (err) reject(err); else resolve(stdout);
        });
      });
      const data = JSON.parse(out);
      const refs = data.refs || [];
      if (refs.length === 0) {
        vscode.window.showInformationMessage(`Aucune référence vers ${addr}`);
        return;
      }
      const items = refs.map(rr => {
        const fnLabel = rr.function_name ? ` · ${rr.function_name}` : '';
        return {
          label: `${rr.from_addr}${fnLabel}`,
          description: rr.text?.substring(0, 70),
          detail: rr.type,
          ref: rr,
        };
      });
      const chosen = await vscode.window.showQuickPick(items, { title: `Références vers ${addr}`, matchOnDescription: true });
      if (chosen && chosen.ref.from_line) {
        const range = new vscode.Range(chosen.ref.from_line - 1, 0, chosen.ref.from_line - 1, 1000);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
        editor.selection = new vscode.Selection(range.start, range.start);
      }
    } catch (err) {
      vscode.window.showErrorMessage(`Xrefs: ${err.message}`);
    }
  });
  subs.push(xrefsTo);

  const xrefsFrom = vscode.commands.registerCommand('pileOuFace.xrefsFrom', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    const doc = editor.document;
    const line = doc.lineAt(editor.selection.active.line);
    const lineText = line.text;
    const addrMatch = lineText.match(/^\s*([0-9a-fA-F]+):/);
    if (!addrMatch) {
      vscode.window.showWarningMessage('Placez le curseur sur une ligne d\'instruction (format: addr: ...).');
      return;
    }
    const addr = addrMatch[1].startsWith('0x') ? addrMatch[1] : `0x${addrMatch[1]}`;
    if (!root) return;
    const r = root;
    const docPath = doc.uri.fsPath;
    const baseName = path.basename(docPath, '.asm').replace(/\.disasm/, '');
    const mappingPath = path.join(path.dirname(docPath), `${baseName}.disasm.mapping.json`);
    if (!fs.existsSync(mappingPath)) {
      vscode.window.showErrorMessage('Fichier de mapping introuvable.');
      return;
    }
    try {
      const binaryPath = readMappingBinary(mappingPath);
      const xrefsArgs = [getXrefsScript(r), '--mapping', mappingPath, '--addr', addr, '--mode', 'from'];
      if (binaryPath) xrefsArgs.push('--binary', binaryPath);
      const backendRoot = getExtensionPath() || r;
      const out = await new Promise((resolve, reject) => {
        cp.execFile(pythonExe, xrefsArgs, { encoding: 'utf8', cwd: r, maxBuffer: 4 * 1024 * 1024, timeout: 30000, env: { ...process.env, PYTHONPATH: backendRoot } }, (err, stdout) => {
          if (err) reject(err); else resolve(stdout);
        });
      });
      const data = JSON.parse(out);
      const targets = data.targets || [];
      if (targets.length === 0) {
        vscode.window.showInformationMessage(`L'instruction à ${addr} ne référence aucune adresse.`);
        return;
      }
      vscode.window.showInformationMessage(`Références depuis ${addr}: ${targets.join(', ')}`);
    } catch (err) {
      vscode.window.showErrorMessage(`Xrefs: ${err.message}`);
    }
  });
  subs.push(xrefsFrom);

  const sidebarRefresh = vscode.commands.registerCommand('pileOuFace.sidebarRefresh', async () => {
    const binaryPath = await vscode.window.showInputBox({ prompt: 'Chemin du binaire', placeHolder: 'examples/stack3.elf' });
    if (binaryPath && refreshSidebar) {
      refreshSidebar(binaryPath);
      recordRuntimeEvent('host_effect', 'pileOuFace.sidebarRefresh', { source: 'staticCommands', effect: 'sidebar.refresh', binaryPath: path.basename(binaryPath) });
    }
  });
  subs.push(sidebarRefresh);

  const goToSymbolInDisasm = vscode.commands.registerCommand('pileOuFace.goToSymbolInDisasm', async (addr, binaryPath) => {
    if (!addr || !root) return;
    const absPath = path.isAbsolute(binaryPath) ? binaryPath : path.join(root, binaryPath);
    if (!fs.existsSync(absPath)) {
      vscode.window.showErrorMessage('Binaire introuvable.');
      return;
    }
    const tempDir = storageDir || ensureTempDir(root);
    const baseName = path.basename(absPath, path.extname(absPath)) || 'binary';
    const disasmPath = path.join(tempDir, `${baseName}.disasm.asm`);
    const mappingPath = path.join(tempDir, `${baseName}.disasm.mapping.json`);
    if (!fs.existsSync(disasmPath)) {
      await runCommand(
        pythonExe,
        [
          getDisasmScript(root),
          '--binary',
          absPath,
          '--output',
          disasmPath,
          '--output-mapping',
          mappingPath,
          '--dwarf-lines',
          '--cache-db',
          'auto',
        ],
        root,
        logChannel,
        { PYTHONPATH: getExtensionPath() || root }
      );
    }
    if (fs.existsSync(disasmPath)) {
      const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
      const addrVal = parseInt(addr, 16);
      const entry = (mapping.lines || []).find(l => l.addr && parseInt(l.addr, 16) === addrVal);
      if (entry) {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(disasmPath));
        const editor = await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, preview: false });
        const range = new vscode.Range(entry.line - 1, 0, entry.line - 1, 1000);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
        editor.selection = new vscode.Selection(range.start, range.start);
      }
    }
  });
  subs.push(goToSymbolInDisasm);

  const disasmSection = vscode.commands.registerCommand('pileOuFace.disasmSection', async (sectionName, binaryPath) => {
    if (!sectionName || !binaryPath || !root) return;
    const absPath = path.isAbsolute(binaryPath) ? binaryPath : path.join(root, binaryPath);
    if (!fs.existsSync(absPath)) {
      vscode.window.showErrorMessage('Binaire introuvable.');
      return;
    }
    const tempDir = storageDir || ensureTempDir(root);
    const baseName = path.basename(absPath, path.extname(absPath)) || 'binary';
    const disasmPath = path.join(tempDir, `${baseName}.disasm.asm`);
    const mappingPath = path.join(tempDir, `${baseName}.disasm.mapping.json`);
    await runCommand(
      pythonExe,
      [
        getDisasmScript(root),
        '--binary',
        absPath,
        '--output',
        disasmPath,
        '--output-mapping',
        mappingPath,
        '--section',
        sectionName,
      ],
      root,
      logChannel,
      { PYTHONPATH: getExtensionPath() || root }
    );
    if (fs.existsSync(disasmPath)) {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(disasmPath));
      await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, preview: false });
    }
  });
  subs.push(disasmSection);

  return subs;
}

module.exports = {
  buildDisasmAiPrompt,
  getDisasmSelectionContext,
  registerStaticCommands,
};
