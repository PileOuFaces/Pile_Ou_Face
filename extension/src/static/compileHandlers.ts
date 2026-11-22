// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file compileHandlers.ts
 * @brief Webview messages of the compiler panel, under compilePolicy (#548).
 *
 * The binary is always built in a fresh private directory. It is copied
 * elsewhere only to a path the user picked in the native save dialog.
 */
const fs = require('fs');
const path = require('path');
const vscode = require('vscode');
const { ensurePrivateSubdir, writeFileAtomic } = require('../shared/privateTempDir');
const {
  validateCompileFlags,
  validateLangTarget,
  validateSourcePath,
  privateOutputName,
  createExportRegistry,
  exportCompiledBinary,
} = require('./compilePolicy');

const COMPILE_TIMEOUT_MS = 180000;
const SOURCE_FILTERS: Record<string, Record<string, string[]>> = {
  c: { 'C source': ['c'] },
  cpp: { 'C++ source': ['cpp', 'cc', 'cxx'] },
  rust: { 'Rust source': ['rs'] },
  go: { 'Go source': ['go'] },
};

function outputFilter(target: string) {
  const ext = target.startsWith('pe-') ? 'exe' : target.startsWith('macho-') ? '' : 'elf';
  return { ext, filters: ext ? { Binary: [ext] } : { Binary: ['*'] } };
}

/** Validates a compileRequest; returns the host-side parameters or the refusal reason. */
function checkCompileRequest(message, exportRegistry) {
  const langTarget = validateLangTarget(message?.lang, message?.target);
  if (!langTarget.ok) return langTarget;
  const { lang, target } = langTarget.value;
  const flags = validateCompileFlags(message?.flags, lang);
  if (!flags.ok) return flags;
  const source = validateSourcePath(message?.src, lang);
  if (!source.ok) return source;
  const requested = typeof message?.output === 'string' ? message.output : '';
  const exportPath = requested ? exportRegistry.attested(requested) : null;
  if (requested && !exportPath) {
    return { ok: false, reason: 'choose the output file with the … button (native dialog)' };
  }
  return { ok: true, value: { lang, target, flags: flags.value, source: source.value, exportPath } };
}

function createCompileHandlers({ panel, root, runPython, logChannel }) {
  const exportRegistry = createExportRegistry();
  const reply = (payload) => panel.webview.postMessage({ type: 'compileResult', ...payload });

  return {
    compilerBrowseSource: async (message = {} as any) => {
      const lang = String(message.lang || 'c');
      const picked = await vscode.window.showOpenDialog({
        canSelectFiles: true, canSelectFolders: false, canSelectMany: false,
        openLabel: 'Choose source file',
        defaultUri: vscode.Uri.file(root),
        filters: SOURCE_FILTERS[lang] || { Source: ['c', 'cpp', 'cc', 'cxx', 'rs', 'go'] },
      });
      panel.webview.postMessage({ type: 'compilerBrowseSourceResult', path: picked?.[0]?.fsPath || null });
    },
    compilerBrowseOutput: async (message = {} as any) => {
      const target = String(message.target || 'elf-x64');
      const { ext, filters } = outputFilter(target);
      const src = String(message.src || '');
      const stem = src ? path.basename(src, path.extname(src)) : 'output';
      const saved = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(root, ext ? `${stem}.${ext}` : stem)),
        filters,
        title: 'Output binary path',
      });
      if (saved?.fsPath) exportRegistry.remember(saved.fsPath);
      panel.webview.postMessage({ type: 'compilerBrowseOutputResult', path: saved?.fsPath || null });
    },
    compileRequest: async (message = {} as any) => {
      const check = checkCompileRequest(message, exportRegistry);
      if (!check.ok) {
        logChannel?.appendLine(`[compile] request refused: ${check.reason}`);
        reply({ error: `Compilation refused: ${check.reason}.` });
        return;
      }
      const { lang, target, flags, source, exportPath } = check.value;
      try {
        const workDir = fs.mkdtempSync(path.join(ensurePrivateSubdir('compile'), 'build-'));
        const privatePath = path.join(workDir, privateOutputName(source, target));
        const args = ['backends/static/compile/compile.py', '--src', source, '--lang', lang, '--target', target, '--output', privatePath];
        if (flags.length) args.push('--flags', JSON.stringify(flags));
        const { stdout } = await runPython(args, { timeout: COMPILE_TIMEOUT_MS });
        const result = JSON.parse(stdout);
        if (result.output_path && exportPath) {
          exportCompiledBinary(result.output_path, exportPath, writeFileAtomic);
          result.output_path = exportPath;
        }
        reply(result);
      } catch (err) {
        reply({ error: String(err?.message || err) });
      }
    },
  };
}

module.exports = { createCompileHandlers, checkCompileRequest };
