// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file visualizer.js
 * @brief Webview de visualisation des traces (stack frames).
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { resolveProjectRoot } = require('../shared/utils');
const { getWebviewContent } = require('../shared/webview');
const { buildFunctionModel, buildMcpPayload, chooseFocusFunction } = require('./pedagogy');

/**
 * @brief Crée la fonction openVisualizerWebview.
 * @param config { context, logChannel, decorationTypes }
 * @return openVisualizerWebview(trace)
 */
function createVisualizer(config) {
  const { context, logChannel, decorationTypes } = config;
  let visualizerPanelRef = null;
  let currentTraceRef = null;
  let functionModelCacheRef = new Map();

  function openVisualizerWebview(trace) {
    currentTraceRef = trace;
    functionModelCacheRef = new Map();
    const besideColumn = vscode?.ViewColumn?.Beside ?? vscode?.ViewColumn?.Two ?? 2;
    const getActiveTrace = () => currentTraceRef || trace;
    const getTraceRunId = (traceData) => {
      const raw = traceData?.meta?.trace_run_id;
      return raw === undefined || raw === null ? null : String(raw);
    };

    const ensureFunctionModel = (traceData, functionName = '') => {
      const requestedFunction = String(functionName || chooseFocusFunction(traceData) || '').trim();
      const cacheKey = requestedFunction || '__default__';
      if (functionModelCacheRef.has(cacheKey)) return functionModelCacheRef.get(cacheKey);
      const model = buildFunctionModel(traceData, requestedFunction);
      functionModelCacheRef.set(cacheKey, model);
      return model;
    };

    const openDisasmIfPresent = async () => {
      const activeTrace = getActiveTrace();
      const meta = activeTrace && activeTrace.meta ? activeTrace.meta : {};
      const asmPath = meta.asm_path;
      if (meta.view_mode !== 'static') return;
      const targetPath = asmPath;
      if (!targetPath || !fs.existsSync(targetPath)) return;
      try {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(targetPath));
        await vscode.window.showTextDocument(doc, {
          viewColumn: vscode.ViewColumn.One,
          preserveFocus: true,
          preview: true
        });
      } catch (err) {
        logChannel.appendLine('[pile-ou-face] open disasm failed: ' + String(err));
      }
    };

    const sendInitToWebview = (panel) => {
      const activeTrace = getActiveTrace();
      ensureFunctionModel(activeTrace, chooseFocusFunction(activeTrace));
      panel.webview.postMessage({
        type: 'init',
        traceRunId: getTraceRunId(activeTrace),
        snapshots: activeTrace.snapshots,
        risks: activeTrace.risks,
        diagnostics: Array.isArray(activeTrace.diagnostics) ? activeTrace.diagnostics : [],
        crash: activeTrace && typeof activeTrace.crash === 'object' ? activeTrace.crash : null,
        meta: activeTrace.meta,
        analysisByStep: activeTrace.analysisByStep ?? {},
        enrichment: activeTrace.enrichment ?? {}
      });
    };

    if (visualizerPanelRef && !visualizerPanelRef.disposed) {
      visualizerPanelRef.reveal(besideColumn);
      sendInitToWebview(visualizerPanelRef);
      openDisasmIfPresent();
      return;
    }

    const visualizerPanel = vscode.window.createWebviewPanel(
      'pileOuFace',
      'Pile ou Face',
      besideColumn,
      { enableScripts: true }
    );
    visualizerPanelRef = visualizerPanel;
    visualizerPanel.onDidDispose(() => {
      visualizerPanelRef = null;
      currentTraceRef = null;
      functionModelCacheRef = new Map();
    });

    visualizerPanel.webview.html = getWebviewContent(visualizerPanel.webview, context.extensionUri);

    visualizerPanel.webview.onDidReceiveMessage(
      async (message) => {
        logChannel.appendLine('[pile-ou-face] webview message: ' + JSON.stringify(message));
        const traceForHandler = getActiveTrace();
        const currentTraceRunId = getTraceRunId(traceForHandler);

        if (message.type === 'ready') {
          sendInitToWebview(visualizerPanel);
          await openDisasmIfPresent();
        }

        if (message.type === 'readTextFile') {
          const requestedPath = typeof message.path === 'string' ? message.path.trim() : '';
          const tr = currentTraceRef || trace;
          const allowedPath = tr?.meta?.disasm_path ? String(tr.meta.disasm_path) : '';
          const folders = vscode.workspace.workspaceFolders;
          const root = folders && folders.length ? resolveProjectRoot(folders[0].uri.fsPath) : '';
          const toAbsolute = (p) => (path.isAbsolute(p) ? p : path.join(root, p));

          let content = '';
          let resolvedAllowed = '';
          try {
            if (requestedPath && allowedPath) {
              const resolvedRequested = path.normalize(toAbsolute(requestedPath));
              resolvedAllowed = path.normalize(toAbsolute(allowedPath));
              if (resolvedRequested === resolvedAllowed && fs.existsSync(resolvedAllowed)) {
                content = fs.readFileSync(resolvedAllowed, 'utf8');
              } else {
                logChannel.appendLine('[pile-ou-face] readTextFile rejected: path not allowed');
              }
            }
          } catch (err) {
            logChannel.appendLine('[pile-ou-face] readTextFile failed: ' + String(err));
          }

          visualizerPanel.webview.postMessage({
            type: 'disasmFileContent',
            path: resolvedAllowed || allowedPath || requestedPath,
            content
          });
          return;
        }

        if (message.type === 'requestAnalysis') {
          const messageTraceRunId = message.traceRunId === undefined || message.traceRunId === null
            ? null
            : String(message.traceRunId);
          if (messageTraceRunId && currentTraceRunId && messageTraceRunId !== currentTraceRunId) {
            logChannel.appendLine(
              `[pile-ou-face] requestAnalysis ignore: trace ${messageTraceRunId} != ${currentTraceRunId}`
            );
            return;
          }
          const requestedStep = Number(message.step);
          if (!Number.isFinite(requestedStep) || requestedStep < 1) return;
          const totalSteps = Array.isArray(traceForHandler?.snapshots) ? traceForHandler.snapshots.length : 0;
          const safeStep = totalSteps ? Math.min(totalSteps, Math.max(1, Math.trunc(requestedStep))) : 1;
          const analysisByStep = traceForHandler?.analysisByStep && typeof traceForHandler.analysisByStep === 'object'
            ? traceForHandler.analysisByStep
            : {};
          visualizerPanel.webview.postMessage({
            type: 'analysisUpdate',
            traceRunId: currentTraceRunId,
            step: safeStep,
            analysis: analysisByStep[String(safeStep)] ?? null
          });
          try {
            const snapshot = Array.isArray(traceForHandler?.snapshots)
              ? traceForHandler.snapshots[safeStep - 1]
              : null;
            const stepFunction = snapshot?.func || chooseFocusFunction(traceForHandler);
            const mcp = buildMcpPayload(
              traceForHandler,
              safeStep,
              ensureFunctionModel(traceForHandler, stepFunction)
            );
            visualizerPanel.webview.postMessage({
              type: 'mcpUpdate',
              traceRunId: currentTraceRunId,
              ...mcp
            });
          } catch (err) {
            logChannel.appendLine('[pile-ou-face] mcpUpdate failed: ' + String(err));
          }
          return;
        }

        if (message.type === 'goToLine') {
          const line = message.line ?? 1;
          let targetFile = message.file;
          logChannel.appendLine(`[goToLine] line=${line} file=${targetFile ?? ''}`);
          const folders = vscode.workspace.workspaceFolders;
          const root = folders && folders.length ? resolveProjectRoot(folders[0].uri.fsPath) : '';

          let docUri = null;
          const tr = currentTraceRef || trace;
          if ((!targetFile || !fs.existsSync(targetFile)) && tr && tr.meta && tr.meta.disasm_path) {
            targetFile = tr.meta.disasm_path;
          }
          if (targetFile) {
            if (path.isAbsolute(targetFile) && fs.existsSync(targetFile)) {
              docUri = vscode.Uri.file(targetFile);
            } else {
              const candidate = path.join(root, targetFile);
              if (fs.existsSync(candidate)) docUri = vscode.Uri.file(candidate);
            }
            if (!docUri) {
              const pattern = path.isAbsolute(targetFile) ? `**/${path.basename(targetFile)}` : `**/${targetFile}`;
              const matches = await vscode.workspace.findFiles(pattern);
              if (matches.length) docUri = matches[0];
            }
          }
          if (!docUri) {
            const asmDocs = await vscode.workspace.findFiles('**/input.asm');
            if (!asmDocs.length) return;
            docUri = asmDocs[0];
          }

          const doc = await vscode.workspace.openTextDocument(docUri);
          const editor = await vscode.window.showTextDocument(doc, {
            viewColumn: vscode.ViewColumn.One,
            preserveFocus: true,
            preview: true
          });
          const range = new vscode.Range(line - 1, 0, line - 1, 1000);
          editor.selection = new vscode.Selection(range.start, range.start);
          editor.revealRange(range, vscode.TextEditorRevealType.InCenter);

          const uriKey = doc.uri.toString();
          let deco = decorationTypes.get(uriKey);
          if (!deco) {
            deco = vscode.window.createTextEditorDecorationType({
              isWholeLine: true,
              backgroundColor: 'rgba(255, 255, 0, 0.25)',
              border: '1px solid rgba(255, 215, 0, 0.6)',
              overviewRulerColor: 'rgba(255, 215, 0, 0.9)',
              overviewRulerLane: vscode.OverviewRulerLane.Right
            });
            decorationTypes.set(uriKey, deco);
          }
          editor.setDecorations(deco, [range]);
        }
      },
      undefined,
      context.subscriptions
    );
  }

  openVisualizerWebview.clearCurrentTrace = function clearCurrentTrace(message = {}) {
    currentTraceRef = null;
    functionModelCacheRef = new Map();
    if (visualizerPanelRef && !visualizerPanelRef.disposed) {
      visualizerPanelRef.webview.postMessage({
        type: 'clearTrace',
        ...message
      });
    }
  };

  return openVisualizerWebview;
}

module.exports = { createVisualizer };
