// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function createGraphRenderers({
  panel,
  analysisCtx,
  root,
  runPythonJson,
  ensureTempDir,
  logChannel,
  vscode,
  fs,
  path,
  getCfgScript,
  getCallGraphScript,
  getDiscoverFunctionsScript,
}) {
  const {
    resolveAnalysisArtifactsContext,
    resolveCachedAnalysisView,
    ensureDiscoveredFunctionsArtifact,
    loadBinarySymbols,
  } = analysisCtx;

  const hubPost = (type, data) => panel.webview.postMessage(Object.assign({ type }, data || {}));

  return {
    hubLoadCfg: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const {
        mappingPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'CFG',
        ensureMapping: true,
      });
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] } });
          return;
        }
      }
      try {
        if (fs.existsSync(mappingPath)) {
          const cfg = await resolveCachedAnalysisView({
            effectiveAbsPath,
            allowCache,
            cacheKey: 'cfg',
            logLabel: 'CFG',
            compute: () => runPythonJson(getCfgScript(root), ['--mapping', mappingPath]),
          });
          hubPost('hubCfg', { cfg });
        } else {
          logChannel.appendLine(`[CFG] Mapping introuvable: ${mappingPath}`);
          hubPost('hubCfg', { cfg: { blocks: [], edges: [] } });
        }
      } catch (err) {
        logChannel.appendLine(`[CFG] Erreur: ${err.message}`);
        hubPost('hubCfg', { cfg: { blocks: [], edges: [] } });
      }
    },

    hubLoadCallGraph: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const {
        absPath,
        artifacts,
        baseName,
        mappingPath,
        symbolsPath,
        discoveredPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'CallGraph',
        exampleLimit: 2,
        ensureMapping: true,
      });
      const resolvedSymbolsPath = symbolsPath;
      let resolvedDiscoveredPath = discoveredPath;
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
          return;
        }
      }
      try {
        const binForSymbols = (effectiveAbsPath && fs.existsSync(effectiveAbsPath)) ? effectiveAbsPath : absPath;
        if (artifacts?.binaryMeta?.kind === 'raw') {
          resolvedDiscoveredPath = await ensureDiscoveredFunctionsArtifact({
            artifacts,
            absPath,
            mappingPath,
            baseName,
          }) || resolvedDiscoveredPath;
          if (resolvedDiscoveredPath && fs.existsSync(resolvedDiscoveredPath)) {
            fs.writeFileSync(resolvedSymbolsPath, fs.readFileSync(resolvedDiscoveredPath, 'utf8'), 'utf8');
          } else {
            fs.writeFileSync(resolvedSymbolsPath, '[]', 'utf8');
          }
        } else if (!fs.existsSync(resolvedSymbolsPath) && fs.existsSync(binForSymbols)) {
          const symbols = await loadBinarySymbols(binForSymbols);
          fs.writeFileSync(resolvedSymbolsPath, JSON.stringify(symbols, null, 2), 'utf8');
        }
        if (fs.existsSync(mappingPath) && fs.existsSync(resolvedSymbolsPath)) {
          const callGraph = await resolveCachedAnalysisView({
            effectiveAbsPath,
            allowCache,
            cacheKey: 'callgraph',
            logLabel: 'Call graph',
            compute: () => runPythonJson(getCallGraphScript(root), ['--mapping', mappingPath, '--symbols', resolvedSymbolsPath]),
          });
          hubPost('hubCallGraph', { callGraph });
        } else {
          logChannel.appendLine(`[CallGraph] Fichiers manquants: mapping=${fs.existsSync(mappingPath)}, symbols=${fs.existsSync(resolvedSymbolsPath)}`);
          hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
        }
      } catch (err) {
        logChannel.appendLine(`[CallGraph] Erreur: ${err.message}`);
        hubPost('hubCallGraph', { callGraph: { nodes: [], edges: [] } });
      }
    },

    hubLoadDiscoveredFunctions: async (message) => {
      const binaryPath = (message.binaryPath || '').trim();
      const {
        absPath,
        artifacts,
        mappingPath,
        discoveredPath,
        effectiveAbsPath,
        allowCache,
        hasAnalyzableBinary,
      } = await resolveAnalysisArtifactsContext({
        binaryPath,
        binaryMeta: message.binaryMeta || null,
        logPrefix: 'Discovered',
        ensureMapping: true,
      });
      const resolvedDiscoveredPath = discoveredPath;
      if (!fs.existsSync(mappingPath)) {
        if (!hasAnalyzableBinary) {
          hubPost('hubDiscoveredFunctions', { functions: [] });
          return;
        }
      }
      try {
        if (!allowCache && fs.existsSync(resolvedDiscoveredPath)) {
          const rawCached = JSON.parse(fs.readFileSync(resolvedDiscoveredPath, 'utf8'));
          hubPost('hubDiscoveredFunctions', { functions: rawCached, analyzed: true });
          return;
        }
        if (fs.existsSync(mappingPath)) {
          const discScript = getDiscoverFunctionsScript(root);
          const binArg = (artifacts?.binaryMeta?.kind === 'raw')
            ? null
            : ((effectiveAbsPath && fs.existsSync(effectiveAbsPath) && !fs.statSync(effectiveAbsPath).isDirectory()) ? effectiveAbsPath : (absPath && fs.existsSync(absPath) && !fs.statSync(absPath).isDirectory() ? absPath : null));
          const args = [discScript, '--mapping', mappingPath];
          if (binArg) args.push('--binary', binArg);
          const functions = await resolveCachedAnalysisView({
            effectiveAbsPath,
            allowCache,
            cacheKey: 'discovered',
            logLabel: 'Fonctions découvertes',
            compute: async () => {
              const discovered = await runPythonJson(discScript, args.slice(1));
              if (!allowCache && artifacts?.binaryMeta?.kind === 'raw') {
                fs.writeFileSync(resolvedDiscoveredPath, JSON.stringify(discovered, null, 2), 'utf8');
              }
              return discovered;
            },
          });
          hubPost('hubDiscoveredFunctions', { functions, analyzed: true });
        } else {
          logChannel.appendLine(`[Discovered] Mapping introuvable: ${mappingPath}`);
          hubPost('hubDiscoveredFunctions', { functions: [] });
        }
      } catch (err) {
        logChannel.appendLine(`[Discovered] Erreur: ${err.message}`);
        hubPost('hubDiscoveredFunctions', { functions: [], analyzed: true, error: err.message });
      }
    },

    hubExportCfgSvg: async (message) => {
      const svg = message.svg || '';
      if (!svg) return;
      const tempDir = ensureTempDir(root);
      const defaultPath = path.join(tempDir, 'cfg_export.svg');
      vscode.window.showSaveDialog({
        title: 'Exporter le graphe CFG en SVG',
        defaultUri: vscode.Uri.file(defaultPath),
        filters: { 'SVG': ['svg'], 'Tous': ['*'] }
      }).then(async (saveUri) => {
        if (!saveUri) return;
        try {
          await fs.promises.writeFile(saveUri.fsPath, svg, 'utf8');
          vscode.window.showInformationMessage(`CFG exporté: ${path.basename(saveUri.fsPath)}`);
        } catch (err) {
          vscode.window.showErrorMessage(`Export échoué: ${err.message}`);
        }
      });
    },
  };
}

module.exports = { createGraphRenderers };
