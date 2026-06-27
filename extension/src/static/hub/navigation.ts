// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function createNavigation({
  panel,
  analysisCtx,
  logChannel,
  vscode,
  fs,
  path,
  normalizeAddress,
  parseIntLiteral,
  symbolLookupCandidates,
  isMachOFormat,
}) {
  const {
    buildAnalysisArtifactContext,
    resolveLegacyArtifactFallback,
    ensureAnalysisMappingArtifacts,
    loadDisasmMapping,
    findDisasmMappingEntryByAddress,
    getMappingEntrySpanLength,
    openDisasmAtLine,
    resolveBinaryInputContext,
    loadBinaryHeaders,
    loadBinarySymbols,
    getArtifactPaths,
    loadOffsetToVaddr,
  } = analysisCtx;

  const resolveDisasmMappingContext = async ({
    binaryPath,
    binaryMeta = null,
    logPrefix = 'Mapping',
  }) => {
    const context = buildAnalysisArtifactContext(binaryPath, binaryMeta);
    const { tempDir, artifacts, baseName } = context;
    let { mappingPath, effectiveAbsPath } = context;
    ({ mappingPath, effectiveAbsPath } = resolveLegacyArtifactFallback({
      tempDir,
      mappingPath,
      effectiveAbsPath,
      logPrefix,
    }));
    if (!fs.existsSync(mappingPath) && effectiveAbsPath) {
      ({ mappingPath } = await ensureAnalysisMappingArtifacts({
        binaryPath: effectiveAbsPath,
        artifacts,
        mappingPath,
        useCacheDb: artifacts?.binaryMeta?.kind !== 'raw',
      }));
    }
    const mapping = loadDisasmMapping(mappingPath);
    const disasmPath = mapping.path || artifacts?.disasmPath || path.join(tempDir, `${baseName}.disasm.asm`);
    return {
      ...context,
      effectiveAbsPath,
      mappingPath,
      mapping,
      disasmPath,
    };
  };

  const revealDisasmAddress = async ({
    binaryPath,
    binaryMeta = null,
    addr,
    logPrefix = 'GoToAddress',
    syncHex = true,
    spanLength = null,
  }) => {
    const normalized = normalizeAddress(addr);
    if (!normalized) {
      throw new Error('Adresse invalide.');
    }
    const { mapping, disasmPath } = await resolveDisasmMappingContext({
      binaryPath,
      binaryMeta,
      logPrefix,
    });
    const entry = findDisasmMappingEntryByAddress(mapping.lines, normalized.norm);
    if (!entry || typeof entry.line !== 'number') {
      throw new Error(`Adresse ${normalized.norm} introuvable dans le désassemblage.`);
    }
    if (syncHex) {
      panel.webview.postMessage({
        type: 'hubSyncHexToAddr',
        addr: normalized.norm,
        spanLength: Number.isFinite(Number(spanLength)) && Number(spanLength) > 0
          ? Number(spanLength)
          : getMappingEntrySpanLength(entry),
      });
    }
    await openDisasmAtLine(disasmPath, entry.line);
    return { entry, mapping, addr: normalized.norm };
  };

  return {
    resolveDisasmMappingContext,
    hubGoToEntryPoint: async (message) => {
      const {
        absPath,
        exists,
        isDirectory,
      } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      const symbolName = message.symbol || 'main';
      let addrVal = null;
      if (!exists || isDirectory) {
        vscode.window.showErrorMessage(`Binaire introuvable: ${absPath}`);
        return;
      }
      if (symbolName === '__entry__') {
        try {
          const info = await loadBinaryHeaders(absPath);
          const entry = (info.entry || '').trim();
          if (!entry) {
            vscode.window.showWarningMessage('Entry point non trouvé dans les headers.');
            return;
          }
          addrVal = parseInt(entry.replace(/^0x/, ''), 16);
        } catch (err) {
          vscode.window.showErrorMessage(`Entry point: ${err.message}`);
          return;
        }
      } else {
        try {
          const info = await loadBinaryHeaders(absPath).catch(() => ({}));
          const symbols = await loadBinarySymbols(absPath);
          const candidates = symbolLookupCandidates(symbolName, info);
          let sym = symbols.find(s => candidates.includes(String(s.name || '')));
          if (!sym && symbolName === '_start' && isMachOFormat(info)) {
            try {
              const entry = (info.entry || '').trim();
              if (entry) {
                addrVal = parseInt(entry.replace(/^0x/, ''), 16);
                sym = { addr: entry };
              }
            } catch (_) { /* fallback to warning */ }
          }
          if (!sym) {
            const hint = symbolName === '_start' && isMachOFormat(info)
              ? ' (sur Mach-O, utilisez plutôt « Aller à l\'entry point »)'
              : '';
            vscode.window.showWarningMessage(`Symbole ${symbolName} non trouvé.${hint}`);
            return;
          }
          if (!addrVal && sym.addr) addrVal = parseInt(sym.addr, 16);
          addrVal = parseInt(sym.addr, 16);
        } catch (err) {
          vscode.window.showErrorMessage(`Aller à ${symbolName}: ${err.message}`);
          return;
        }
      }
      try {
        await revealDisasmAddress({
          binaryPath: absPath,
          addr: `0x${addrVal.toString(16)}`,
          logPrefix: 'GoToSymbol',
        });
      } catch (err) {
        vscode.window.showErrorMessage(`Aller à ${symbolName}: ${err.message}`);
      }
      return;
    },

    hubGoToFileOffset: async (message) => {
      const fileOffsetStr = (message.fileOffset || '').trim();
      const {
        binaryPath,
        absPath,
        exists,
        isDirectory,
        binaryMeta,
      } = resolveBinaryInputContext(message.binaryPath, message.binaryMeta || null);
      if (!fileOffsetStr || !binaryPath) return;
      if (!exists || isDirectory) return;
      const artifacts = getArtifactPaths({ binaryPath: absPath, binaryMeta });
      const fileOffset = fileOffsetStr.toLowerCase().startsWith('0x') ? parseInt(fileOffsetStr, 16) : parseInt(fileOffsetStr, 10);
      if (isNaN(fileOffset)) return;
      if (artifacts?.binaryMeta?.kind === 'raw') {
        const baseAddr = parseIntLiteral(artifacts.binaryMeta.rawConfig?.baseAddr || '0');
        if (baseAddr == null) {
          vscode.window.showInformationMessage(`Impossible de convertir l'offset ${fileOffsetStr} pour ce blob brut.`);
          return;
        }
        const addr = `0x${(baseAddr + fileOffset).toString(16)}`;
        try {
          await revealDisasmAddress({
            binaryPath,
            binaryMeta: artifacts.binaryMeta,
            addr,
            logPrefix: 'GoToAddress',
            spanLength: message.spanLength,
          });
        } catch (_) {
          panel.webview.postMessage({
            type: 'hubSyncHexToAddr',
            addr,
            spanLength: Number.isFinite(Number(message.spanLength)) && Number(message.spanLength) > 0
              ? Number(message.spanLength)
              : 1,
          });
        }
      } else {
        try {
          const vaddr = (await loadOffsetToVaddr(absPath, fileOffset)).trim();
          if (vaddr) {
            try {
              await revealDisasmAddress({
                binaryPath,
                binaryMeta,
                addr: vaddr,
                logPrefix: 'GoToAddress',
                spanLength: message.spanLength,
              });
            } catch (_) {
              panel.webview.postMessage({
                type: 'hubSyncHexToAddr',
                addr: vaddr,
                spanLength: Number.isFinite(Number(message.spanLength)) && Number(message.spanLength) > 0
                  ? Number(message.spanLength)
                  : 1,
              });
            }
          } else {
            vscode.window.showInformationMessage(`Offset ${fileOffsetStr} : pas d'adresse virtuelle (section non chargée ou binaire non-ELF).`);
            return;
          }
        } catch (_) {
          vscode.window.showInformationMessage(`Impossible de convertir l'offset ${fileOffsetStr} en adresse virtuelle.`);
          return;
        }
      }
    },

    hubGoToAddress: async (message) => {
      const addr = (message.addr || '').trim();
      const binaryPath = (message.binaryPath || '').trim();
      if (!addr) return;
      try {
        await revealDisasmAddress({
          binaryPath,
          binaryMeta: message.binaryMeta || null,
          addr,
          logPrefix: 'GoToAddress',
          spanLength: message.spanLength,
        });
      } catch (_) {
        // Address is not in disassembly (data section) — sync hex view silently
        panel.webview.postMessage({
          type: 'hubSyncHexToAddr',
          addr,
          spanLength: Number.isFinite(Number(message.spanLength)) && Number(message.spanLength) > 0
            ? Number(message.spanLength)
            : 1,
        });
      }
      return;
    },
  };
}

module.exports = { createNavigation };
