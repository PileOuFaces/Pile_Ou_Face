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
    findMappingEntryByAddr,
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
      throw new Error('Invalid address.');
    }
    const { mapping, mappingPath, disasmPath } = await resolveDisasmMappingContext({
      binaryPath,
      binaryMeta,
      logPrefix,
    });
    // Mapping allégé : requête SQLite par adresse ; artefact legacy (avant
    // migration) : recherche dans le tableau lines encore présent.
    const entry = Array.isArray(mapping?.lines) && mapping.lines.length
      ? findDisasmMappingEntryByAddress(mapping.lines, normalized.norm)
      : await findMappingEntryByAddr(mappingPath, normalized.norm);
    if (!entry || typeof entry.line !== 'number') {
      throw new Error(`Address ${normalized.norm} was not found in the disassembly.`);
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
        vscode.window.showErrorMessage(`Binary not found: ${absPath}`);
        return;
      }
      if (symbolName === '__entry__') {
        try {
          const info = await loadBinaryHeaders(absPath);
          const entry = (info.entry || '').trim();
          if (!entry) {
            vscode.window.showWarningMessage('Entry point not found in the headers.');
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
              ? ' (on Mach-O, use "Go to entry point" instead)'
              : '';
            vscode.window.showWarningMessage(`Symbol ${symbolName} not found.${hint}`);
            return;
          }
          if (!addrVal && sym.addr) addrVal = parseInt(sym.addr, 16);
          addrVal = parseInt(sym.addr, 16);
        } catch (err) {
          vscode.window.showErrorMessage(`Go to ${symbolName}: ${err.message}`);
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
        vscode.window.showErrorMessage(`Go to ${symbolName}: ${err.message}`);
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
          vscode.window.showInformationMessage(`Unable to convert offset ${fileOffsetStr} for this raw blob.`);
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
            vscode.window.showInformationMessage(`Offset ${fileOffsetStr}: no virtual address (unloaded section or non-ELF binary).`);
            return;
          }
        } catch (_) {
          vscode.window.showInformationMessage(`Unable to convert offset ${fileOffsetStr} to a virtual address.`);
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
