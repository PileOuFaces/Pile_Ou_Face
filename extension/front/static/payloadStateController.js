/**
 * Classic-script controller for shared payload state orchestration inside the hub.
 * Delegates tab-specific work to extracted controllers and keeps hub.js as shell.
 */
(function initHubPayloadStateController(global) {
  function initPayloadStateController(deps) {
    const {
      document,
      TextEncoder,
      normalizePayloadMode,
      normalizePayloadTargetMode,
      normalizeEffectiveTarget,
      payloadTargetLabel,
      payloadTabsController,
      dynamicPayloadTargetMode,
      getDynamicTraceInitState,
      markPreviewStale,
      renderPreview,
      createPreviewState,
      getPreviewFingerprint,
      payloadBuilderController,
      filePayloadController,
      exploitHelperController,
      pwntoolsScriptController,
      getDynamicResolvedArch,
      getPwntoolsCaptureEntries,
      hexHasNullByte,
      hexToByteArray,
    } = deps || {};

    function getPayloadMode() {
      const current = payloadTabsController?.getMode?.() || 'payload_builder';
      return typeof normalizePayloadMode === 'function'
        ? normalizePayloadMode(current)
        : current;
    }

    function setPayloadMode(mode) {
      const nextMode = typeof normalizePayloadMode === 'function'
        ? normalizePayloadMode(mode)
        : (mode || 'payload_builder');
      return payloadTabsController?.setMode?.(nextMode) || nextMode;
    }

    function getPayloadTargetMode() {
      const traceState = typeof getDynamicTraceInitState === 'function'
        ? (getDynamicTraceInitState() || {})
        : {};
      const raw = dynamicPayloadTargetMode?.value || traceState.payloadTargetMode || 'auto';
      return typeof normalizePayloadTargetMode === 'function'
        ? normalizePayloadTargetMode(raw)
        : raw;
    }

    function getEffectivePayloadTarget() {
      const mode = getPayloadTargetMode();
      if (mode !== 'auto') {
        return typeof normalizeEffectiveTarget === 'function'
          ? normalizeEffectiveTarget(mode)
          : mode;
      }
      const traceState = typeof getDynamicTraceInitState === 'function'
        ? (getDynamicTraceInitState() || {})
        : {};
      const fallback = traceState.payloadTargetAuto || traceState.payloadTargetEffective || 'argv1';
      return typeof normalizeEffectiveTarget === 'function'
        ? normalizeEffectiveTarget(fallback)
        : fallback;
    }

    function getPayloadTargetHint() {
      const mode = getPayloadTargetMode();
      if (mode !== 'auto') {
        const label = typeof payloadTargetLabel === 'function'
          ? payloadTargetLabel(mode)
          : String(mode || 'argv1');
        return `${label} force manuellement.`;
      }
      const traceState = typeof getDynamicTraceInitState === 'function'
        ? (getDynamicTraceInitState() || {})
        : {};
      return String(traceState.payloadTargetReason || 'Auto: aucune source claire, fallback sur argv[1]');
    }

    function getInputTargetModeForPayload() {
      if (getPayloadMode() === 'file') return 'argv1';
      return getPayloadTargetMode();
    }

    function getActivePayloadTarget() {
      const mode = getPayloadMode();
      if (mode === 'file') return 'argv1';
      if (mode === 'pwntools_script') {
        const selectedCapture = pwntoolsScriptController?.getSelectedCapture?.() || null;
        const entries = typeof getPwntoolsCaptureEntries === 'function'
          ? getPwntoolsCaptureEntries(pwntoolsScriptController?.getAnalysisResult?.())
          : [];
        const selected = entries.find((entry) => entry.id === selectedCapture?.captureId) || entries[0] || null;
        return selectedCapture?.target || selected?.targetHint || 'stdin';
      }
      return getEffectivePayloadTarget();
    }

    function getActivePayloadSnapshot() {
      const mode = getPayloadMode();
      if (mode === 'payload_builder') {
        const snapshot = payloadBuilderController?.getBuilderPayloadSnapshot?.() || {};
        return {
          mode,
          builderLevel: snapshot.builderLevel || payloadBuilderController?.getBuilderLevel?.() || 'beginner',
          input: snapshot.input || '',
          targetMode: snapshot.targetMode || getPayloadTargetMode(),
          arch: snapshot.arch || (typeof getDynamicResolvedArch === 'function' ? getDynamicResolvedArch() : 'amd64'),
          endian: snapshot.endian || exploitHelperController?.getEndian?.() || 'little',
          badchars: snapshot.badchars || exploitHelperController?.getBadchars?.() || '',
        };
      }
      if (mode === 'file') {
        const snapshot = filePayloadController?.getFilePayloadSnapshot?.() || {};
        return {
          mode,
          source: snapshot.source || 'inline',
          guestPath: snapshot.guestPath || '/tmp/pof-input.txt',
          hostPath: snapshot.hostPath || '',
          inlineContent: snapshot.inlineContent || '',
        };
      }
      if (mode === 'exploit_helper') {
        return {
          mode,
          ...(exploitHelperController?.collectExploitHelperFields?.() || {}),
        };
      }
      if (mode === 'pwntools_script') {
        const snapshot = pwntoolsScriptController?.getSourceSnapshot?.() || {};
        return {
          mode,
          sourceFileName: snapshot.sourceFileName || '',
          scriptPath: snapshot.scriptPath || '',
          scriptContent: snapshot.scriptContent || '',
          selectedCapture: snapshot.selectedCapture || null,
        };
      }
      return { mode };
    }

    function buildFileInputConfig() {
      const snapshot = filePayloadController?.getFilePayloadSnapshot?.() || {};
      const source = snapshot.source === 'path' ? 'path' : 'inline';
      const guestPath = String(snapshot.guestPath || '/tmp/pof-input.txt').trim() || '/tmp/pof-input.txt';
      const hostPath = String(snapshot.hostPath || '').trim();
      const inlineContent = snapshot.inlineContent || '';
      const warnings = [];
      const encoder = TextEncoder ? new TextEncoder() : null;
      const inlineBytes = source === 'inline' && encoder ? Array.from(encoder.encode(inlineContent)) : [];
      if (source === 'path' && !hostPath) warnings.push('Fichier local requis.');
      if (source === 'inline' && !inlineContent) warnings.push('Contenu de fichier vide.');
      const generatedSnippet = [
        'from pwn import *',
        `io = process([exe, ${JSON.stringify(guestPath)}])`,
      ].join('\n');
      return {
        mode: 'file',
        targetMode: 'argv1',
        payloadBytesHex: '',
        sourceFields: { source, guestPath, hostPath: source === 'path' ? hostPath : '', passAs: 'argv1' },
        generatedSnippet,
        generatedPwntoolsSnippet: generatedSnippet,
        currentPayloadSource: source === 'inline' ? inlineContent : hostPath,
        resolvedPayloadBytes: inlineBytes,
        size: inlineBytes.length,
        previewHex: '',
        previewAscii: source === 'inline' ? inlineContent.slice(0, 160) : hostPath,
        warnings,
        file: {
          source,
          guestPath,
          hostPath: source === 'path' ? hostPath : '',
          inlineContent: source === 'inline' ? inlineContent : '',
          passAs: 'argv1',
        },
      };
    }

    function buildPwntoolsInputConfig() {
      const result = pwntoolsScriptController?.getAnalysisResult?.();
      if (!result || typeof result !== 'object') {
        throw new Error('Analyse pwntools requise avant la preview.');
      }
      const entries = typeof getPwntoolsCaptureEntries === 'function'
        ? getPwntoolsCaptureEntries(result)
        : [];
      if (!entries.length) {
        throw new Error('Aucun payload capturé dans le script pwntools.');
      }
      const selectedCapture = pwntoolsScriptController?.getSelectedCapture?.() || null;
      const selected = entries.find((entry) => entry.id === selectedCapture?.captureId) || entries[0];
      const targetMode = selectedCapture?.target || selected.targetHint || 'stdin';
      const warnings = [
        ...(Array.isArray(result.warnings) ? result.warnings.map(String) : []),
      ];
      if (targetMode === 'argv1' && typeof hexHasNullByte === 'function' && hexHasNullByte(selected.hex)) {
        warnings.push('argv[1] ne peut pas transporter un octet NUL exact.');
      }
      return {
        mode: 'pwntools_script',
        targetMode,
        payloadBytesHex: selected.hex,
        sourceFields: {
          sourceFileName: pwntoolsScriptController?.getScriptName?.() || result.sourceFileName || '',
          captureId: selected.id,
          selectedCaptureKind: selected.kind,
          target: targetMode,
          processArgs: selected.processArgs,
        },
        generatedSnippet: pwntoolsScriptController?.getScriptContent?.() || '',
        generatedPwntoolsSnippet: pwntoolsScriptController?.getScriptContent?.() || '',
        currentPayloadSource: pwntoolsScriptController?.getScriptContent?.() || '',
        resolvedPayloadBytes: typeof hexToByteArray === 'function' ? hexToByteArray(selected.hex) : [],
        size: selected.size,
        previewHex: selected.hex,
        previewAscii: selected.asciiPreview || '',
        warnings,
        payloadExpr: '',
        sourceFileName: pwntoolsScriptController?.getScriptName?.() || result.sourceFileName || '',
        selectedCaptureKind: selected.kind,
        target: targetMode,
      };
    }

    function buildActiveInputConfig() {
      const mode = getPayloadMode();
      if (mode === 'payload_builder') {
        return payloadBuilderController?.buildBuilderInputConfig?.();
      }
      if (mode === 'file') {
        return buildFileInputConfig();
      }
      if (mode === 'exploit_helper') {
        return exploitHelperController?.getExploitHelperPayload?.();
      }
      if (mode === 'pwntools_script') {
        return buildPwntoolsInputConfig();
      }
      throw new Error('Mode payload non supporte pour la preview.');
    }

    function invalidatePayloadPreview(reason = 'generic') {
      if (typeof markPreviewStale === 'function') {
        return markPreviewStale(reason);
      }
      const nextState = typeof createPreviewState === 'function'
        ? createPreviewState('stale', {
          fingerprint: typeof getPreviewFingerprint === 'function'
            ? getPreviewFingerprint()
            : '',
        })
        : null;
      if (nextState && typeof renderPreview === 'function') renderPreview(nextState);
      return nextState;
    }

    function refreshPayloadStateUi() {
      payloadBuilderController?.refreshPayloadBuilderUi?.();
      filePayloadController?.refreshFilePayloadUi?.();
      exploitHelperController?.refreshExploitHelperUi?.();
      pwntoolsScriptController?.refreshPwntoolsScriptUi?.();
    }

    return {
      buildActiveInputConfig,
      getActivePayloadSnapshot,
      getActivePayloadTarget,
      getEffectivePayloadTarget,
      getInputTargetModeForPayload,
      getPayloadMode,
      getPayloadTargetHint,
      getPayloadTargetMode,
      invalidatePayloadPreview,
      normalizePayloadMode: (mode) => (typeof normalizePayloadMode === 'function'
        ? normalizePayloadMode(mode)
        : mode),
      refreshPayloadStateUi,
      setPayloadMode,
    };
  }

  const api = { initPayloadStateController };
  global.POFHubPayloadStateController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.payloadStateController = api;
  }
})(window);
