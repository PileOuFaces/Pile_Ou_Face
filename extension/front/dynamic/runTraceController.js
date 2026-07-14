/**
 * Classic-script controller for Run Trace orchestration inside the hub.
 * Keeps hub.js as the compatibility shell and receives explicit dependencies.
 */
(function initHubRunTraceController(global) {
  function createDefaultInitState() {
    return {
      archBits: 64,
      pie: false,
      sourcePath: '',
      sourceEnrichmentEnabled: false,
      sourceEnrichmentStatus: '',
      sourceEnrichmentMessage: '',
      payloadTargetMode: 'auto',
      payloadTargetAuto: 'argv1',
      payloadTargetEffective: 'argv1',
      payloadTargetReason: 'Auto: aucune source claire, fallback sur argv[1]',
      profile: {
        bufferOffset: '',
        bufferSize: '',
        maxSteps: 800,
        startSymbol: 'main',
        stopSymbol: ''
      }
    };
  }

  function initRunTraceController(deps) {
    const {
      document,
      postMessage,
      form,
      runBtn,
      binaryPathInput,
      dynamicArchBits,
      dynamicPie,
      dynamicSourcePathInput,
      dynamicSourceHint,
      dynamicPayloadTargetMode,
      payloadBuilderInput,
      btnDynamicSelectBinary,
      btnDynamicSelectSource,
      getDynamicTraceInitState,
      setDynamicTraceInitState,
      getDynamicPayloadPreviewState,
      setDynamicPayloadPreviewState,
      normalizeDynamicPayloadTargetMode,
      normalizeDynamicEffectiveTarget,
      dynamicPayloadTargetLabel,
      getDynamicPayloadTargetMode,
      getDynamicPayloadMode,
      getDynamicEffectivePayloadTarget,
      buildDynamicSourceHintText,
      setDynamicTraceStatus,
      setTraceField,
      updateArgvPayloadHint,
      invalidateDynamicPayloadPreview,
      refreshDynamicTraceHistory,
      requestSymbols,
      ensureDynamicPayloadPreview,
      getDynamicPreviewFingerprint,
      createDynamicPreviewState,
      renderDynamicPayloadPreview,
      debugDynamicPayload,
    } = deps || {};

    let fallbackInitState = createDefaultInitState();

    function readInitState() {
      return typeof getDynamicTraceInitState === 'function'
        ? (getDynamicTraceInitState() || fallbackInitState)
        : fallbackInitState;
    }

    function writeInitState(nextState) {
      fallbackInitState = nextState || fallbackInitState;
      if (typeof setDynamicTraceInitState === 'function') {
        setDynamicTraceInitState(fallbackInitState);
      }
      return fallbackInitState;
    }

    function readPreviewState() {
      return typeof getDynamicPayloadPreviewState === 'function'
        ? getDynamicPayloadPreviewState()
        : null;
    }

    function writePreviewState(nextState) {
      if (typeof setDynamicPayloadPreviewState === 'function') {
        setDynamicPayloadPreviewState(nextState);
      }
      return nextState;
    }

    function getBinaryPath() {
      return String(binaryPathInput?.value || '').trim();
    }

    function resolvePayloadTargetMode() {
      return typeof getDynamicPayloadTargetMode === 'function'
        ? getDynamicPayloadTargetMode()
        : 'auto';
    }

    function getSourcePath() {
      const state = readInitState();
      return String(dynamicSourcePathInput?.value || state.sourcePath || '').trim();
    }

    function safePostMessage(message) {
      if (typeof postMessage === 'function') postMessage(message);
    }

    function normalizeBinaryPathForCompare(value) {
      return String(value || '').trim().replace(/\\/g, '/');
    }

    function isStaleDynamicBinaryResponse(msg, scope) {
      const responseBinaryPath = String(msg?.binaryPath || '').trim();
      const currentBinaryPath = getBinaryPath();
      if (
        !responseBinaryPath
        || !currentBinaryPath
        || normalizeBinaryPathForCompare(responseBinaryPath) === normalizeBinaryPathForCompare(currentBinaryPath)
      ) {
        return false;
      }
      safePostMessage({
        type: 'hubDebugLog',
        scope,
        event: 'ignored-stale-response',
        details: { currentBinaryPath, responseBinaryPath },
      });
      return true;
    }

    function requestRunTraceInit(preset = null, forcedBinaryPath = '') {
      safePostMessage({
        type: 'requestRunTraceInit',
        binaryPath: forcedBinaryPath || getBinaryPath(),
        sourcePath: getSourcePath(),
        payloadTargetMode: resolvePayloadTargetMode(),
        preset
      });
    }

    function applyRunTraceInit(msg) {
      if (isStaleDynamicBinaryResponse(msg, 'dynamic-init')) return;
      const previousArgvPayload = payloadBuilderInput?.value ?? '';
      const previousPayloadTargetMode = typeof getDynamicPayloadTargetMode === 'function'
        ? getDynamicPayloadTargetMode()
        : 'auto';
      const nextPayloadTargetMode = typeof normalizeDynamicPayloadTargetMode === 'function'
        ? normalizeDynamicPayloadTargetMode(msg.payloadTargetMode || previousPayloadTargetMode)
        : (msg.payloadTargetMode || previousPayloadTargetMode || 'auto');
      const nextState = {
        archBits: Number(msg.archBits) === 32 ? 32 : 64,
        pie: msg.pie === true,
        sourcePath: String(msg.sourcePath || '').trim(),
        sourceEnrichmentEnabled: msg.sourceEnrichmentEnabled === true,
        sourceEnrichmentStatus: String(msg.sourceEnrichmentStatus || '').trim(),
        sourceEnrichmentMessage: String(msg.sourceEnrichmentMessage || '').trim(),
        payloadTargetMode: nextPayloadTargetMode,
        payloadTargetAuto: typeof normalizeDynamicEffectiveTarget === 'function'
          ? normalizeDynamicEffectiveTarget(msg.payloadTargetAuto || 'argv1')
          : String(msg.payloadTargetAuto || 'argv1'),
        payloadTargetEffective: typeof normalizeDynamicEffectiveTarget === 'function'
          ? normalizeDynamicEffectiveTarget(msg.payloadTargetEffective || msg.payloadTargetAuto || 'argv1')
          : String(msg.payloadTargetEffective || msg.payloadTargetAuto || 'argv1'),
        payloadTargetReason: String(msg.payloadTargetReason || '').trim() || 'Auto: aucune source claire, fallback sur argv[1]',
        profile: {
          bufferOffset: msg?.mvpProfile?.bufferOffset ?? '',
          bufferSize: msg?.mvpProfile?.bufferSize ?? '',
          maxSteps: msg?.mvpProfile?.maxSteps ?? 800,
          startSymbol: msg?.mvpProfile?.startSymbol || msg?.symbols?.startDefault || 'main',
          stopSymbol: msg?.mvpProfile?.stopSymbol || msg?.symbols?.stopDefault || ''
        }
      };

      const profile = msg.mvpProfile || {};
      writeInitState(nextState);
      if (typeof setTraceField === 'function') {
        setTraceField('binaryPath', msg.binaryPath || '');
        setTraceField('sourcePath', nextState.sourcePath || '');
        setTraceField(
          'argvPayload',
          typeof profile.argvPayload === 'string' ? profile.argvPayload : previousArgvPayload
        );
      }
      if (dynamicPayloadTargetMode) dynamicPayloadTargetMode.value = nextPayloadTargetMode;
      if (dynamicArchBits) dynamicArchBits.textContent = `${nextState.archBits}-bit`;
      if (dynamicPie) dynamicPie.textContent = nextState.pie ? 'Yes' : 'No';
      if (dynamicSourceHint && typeof buildDynamicSourceHintText === 'function') {
        dynamicSourceHint.textContent = buildDynamicSourceHintText(nextState);
      }
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus(msg.binaryPath ? 'Prêt.' : 'Sélectionnez un binaire pour lancer la trace.');
      }
      if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
      if (typeof invalidateDynamicPayloadPreview === 'function') invalidateDynamicPayloadPreview();
      if (typeof refreshDynamicTraceHistory === 'function') refreshDynamicTraceHistory();
    }

    function buildRunTraceConfig(binaryPath, inputConfig) {
      const state = readInitState();
      const payloadExpr = inputConfig?.mode === 'file'
        ? ''
        : (inputConfig?.payloadExpr || payloadBuilderInput?.value?.trim() || '');
      return {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath,
        sourcePath: getSourcePath(),
        archBits: state.archBits,
        pie: state.pie,
        bufferOffset: String(state.profile?.bufferOffset ?? ''),
        bufferSize: String(state.profile?.bufferSize ?? ''),
        maxSteps: String(state.profile?.maxSteps ?? 800),
        startSymbol: String(state.profile?.startSymbol || ''),
        stopSymbol: String(state.profile?.stopSymbol || ''),
        injectPayload: inputConfig?.mode === 'file' ? false : !!(payloadExpr || inputConfig?.payloadBytesHex),
        payloadExpr,
        payloadTargetMode: inputConfig?.targetMode || resolvePayloadTargetMode(),
        payloadTarget: inputConfig?.targetMode || resolvePayloadTargetMode(),
        input: inputConfig ? {
          mode: inputConfig.mode,
          template: inputConfig.template || inputConfig.sourceFields?.template || '',
          targetMode: inputConfig.targetMode || resolvePayloadTargetMode(),
          builderLevel: inputConfig.sourceFields?.builderLevel || '',
          payloadBytesHex: inputConfig.payloadBytesHex || '',
          sourceFields: inputConfig.sourceFields || {},
          generatedSnippet: inputConfig.generatedSnippet || '',
          size: inputConfig.size || 0,
          previewHex: inputConfig.previewHex || '',
          previewAscii: inputConfig.previewAscii || '',
          warnings: inputConfig.warnings || [],
        } : undefined,
        file: inputConfig?.file || undefined,
      };
    }

    function handleSubmit(event) {
      event?.preventDefault?.();
      const binaryPath = getBinaryPath();
      if (!binaryPath) {
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Chemin binaire requis.');
        }
        return;
      }

      let inputConfig = null;
      try {
        const preview = typeof ensureDynamicPayloadPreview === 'function'
          ? ensureDynamicPayloadPreview()
          : null;
        inputConfig = preview?.inputConfig || null;
      } catch (err) {
        if (typeof createDynamicPreviewState === 'function') {
          const nextPreviewState = writePreviewState(createDynamicPreviewState('error', {
            fingerprint: typeof getDynamicPreviewFingerprint === 'function'
              ? getDynamicPreviewFingerprint()
              : '',
            error: err.message || String(err),
          }));
          if (typeof renderDynamicPayloadPreview === 'function') {
            renderDynamicPayloadPreview(nextPreviewState);
          }
        }
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Payload invalide.');
        }
        return;
      }

      if (inputConfig?.warnings?.some((warning) => /requis|required|cannot carry NUL/i.test(warning))) {
        if (typeof renderDynamicPayloadPreview === 'function') {
          renderDynamicPayloadPreview(readPreviewState());
        }
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Payload avec warning bloquant.');
        }
        return;
      }

      if (runBtn) runBtn.disabled = true;
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Trace en cours...');
      }

      const config = buildRunTraceConfig(binaryPath, inputConfig);
      if (typeof debugDynamicPayload === 'function') {
        debugDynamicPayload('run-trace-submit', {
          mode: inputConfig?.mode || (typeof getDynamicPayloadMode === 'function' ? getDynamicPayloadMode() : ''),
          targetMode: inputConfig?.targetMode || resolvePayloadTargetMode(),
          size: inputConfig?.size || 0,
          payloadBytesHex: inputConfig?.payloadBytesHex || '',
          payloadExpr: config.payloadExpr,
        });
      }

      safePostMessage({
        type: 'runTrace',
        config
      });
    }

    function handleDynamicSourceInput() {
      const current = readInitState();
      const sourcePath = String(dynamicSourcePathInput?.value || '').trim();
      const nextState = {
        ...current,
        sourcePath,
      };
      if (!sourcePath) {
        nextState.sourceEnrichmentEnabled = false;
        nextState.sourceEnrichmentStatus = '';
        nextState.sourceEnrichmentMessage = '';
      } else if (nextState.sourceEnrichmentEnabled !== true) {
        nextState.sourceEnrichmentStatus = 'pending';
        nextState.sourceEnrichmentMessage = '';
      }
      writeInitState(nextState);
      if (dynamicSourceHint && typeof buildDynamicSourceHintText === 'function') {
        dynamicSourceHint.textContent = buildDynamicSourceHintText(nextState);
      }
      if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
    }

    function handlePickedFile(msg) {
      if (!msg || msg.type !== 'hubPickedFile') return false;
      if (msg.target !== 'dynamicSourcePath') return false;
      const input = document?.getElementById ? document.getElementById(msg.target) : null;
      if (input) input.value = msg.path;
      if (msg.target === 'dynamicSourcePath') {
        const current = readInitState();
        const nextState = {
          ...current,
          sourcePath: String(msg.path || '').trim(),
          sourceEnrichmentEnabled: false,
          sourceEnrichmentStatus: 'pending',
          sourceEnrichmentMessage: '',
        };
        writeInitState(nextState);
        if (dynamicSourceHint && typeof buildDynamicSourceHintText === 'function') {
          dynamicSourceHint.textContent = buildDynamicSourceHintText(nextState);
        }
        if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
        requestRunTraceInit(null, getBinaryPath());
        return true;
      }
      return false;
    }

    function handleMessage(msg) {
      if (!msg || typeof msg !== 'object') return false;
      if (msg.type === 'initRunTrace') {
        applyRunTraceInit(msg);
        return true;
      }
      if (msg.type === 'runTraceDone') {
        if (runBtn) runBtn.disabled = false;
        if (isStaleDynamicBinaryResponse(msg, 'dynamic-run-trace-done')) {
          return true;
        }
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Trace terminée.');
        }
        if (typeof refreshDynamicTraceHistory === 'function') refreshDynamicTraceHistory();
        return true;
      }
      return handlePickedFile(msg);
    }

    form?.addEventListener('submit', handleSubmit);
    btnDynamicSelectBinary?.addEventListener('click', () => {
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Sélection du fichier de travail...');
      }
      safePostMessage({ type: 'requestBinarySelection' });
    });
    btnDynamicSelectSource?.addEventListener('click', () => {
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Sélection du fichier C...');
      }
      safePostMessage({ type: 'hubPickFile', target: 'dynamicSourcePath', fileType: 'sourceC' });
    });
    dynamicSourcePathInput?.addEventListener('input', handleDynamicSourceInput);
    dynamicSourcePathInput?.addEventListener('blur', () => {
      requestRunTraceInit(null, getBinaryPath());
    });
    binaryPathInput?.addEventListener('blur', () => {
      const binaryPath = getBinaryPath();
      if (!binaryPath) return;
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Actualisation du profil binaire...');
      }
      requestRunTraceInit(null, binaryPath);
      if (typeof requestSymbols === 'function') requestSymbols();
    });
    dynamicPayloadTargetMode?.addEventListener('change', () => {
      const current = readInitState();
      writeInitState({
        ...current,
        payloadTargetMode: resolvePayloadTargetMode() || current.payloadTargetMode || 'auto',
      });
      if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
      if (typeof invalidateDynamicPayloadPreview === 'function') invalidateDynamicPayloadPreview();
      requestRunTraceInit(null, getBinaryPath());
    });

    return {
      requestRunTraceInit,
      applyRunTraceInit,
      handleMessage,
    };
  }

  const api = { initRunTraceController };
  global.POFHubRunTraceController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.runTraceController = api;
  }
})(window);
