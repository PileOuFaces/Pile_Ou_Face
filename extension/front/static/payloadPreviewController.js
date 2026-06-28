/**
 * Classic-script controller for payload preview orchestration in the hub.
 * Keeps payload generation logic outside this module and operates via deps.
 */
(function initHubPayloadPreviewController(global) {
  function initPayloadPreviewController(deps) {
    const {
      document,
      navigator,
      storageKey = 'pof-preview-open',
      dynamicPreviewCard,
      dynamicPreviewCardHeader,
      dynamicPreviewCardBody,
      dynamicPreviewToggleLabel,
      payloadPreviewStatus,
      payloadPreviewTarget,
      payloadPreviewSize,
      payloadPreviewHex,
      payloadPreviewAscii,
      payloadPreviewTruncated,
      payloadPreviewSnippetDetails,
      payloadPwntoolsSnippet,
      payloadPreviewWarnings,
      btnPayloadPreview,
      btnPayloadUseGenerated,
      btnPayloadCopyPwntools,
      payloadBuilderInput,
      getPayloadPreviewApi,
      getDynamicPayloadPreviewState,
      setDynamicPayloadPreviewState,
      buildDynamicPayloadSourceSnapshot,
      buildDynamicInputConfig,
      dynamicPayloadTargetLabel,
      getDynamicEffectivePayloadTarget,
      getDynamicInputTargetModeForPayload,
      getDynamicPayloadMode,
      setDynamicPayloadMode,
      setDynamicPayloadBuilderLevel,
      formatDynamicPayloadSize,
      updateArgvPayloadHint,
      setDynamicTraceStatus,
      debugDynamicPayload,
      renderWarnings,
    } = deps || {};

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

    function getPreviewApi() {
      return typeof getPayloadPreviewApi === 'function'
        ? getPayloadPreviewApi()
        : null;
    }

    function resolvePreviewTarget(targetMode = '') {
      const target = targetMode && targetMode !== 'auto'
        ? targetMode
        : (typeof getDynamicEffectivePayloadTarget === 'function'
          ? getDynamicEffectivePayloadTarget()
          : 'argv1');
      return typeof dynamicPayloadTargetLabel === 'function'
        ? dynamicPayloadTargetLabel(target)
        : String(target || 'argv[1]');
    }

    function buildPreviewFingerprint() {
      const previewApi = getPreviewApi();
      const snapshot = typeof buildDynamicPayloadSourceSnapshot === 'function'
        ? buildDynamicPayloadSourceSnapshot()
        : {};
      return previewApi?.buildPayloadPreviewFingerprint
        ? previewApi.buildPayloadPreviewFingerprint(snapshot)
        : JSON.stringify(snapshot);
    }

    function createPreviewState(status = 'stale', overrides = {}) {
      const previewApi = getPreviewApi();
      const target = resolvePreviewTarget();
      if (status === 'error') {
        return previewApi?.createErrorPreviewState
          ? previewApi.createErrorPreviewState(overrides.error || 'Erreur', { target, ...overrides })
          : { status: 'error', target, size: 0, previewHexDisplay: '—', previewAsciiDisplay: '—', warnings: [], ...overrides };
      }
      return previewApi?.createStalePreviewState
        ? previewApi.createStalePreviewState({ target, ...overrides })
        : { status: 'stale', target, size: 0, previewHexDisplay: '—', previewAsciiDisplay: '—', warnings: [], ...overrides };
    }

    function setPreviewOpen(open, persist = true) {
      if (!dynamicPreviewCard || !dynamicPreviewCardHeader) return;
      const nextOpen = !!open;
      dynamicPreviewCard.classList.toggle('is-open', nextOpen);
      dynamicPreviewCardHeader.setAttribute('aria-expanded', String(nextOpen));
      if (dynamicPreviewToggleLabel) {
        dynamicPreviewToggleLabel.textContent = nextOpen ? 'Masquer l’aperçu' : 'Afficher l’aperçu';
      }
      if (persist) {
        try { localStorage.setItem(storageKey, nextOpen ? 'true' : 'false'); } catch (_) {}
      }
    }

    function renderPreview(state) {
      const current = state || createPreviewState('stale');
      if (payloadPreviewStatus) {
        payloadPreviewStatus.textContent = current.status === 'ready'
          ? 'OK'
          : current.status === 'error'
            ? 'Erreur'
            : '⚠️ Obsolète';
        payloadPreviewStatus.dataset.state = current.status;
      }
      if (payloadPreviewTarget) payloadPreviewTarget.textContent = current.target || resolvePreviewTarget();
      if (payloadPreviewSize) {
        payloadPreviewSize.textContent = typeof formatDynamicPayloadSize === 'function'
          ? formatDynamicPayloadSize(current.size || 0)
          : `${Number(current.size || 0)} byte(s)`;
      }
      if (payloadPreviewHex) payloadPreviewHex.textContent = current.status === 'error' ? '—' : (current.previewHexDisplay || '—');
      if (payloadPreviewAscii) payloadPreviewAscii.textContent = current.status === 'error' ? '—' : (current.previewAsciiDisplay || '—');
      if (payloadPreviewTruncated) {
        payloadPreviewTruncated.textContent = current.previewTruncated ? 'Affichage tronqué aux 256 premiers octets.' : '';
      }
      if (payloadPwntoolsSnippet) {
        payloadPwntoolsSnippet.textContent = current.status === 'error' ? '' : (current.generatedPwntoolsSnippet || '');
      }
      if (payloadPreviewSnippetDetails && !current.generatedPwntoolsSnippet) payloadPreviewSnippetDetails.open = false;
      if (payloadPreviewWarnings) {
        const items = current.status === 'error'
          ? [String(current.error || 'Erreur inconnue')]
          : (Array.isArray(current.warnings) && current.warnings.length ? current.warnings : ['Aucun warning.']);
        if (typeof renderWarnings === 'function') {
          renderWarnings(items, {
            container: payloadPreviewWarnings,
            error: current.status === 'error',
            emptyMessage: 'Aucun warning.',
          });
        } else {
          payloadPreviewWarnings.replaceChildren();
          payloadPreviewWarnings.classList.toggle('error', current.status === 'error');
          payloadPreviewWarnings.classList.toggle(
            'warning',
            current.status !== 'error' && Array.isArray(current.warnings) && current.warnings.length > 0
          );
          items.forEach((message) => {
            const line = document.createElement('li');
            line.textContent = String(message);
            payloadPreviewWarnings.appendChild(line);
          });
        }
      }
    }

    function markPreviewStale() {
      const nextState = writePreviewState(createPreviewState('stale', {
        fingerprint: buildPreviewFingerprint(),
      }));
      renderPreview(nextState);
      return nextState;
    }

    function buildResolvedPreviewState(inputConfig, fingerprint) {
      const previewApi = getPreviewApi();
      const previewState = previewApi?.buildResolvedPreviewState
        ? previewApi.buildResolvedPreviewState(
          {
            mode: inputConfig.mode,
            target: resolvePreviewTarget(
              inputConfig.targetMode && inputConfig.targetMode !== 'auto'
                ? inputConfig.targetMode
                : ''
            ),
            currentPayloadSource: inputConfig.currentPayloadSource || '',
            resolvedPayloadBytes: inputConfig.resolvedPayloadBytes || [],
            generatedPwntoolsSnippet: inputConfig.generatedPwntoolsSnippet || inputConfig.generatedSnippet || '',
            size: inputConfig.size || 0,
            warnings: inputConfig.warnings || [],
            payloadExpr: inputConfig.payloadExpr || '',
            inputConfig,
          },
          { fingerprint }
        )
        : {
          status: 'ready',
          fingerprint,
          mode: inputConfig.mode,
          target: resolvePreviewTarget(),
          currentPayloadSource: inputConfig.currentPayloadSource || '',
          resolvedPayloadBytes: inputConfig.resolvedPayloadBytes || [],
          generatedPwntoolsSnippet: inputConfig.generatedPwntoolsSnippet || inputConfig.generatedSnippet || '',
          size: inputConfig.size || 0,
          warnings: inputConfig.warnings || [],
          payloadExpr: inputConfig.payloadExpr || '',
          inputConfig,
        };
      if ((!previewState.previewAsciiDisplay || previewState.previewAsciiDisplay === '—') && inputConfig.previewAscii) {
        previewState.previewAsciiDisplay = String(inputConfig.previewAscii);
      }
      if ((!previewState.previewHexDisplay || previewState.previewHexDisplay === '—') && inputConfig.previewHex) {
        previewState.previewHexDisplay = String(inputConfig.previewHex);
      }
      return previewState;
    }

    function refreshPreview({ reason = 'manual' } = {}) {
      const fingerprint = buildPreviewFingerprint();
      const inputConfig = typeof buildDynamicInputConfig === 'function'
        ? buildDynamicInputConfig()
        : null;
      const previewState = buildResolvedPreviewState(inputConfig, fingerprint);
      writePreviewState(previewState);
      renderPreview(previewState);
      if (typeof debugDynamicPayload === 'function') {
        debugDynamicPayload('preview', {
          reason,
          mode: inputConfig?.mode,
          targetMode: inputConfig?.targetMode || (
            typeof getDynamicInputTargetModeForPayload === 'function'
              ? getDynamicInputTargetModeForPayload()
              : ''
          ),
          size: previewState.size || inputConfig?.size || 0,
          previewHex: inputConfig?.previewHex || inputConfig?.payloadBytesHex || '',
          previewAscii: previewState.previewAsciiDisplay || inputConfig?.previewAscii || '',
          warnings: inputConfig?.warnings || [],
        });
      }
      return previewState;
    }

    function ensurePreview() {
      const previewApi = getPreviewApi();
      const previewState = readPreviewState();
      const fingerprint = buildPreviewFingerprint();
      const isFresh = previewApi?.isPreviewStateFresh
        ? previewApi.isPreviewStateFresh(previewState, fingerprint)
        : !!previewState && previewState.status === 'ready' && previewState.fingerprint === fingerprint;
      if (isFresh) return previewState;
      return refreshPreview();
    }

    function refreshPreviewAfterSelection(reason = 'selection') {
      try {
        return refreshPreview({ reason });
      } catch (err) {
        const nextState = writePreviewState(createPreviewState('error', {
          fingerprint: buildPreviewFingerprint(),
          error: err.message || String(err),
        }));
        renderPreview(nextState);
        if (typeof debugDynamicPayload === 'function') {
          debugDynamicPayload('preview-error', {
            reason,
            mode: typeof getDynamicPayloadMode === 'function' ? getDynamicPayloadMode() : '',
            error: err.message || String(err),
          });
        }
        return null;
      }
    }

    function useCurrentPreviewAsPayload() {
      try {
        const preview = ensurePreview();
        const input = preview?.inputConfig || null;
        if (input?.mode === 'file') {
          if (typeof debugDynamicPayload === 'function') {
            debugDynamicPayload('use-payload', { mode: input.mode, targetMode: input.targetMode, size: input.size || 0 });
          }
          if (typeof setDynamicTraceStatus === 'function') setDynamicTraceStatus('Fichier payload prêt pour argv[1].');
          return;
        }
        if (input?.mode === 'payload_builder') {
          if (typeof debugDynamicPayload === 'function') {
            debugDynamicPayload('use-payload', {
              mode: input.mode,
              targetMode: input.targetMode,
              size: input.size || 0,
              previewHex: input.previewHex || input.payloadBytesHex || '',
            });
          }
          if (typeof setDynamicTraceStatus === 'function') setDynamicTraceStatus('Payload Builder déjà prêt.');
          return;
        }
        if (input?.mode === 'pwntools_script') {
          if (typeof debugDynamicPayload === 'function') {
            debugDynamicPayload('use-payload', {
              mode: input.mode,
              captureId: input.sourceFields?.captureId || '',
              targetMode: input.targetMode,
              size: input.size || 0,
              previewHex: input.previewHex || input.payloadBytesHex || '',
            });
          }
          if (typeof setDynamicTraceStatus === 'function') {
            setDynamicTraceStatus(`Capture pwntools prête pour ${input?.targetMode === 'argv1' ? 'argv[1]' : 'stdin'}.`);
          }
          return;
        }
        if (typeof setDynamicPayloadMode === 'function') setDynamicPayloadMode('payload_builder');
        if (typeof setDynamicPayloadBuilderLevel === 'function') setDynamicPayloadBuilderLevel('beginner');
        if (payloadBuilderInput) payloadBuilderInput.value = input?.payloadExpr || '';
        if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
        markPreviewStale();
        refreshPreview({ reason: 'use-generated-applied' });
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Payload généré appliqué dans le builder.');
        }
      } catch (err) {
        const nextState = writePreviewState(createPreviewState('error', {
          fingerprint: buildPreviewFingerprint(),
          error: err.message || String(err),
        }));
        renderPreview(nextState);
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Payload généré invalide.');
        }
      }
    }

    function copyCurrentPwntools() {
      let snippet = '';
      try {
        const preview = ensurePreview();
        snippet = preview?.generatedPwntoolsSnippet || '';
      } catch (err) {
        const nextState = writePreviewState(createPreviewState('error', {
          fingerprint: buildPreviewFingerprint(),
          error: err.message || String(err),
        }));
        renderPreview(nextState);
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Snippet pwntools invalide.');
        }
        return;
      }
      if (snippet && navigator?.clipboard) navigator.clipboard.writeText(snippet);
    }

    function handlePreviewAction() {
      try {
        const preview = refreshPreview({ reason: 'preview-button' });
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus(preview?.warnings?.length ? 'Preview prête avec warning.' : 'Preview prête.');
        }
        setPreviewOpen(true);
      } catch (err) {
        const nextState = writePreviewState(createPreviewState('error', {
          fingerprint: buildPreviewFingerprint(),
          error: err.message || String(err),
        }));
        renderPreview(nextState);
        if (typeof debugDynamicPayload === 'function') {
          debugDynamicPayload('preview-error', {
            reason: 'preview-button',
            mode: typeof getDynamicPayloadMode === 'function' ? getDynamicPayloadMode() : '',
            error: err.message || String(err),
          });
        }
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Preview payload invalide.');
        }
      }
    }

    function handlePreviewMessage(_msg) {
      return false;
    }

    btnPayloadPreview?.addEventListener('click', handlePreviewAction);
    btnPayloadUseGenerated?.addEventListener('click', useCurrentPreviewAsPayload);
    btnPayloadCopyPwntools?.addEventListener('click', copyCurrentPwntools);

    (function initPreviewCardCollapse() {
      if (!dynamicPreviewCardHeader || !dynamicPreviewCardBody || !dynamicPreviewCard) return;
      const open = localStorage.getItem(storageKey) === 'true';
      setPreviewOpen(open, false);
      dynamicPreviewCardHeader.addEventListener('click', function onClick() {
        const nowOpen = !dynamicPreviewCard.classList.contains('is-open');
        setPreviewOpen(nowOpen);
      });
      dynamicPreviewCardHeader.addEventListener('keydown', function onKeydown(event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          dynamicPreviewCardHeader.click();
        }
      });
    })();

    return {
      buildPreviewFingerprint,
      copyCurrentPwntools,
      createPreviewState,
      ensurePreview,
      handlePreviewMessage,
      markPreviewStale,
      refreshPreview,
      refreshPreviewAfterSelection,
      renderPreview,
      setPreviewOpen,
      useCurrentPreviewAsPayload,
    };
  }

  const api = { initPayloadPreviewController };
  global.POFHubPayloadPreviewController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.payloadPreviewController = api;
  }
})(window);
