/**
 * Classic-script controller for payload builder tab orchestration inside the hub.
 * Keeps hub.js as the compatibility shell and receives explicit dependencies.
 */
(function initHubPayloadBuilderController(global) {
  function initPayloadBuilderController(deps) {
    const {
      payloadBuilderInput,
      getBuilderLevel,
      setBuilderLevel,
      renderBuilderUi,
      normalizePayloadBuilderLevel,
      getDynamicPayloadTargetMode,
      getDynamicResolvedArch,
      getEndian,
      getBadchars,
      getExploitHelperApi,
      parsePayloadExpressionPreview,
      normalizeGeneratedPreview,
      dynamicPayloadTargetLabel,
      getDynamicEffectivePayloadTarget,
      updateArgvPayloadHint,
      invalidateDynamicPayloadPreview,
      setDynamicTraceStatus,
    } = deps || {};

    function readBuilderLevel() {
      return typeof getBuilderLevel === 'function' ? (getBuilderLevel() || 'beginner') : 'beginner';
    }

    function writeBuilderLevel(level) {
      if (typeof setBuilderLevel === 'function') {
        return setBuilderLevel(level);
      }
      return typeof normalizePayloadBuilderLevel === 'function'
        ? normalizePayloadBuilderLevel(level, 'beginner')
        : (level || 'beginner');
    }

    function getBuilderHint(level = readBuilderLevel()) {
      if (typeof normalizePayloadBuilderLevel === 'function'
        && normalizePayloadBuilderLevel(level) === 'advanced') {
        return 'Advanced : `b"A"*8`, `p32(0xdeadbeef)`, `flat([...])`, `cyclic(128)`.';
      }
      return 'Beginner : `A*8`, `AAAA`, `\\x41\\x42`.';
    }

    function getBuilderPayloadSnapshot() {
      return {
        mode: 'payload_builder',
        builderLevel: readBuilderLevel(),
        input: String(payloadBuilderInput?.value || ''),
        targetMode: typeof getDynamicPayloadTargetMode === 'function'
          ? getDynamicPayloadTargetMode()
          : 'auto',
        arch: typeof getDynamicResolvedArch === 'function'
          ? getDynamicResolvedArch()
          : 'amd64',
        endian: typeof getEndian === 'function' ? getEndian() : 'little',
        badchars: typeof getBadchars === 'function' ? getBadchars() : '',
      };
    }

    function buildBuilderInputConfig() {
      const helper = typeof getExploitHelperApi === 'function' ? getExploitHelperApi() : null;
      if (!helper?.buildPayload) throw new Error('Helper payload indisponible.');
      const payloadSource = String(payloadBuilderInput?.value || '').trim();
      const targetMode = typeof getDynamicPayloadTargetMode === 'function'
        ? getDynamicPayloadTargetMode()
        : 'auto';
      const resolved = typeof normalizeGeneratedPreview === 'function'
        ? normalizeGeneratedPreview(
          helper.buildPayload(payloadSource, readBuilderLevel(), {
            arch: typeof getDynamicResolvedArch === 'function' ? getDynamicResolvedArch() : 'amd64',
            endian: typeof getEndian === 'function' ? getEndian() : 'little',
            badchars: typeof getBadchars === 'function' ? getBadchars() : '',
            targetMode,
          }),
          {
            mode: 'payload_builder',
            targetMode,
            currentPayloadSource: payloadSource,
          }
        )
        : helper.buildPayload(payloadSource, readBuilderLevel(), {
          arch: typeof getDynamicResolvedArch === 'function' ? getDynamicResolvedArch() : 'amd64',
          endian: typeof getEndian === 'function' ? getEndian() : 'little',
          badchars: typeof getBadchars === 'function' ? getBadchars() : '',
          targetMode,
        });
      return {
        ...resolved,
        currentPayloadSource: payloadSource,
        payloadExpr: resolved.payloadExpr || '',
        sourceFields: {
          input: payloadSource,
          expression: payloadSource,
          builderLevel: readBuilderLevel(),
        },
      };
    }

    function refreshPayloadBuilderUi() {
      if (typeof renderBuilderUi === 'function') renderBuilderUi();
    }

    function handlePayloadBuilderInput() {
      if (typeof invalidateDynamicPayloadPreview === 'function') {
        invalidateDynamicPayloadPreview();
      }
      if (typeof updateArgvPayloadHint === 'function') {
        updateArgvPayloadHint();
      }
      const raw = String(payloadBuilderInput?.value || '').trim();
      if (!raw) {
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Prêt.');
        }
        return;
      }
      try {
        const helper = typeof getExploitHelperApi === 'function' ? getExploitHelperApi() : null;
        const parsed = helper?.buildPayload
          ? helper.buildPayload(raw, readBuilderLevel(), {
            arch: typeof getDynamicResolvedArch === 'function' ? getDynamicResolvedArch() : 'amd64',
            endian: typeof getEndian === 'function' ? getEndian() : 'little',
            badchars: typeof getBadchars === 'function' ? getBadchars() : '',
            targetMode: typeof getDynamicPayloadTargetMode === 'function'
              ? getDynamicPayloadTargetMode()
              : 'auto',
          })
          : {
            size: typeof parsePayloadExpressionPreview === 'function'
              ? parsePayloadExpressionPreview(raw).bytes
              : 0
          };
        if (typeof setDynamicTraceStatus === 'function') {
          const target = typeof getDynamicEffectivePayloadTarget === 'function'
            ? getDynamicEffectivePayloadTarget()
            : 'argv1';
          const label = typeof dynamicPayloadTargetLabel === 'function'
            ? dynamicPayloadTargetLabel(target)
            : target;
          setDynamicTraceStatus(`${label} prêt: ${parsed.size ?? parsed.bytes} byte(s).`);
        }
      } catch (_) {
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus('Expression payload invalide.');
        }
      }
    }

    payloadBuilderInput?.addEventListener('input', handlePayloadBuilderInput);

    return {
      buildBuilderInputConfig,
      getBuilderHint,
      getBuilderLevel: readBuilderLevel,
      getBuilderPayloadSnapshot,
      handlePayloadBuilderInput,
      refreshPayloadBuilderUi,
      setBuilderLevel: writeBuilderLevel,
    };
  }

  const api = { initPayloadBuilderController };
  global.POFHubPayloadBuilderController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.payloadBuilderController = api;
  }
})(window);
