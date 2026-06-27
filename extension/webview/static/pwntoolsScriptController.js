/**
 * Classic-script controller for pwntools script UI/orchestration inside the hub.
 * Keeps hub.js as the compatibility shell and receives explicit dependencies.
 */
(function initHubPwntoolsScriptController(global) {
  function initPwntoolsScriptController(deps) {
    const {
      postMessage,
      btnDynamicImportPwntoolsScript,
      btnAnalyzePwntoolsScript,
      payloadPwntoolsSourceLabel,
      payloadPwntoolsScriptInput,
      payloadPwntoolsScriptWarning,
      payloadPwntoolsCaptureList,
      getBinaryPath,
      setDynamicTraceStatus,
      setDynamicPayloadMode,
      updateArgvPayloadHint,
      invalidateDynamicPayloadPreview,
      refreshDynamicPayloadPreviewAfterSelection,
      normalizeCaptureHex,
      hexToByteArray,
      debugDynamicPayload,
      renderWarnings,
    } = deps || {};

    let dynamicPwntoolsScriptPath = '';
    let dynamicPwntoolsScriptName = '';
    let dynamicPwntoolsAnalysisResult = null;
    let dynamicPwntoolsSelectedCapture = null;

    function safePostMessage(message) {
      if (typeof postMessage === 'function') postMessage(message);
    }

    function getScriptPath() {
      return dynamicPwntoolsScriptPath;
    }

    function getScriptName() {
      return dynamicPwntoolsScriptName;
    }

    function getScriptContent() {
      return String(payloadPwntoolsScriptInput?.value || '');
    }

    function getAnalysisResult() {
      return dynamicPwntoolsAnalysisResult;
    }

    function getSelectedCapture() {
      return dynamicPwntoolsSelectedCapture;
    }

    function getSourceSnapshot() {
      return {
        sourceFileName: dynamicPwntoolsScriptName || '',
        scriptPath: dynamicPwntoolsScriptPath || '',
        scriptContent: getScriptContent(),
        selectedCapture: dynamicPwntoolsSelectedCapture || null,
      };
    }

    function getCaptureEntries(result = dynamicPwntoolsAnalysisResult) {
      if (!result || typeof result !== 'object') return [];
      const entries = [];
      const captured = Array.isArray(result.captures)
        ? result.captures
        : (Array.isArray(result.captured) ? result.captured : []);
      captured.forEach((entry, index) => {
        if (!entry || typeof entry !== 'object') return;
        const hex = typeof normalizeCaptureHex === 'function' ? normalizeCaptureHex(entry) : '';
        if (!hex) return;
        entries.push({
          id: String(entry.id || `capture-${index + 1}`),
          kind: String(entry.kind || entry.type || 'send').trim() || 'send',
          targetHint: String(entry.targetHint || 'stdin').trim() || 'stdin',
          size: Number(entry.size ?? (typeof hexToByteArray === 'function' ? hexToByteArray(hex).length : 0)) || 0,
          hex,
          hexPreview: String(entry.hexPreview || hex || '').trim(),
          asciiPreview: String(entry.asciiPreview || ''),
          processArgs: Array.isArray(entry.processArgs) ? entry.processArgs.map(String) : [],
          delimiterPreview: String(entry.delimiterPreview || ''),
          remoteTarget: String(entry.remoteTarget || ''),
          sourceType: 'capture',
        });
      });
      const payloadGlobal = result.globals && typeof result.globals === 'object'
        ? result.globals.payload
        : null;
      if (payloadGlobal && typeof payloadGlobal === 'object') {
        entries.push({
          id: 'global-payload',
          kind: 'global_payload',
          targetHint: 'stdin',
          size: Number(payloadGlobal.size ?? (typeof hexToByteArray === 'function' ? hexToByteArray(payloadGlobal.hex).length : 0)) || 0,
          hex: String(payloadGlobal.hex || '').trim(),
          hexPreview: String(payloadGlobal.hexPreview || payloadGlobal.hex || '').trim(),
          asciiPreview: String(payloadGlobal.asciiPreview || ''),
          processArgs: [],
          delimiterPreview: '',
          remoteTarget: '',
          sourceType: 'global',
        });
      }
      return entries;
    }

    function renderCaptures(captures = null) {
      if (!payloadPwntoolsCaptureList) return;
      payloadPwntoolsCaptureList.replaceChildren();
      const entries = Array.isArray(captures) ? captures : getCaptureEntries();
      if (!entries.length) {
        const empty = document.createElement('p');
        empty.className = 'hint';
        empty.textContent = 'Aucun payload capturé.';
        payloadPwntoolsCaptureList.appendChild(empty);
        return;
      }

      entries.forEach((entry) => {
        const card = document.createElement('div');
        card.className = [
          'dynamic-pwntools-capture',
          dynamicPwntoolsSelectedCapture?.captureId === entry.id ? 'is-selected' : '',
        ].filter(Boolean).join(' ');

        const title = document.createElement('div');
        title.className = 'dynamic-pwntools-capture-title';
        title.textContent = entry.kind;
        card.appendChild(title);

        const meta = document.createElement('div');
        meta.className = 'dynamic-pwntools-capture-meta';
        const metaBits = [
          `${entry.size} byte${entry.size > 1 ? 's' : ''}`,
          entry.targetHint || 'stdin',
          entry.delimiterPreview ? `after "${entry.delimiterPreview}"` : '',
          entry.remoteTarget ? `remote ${entry.remoteTarget}` : '',
        ].filter(Boolean);
        meta.textContent = metaBits.join(' • ');
        card.appendChild(meta);

        const ascii = document.createElement('pre');
        ascii.className = 'dynamic-pwntools-capture-preview';
        ascii.textContent = entry.asciiPreview || '—';
        card.appendChild(ascii);

        const hex = document.createElement('pre');
        hex.className = 'dynamic-pwntools-capture-preview';
        hex.textContent = entry.hexPreview || entry.hex || '—';
        card.appendChild(hex);

        const actions = document.createElement('div');
        actions.className = 'dynamic-pwntools-capture-actions';

        const stdinBtn = document.createElement('button');
        stdinBtn.type = 'button';
        stdinBtn.className = 'btn btn-secondary btn-sm';
        stdinBtn.textContent = 'Utiliser comme stdin';
        stdinBtn.addEventListener('click', () => {
          selectCapture(entry, 'stdin');
        });
        actions.appendChild(stdinBtn);

        const argvBtn = document.createElement('button');
        argvBtn.type = 'button';
        argvBtn.className = 'btn btn-secondary btn-sm';
        argvBtn.textContent = 'Utiliser comme argv[1]';
        argvBtn.addEventListener('click', () => {
          selectCapture(entry, 'argv1');
        });
        actions.appendChild(argvBtn);

        card.appendChild(actions);
        payloadPwntoolsCaptureList.appendChild(card);
      });
    }

    function refreshPwntoolsScriptUi() {
      if (payloadPwntoolsSourceLabel) {
        payloadPwntoolsSourceLabel.textContent = dynamicPwntoolsScriptPath || dynamicPwntoolsScriptName || 'Aucun script importé.';
      }
      renderCaptures();
    }

    function selectCapture(capture, target) {
      const entries = getCaptureEntries();
      const entry = typeof capture === 'string'
        ? entries.find((item) => item.id === capture) || null
        : capture;
      if (!entry) return false;
      dynamicPwntoolsSelectedCapture = {
        captureId: entry.id,
        kind: entry.kind,
        target: target || entry.targetHint || 'stdin',
      };
      if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
      renderCaptures();
      if (typeof refreshDynamicPayloadPreviewAfterSelection === 'function') {
        refreshDynamicPayloadPreviewAfterSelection(
          dynamicPwntoolsSelectedCapture.target === 'argv1'
            ? 'pwntools-select-argv1'
            : 'pwntools-select-stdin'
        );
      }
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus(
          dynamicPwntoolsSelectedCapture.target === 'argv1'
            ? 'Capture pwntools sélectionnée pour argv[1].'
            : 'Capture pwntools sélectionnée pour stdin.'
        );
      }
      return true;
    }

    function markScriptStale() {
      dynamicPwntoolsAnalysisResult = null;
      dynamicPwntoolsSelectedCapture = null;
      if (payloadPwntoolsScriptWarning) {
        if (typeof renderWarnings === 'function') {
          renderWarnings(['Le script a changé, relance l’analyse.'], {
            container: payloadPwntoolsScriptWarning,
            emptyMessage: '',
          });
        } else {
          payloadPwntoolsScriptWarning.textContent = 'Le script a changé, relance l’analyse.';
        }
      }
      renderCaptures();
      if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
      if (typeof invalidateDynamicPayloadPreview === 'function') invalidateDynamicPayloadPreview();
    }

    function analyzeScript() {
      const scriptContent = getScriptContent();
      const sourceFileName = dynamicPwntoolsScriptName || 'payload.py';
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Analyse du script pwntools...');
      }
      safePostMessage({
        type: 'hubAnalyzePwntoolsScript',
        scriptContent,
        sourceFileName,
        scriptPath: dynamicPwntoolsScriptPath,
        binaryPath: typeof getBinaryPath === 'function' ? getBinaryPath() : '',
      });
    }

    function handlePwntoolsMessage(msg) {
      if (!msg || typeof msg !== 'object') return false;

      if (msg.type === 'hubPwntoolsScriptLoaded') {
        dynamicPwntoolsScriptPath = String(msg.path || '').trim();
        dynamicPwntoolsScriptName = String(msg.name || '').trim() || 'payload.py';
        dynamicPwntoolsAnalysisResult = null;
        dynamicPwntoolsSelectedCapture = null;
        if (payloadPwntoolsScriptInput) payloadPwntoolsScriptInput.value = String(msg.content || '');
        if (payloadPwntoolsScriptWarning) {
          if (typeof renderWarnings === 'function') {
            renderWarnings([], { container: payloadPwntoolsScriptWarning, emptyMessage: '' });
          } else {
            payloadPwntoolsScriptWarning.textContent = '';
          }
        }
        refreshPwntoolsScriptUi();
        if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
        if (typeof invalidateDynamicPayloadPreview === 'function') invalidateDynamicPayloadPreview();
        if (typeof setDynamicPayloadMode === 'function') setDynamicPayloadMode('pwntools_script');
        if (typeof setDynamicTraceStatus === 'function') setDynamicTraceStatus('Script pwntools importé.');
        return true;
      }

      if (msg.type === 'hubPwntoolsScriptAnalyzed') {
        dynamicPwntoolsAnalysisResult = msg.result && typeof msg.result === 'object' ? msg.result : null;
        const entries = getCaptureEntries(dynamicPwntoolsAnalysisResult);
        const firstEntry = entries[0] || null;
        dynamicPwntoolsSelectedCapture = firstEntry
          ? {
              captureId: firstEntry.id,
              kind: firstEntry.kind,
              target: firstEntry.targetHint || 'stdin',
            }
          : null;
        if (payloadPwntoolsScriptWarning) {
          const warnings = Array.isArray(dynamicPwntoolsAnalysisResult?.warnings)
            ? dynamicPwntoolsAnalysisResult.warnings
            : [];
          const error = String(dynamicPwntoolsAnalysisResult?.error || '').trim();
          if (typeof renderWarnings === 'function') {
            renderWarnings([error, ...warnings].filter(Boolean), {
              container: payloadPwntoolsScriptWarning,
              error: !!error,
              emptyMessage: '',
            });
          } else {
            payloadPwntoolsScriptWarning.textContent = [error, ...warnings].filter(Boolean).join(' • ');
          }
        }
        renderCaptures(entries);
        if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
        if (typeof setDynamicPayloadMode === 'function') setDynamicPayloadMode('pwntools_script');
        if (entries.length) {
          if (typeof refreshDynamicPayloadPreviewAfterSelection === 'function') {
            refreshDynamicPayloadPreviewAfterSelection('pwntools-analyzed-first-capture');
          }
        } else if (typeof invalidateDynamicPayloadPreview === 'function') {
          invalidateDynamicPayloadPreview();
        }
        if (typeof debugDynamicPayload === 'function') {
          debugDynamicPayload('pwntools-analyzed', {
            ok: dynamicPwntoolsAnalysisResult?.ok !== false,
            captures: entries.length,
            selectedCapture: dynamicPwntoolsSelectedCapture?.captureId || '',
            error: dynamicPwntoolsAnalysisResult?.error || '',
          });
        }
        if (typeof setDynamicTraceStatus === 'function') {
          setDynamicTraceStatus(entries.length ? 'Captures pwntools prêtes.' : 'Aucun payload capturé.');
        }
        return true;
      }

      return false;
    }

    btnDynamicImportPwntoolsScript?.addEventListener('click', () => {
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Sélection du script pwntools...');
      }
      safePostMessage({ type: 'hubLoadPwntoolsScript' });
    });

    btnAnalyzePwntoolsScript?.addEventListener('click', analyzeScript);

    payloadPwntoolsScriptInput?.addEventListener('input', markScriptStale);

    return {
      analyzeScript,
      getAnalysisResult,
      getCaptureEntries,
      getScriptContent,
      getScriptName,
      getScriptPath,
      getSelectedCapture,
      getSourceSnapshot,
      handlePwntoolsMessage,
      refreshPwntoolsScriptUi,
      renderCaptures,
      selectCapture,
    };
  }

  const api = { initPwntoolsScriptController };
  global.POFHubPwntoolsScriptController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.pwntoolsScriptController = api;
  }
})(window);
