/**
 * Classic-script controller for file payload tab orchestration inside the hub.
 * Keeps hub.js as the compatibility shell and receives explicit dependencies.
 */
(function initHubFilePayloadController(global) {
  function initFilePayloadController(deps) {
    const {
      postMessage,
      payloadFileSource,
      payloadFileGuestPath,
      payloadFileHostPath,
      payloadFileContent,
      btnDynamicSelectPayloadFile,
      setDynamicPayloadMode,
      invalidateDynamicPayloadPreview,
      refreshFilePanels,
      setDynamicTraceStatus,
    } = deps || {};

    function safePostMessage(message) {
      if (typeof postMessage === 'function') postMessage(message);
    }

    function getFilePayloadSnapshot() {
      return {
        mode: 'file',
        source: payloadFileSource?.value === 'path' ? 'path' : 'inline',
        guestPath: String(payloadFileGuestPath?.value || '/tmp/pof-input.txt').trim() || '/tmp/pof-input.txt',
        hostPath: String(payloadFileHostPath?.value || '').trim(),
        inlineContent: String(payloadFileContent?.value || ''),
      };
    }

    function refreshFilePayloadUi() {
      if (typeof refreshFilePanels === 'function') refreshFilePanels();
    }

    function onFieldChange() {
      if (typeof invalidateDynamicPayloadPreview === 'function') {
        invalidateDynamicPayloadPreview();
      }
    }

    function handleFilePayloadMessage(msg) {
      if (!msg || typeof msg !== 'object') return false;
      if (msg.type !== 'hubPickedFile' || msg.target !== 'payloadFileHostPath') return false;
      if (payloadFileHostPath) payloadFileHostPath.value = msg.path;
      if (typeof setDynamicPayloadMode === 'function') setDynamicPayloadMode('file');
      refreshFilePayloadUi();
      if (typeof invalidateDynamicPayloadPreview === 'function') {
        invalidateDynamicPayloadPreview();
      }
      return true;
    }

    btnDynamicSelectPayloadFile?.addEventListener('click', () => {
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Sélection du fichier payload...');
      }
      safePostMessage({ type: 'hubPickFile', target: 'payloadFileHostPath' });
    });

    [payloadFileGuestPath, payloadFileHostPath, payloadFileContent].filter(Boolean).forEach((field) => {
      field.addEventListener('input', onFieldChange);
      field.addEventListener('change', onFieldChange);
    });

    return {
      getFilePayloadSnapshot,
      refreshFilePayloadUi,
      handleFilePayloadMessage,
    };
  }

  const api = { initFilePayloadController };
  global.POFHubFilePayloadController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.filePayloadController = api;
  }
})(window);
