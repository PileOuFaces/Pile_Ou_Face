(function (global) {
  'use strict';

  function fallbackNormalizeMode(mode) {
    return ['payload_builder', 'file', 'exploit_helper', 'pwntools_script'].includes(mode)
      ? mode
      : 'payload_builder';
  }

  function fallbackNormalizeBuilderLevel(level, fallback = 'beginner') {
    return level === 'advanced' || level === 'beginner' ? level : fallback;
  }

  function createPayloadTabsController(options = {}) {
    const doc = options.document || global.document;
    const normalizeMode = options.normalizeMode || fallbackNormalizeMode;
    const normalizeBuilderLevel = options.normalizeBuilderLevel || fallbackNormalizeBuilderLevel;
    const getBuilderHint = typeof options.getBuilderHint === 'function'
      ? options.getBuilderHint
      : ((level) => (level === 'advanced' ? '' : ''));
    const getHelperOutput = typeof options.getHelperOutput === 'function'
      ? options.getHelperOutput
      : (() => '—');

    const tabs = Array.from(doc.querySelectorAll('[data-payload-mode]'));
    const panels = Array.from(doc.querySelectorAll('[data-payload-panel]'));
    const builderLevelButtons = Array.from(doc.querySelectorAll('[data-payload-builder-level]'));
    const commonRow = doc.querySelector('.dynamic-payload-common-row');
    const previewSection = doc.querySelector('#panel-dynamic .dynamic-payload-preview');
    const previewActions = Array.from(doc.querySelectorAll('#panel-dynamic [data-payload-action]'));
    const payloadBuilderInput = doc.getElementById('payloadBuilderInput');
    const payloadBuilderModeHint = doc.getElementById('payloadBuilderModeHint');
    const payloadFileSource = doc.getElementById('payloadFileSource');
    const exploitHelperTemplate = doc.getElementById('exploitHelperTemplate');
    const exploitHelperOutput = doc.getElementById('exploitHelperOutput');

    let mode = normalizeMode(options.initialMode || 'payload_builder');
    let builderLevel = normalizeBuilderLevel(options.initialBuilderLevel || 'beginner', 'beginner');

    function getMode() {
      return mode;
    }

    function getBuilderLevel() {
      return builderLevel;
    }

    function updatePayloadBuilderUi() {
      if (payloadBuilderModeHint) payloadBuilderModeHint.textContent = getBuilderHint(builderLevel);
      builderLevelButtons.forEach((button) => {
        button.classList.toggle('is-active', button.dataset.payloadBuilderLevel === builderLevel);
      });
      if (payloadBuilderInput) {
        payloadBuilderInput.placeholder = builderLevel === 'advanced'
          ? 'b"A"*72 + p64(0x401234)'
          : 'A*64';
      }
    }

    function updatePayloadFilePanels() {
      const source = payloadFileSource?.value || 'inline';
      doc.querySelectorAll('[data-file-source-panel]').forEach((panel) => {
        panel.classList.toggle('active', panel.dataset.fileSourcePanel === source);
      });
    }

    function updateExploitHelperTemplateFields() {
      const template = exploitHelperTemplate?.value || 'pattern';
      doc.querySelectorAll('[data-helper-fields]').forEach((panel) => {
        panel.classList.toggle('active', panel.dataset.helperFields === template);
      });
    }

    function updatePayloadActionVisibility() {
      const showPreviewSection = mode === 'payload_builder' || mode === 'file';
      previewSection?.classList.toggle('is-hidden', !showPreviewSection);
      previewActions.forEach((action) => {
        const kind = action.dataset.payloadAction;
        const visible = mode === 'payload_builder'
          || (mode === 'file' && (kind === 'preview' || kind === 'use'));
        action.classList.toggle('is-hidden', !visible);
      });
    }

    function renderExploitHelperOutput() {
      if (!exploitHelperOutput) return;
      if (mode !== 'exploit_helper') {
        exploitHelperOutput.textContent = '—';
        return;
      }
      try {
        exploitHelperOutput.textContent = String(getHelperOutput() || '—');
      } catch (err) {
        exploitHelperOutput.textContent = err?.message || String(err);
      }
    }

    function render() {
      tabs.forEach((tab) => {
        tab.classList.toggle('active', tab.dataset.payloadMode === mode);
      });
      panels.forEach((panel) => {
        panel.classList.toggle('active', panel.dataset.payloadPanel === mode);
      });
      if (commonRow) {
        commonRow.style.display = mode === 'payload_builder' ? '' : 'none';
      }
      updatePayloadFilePanels();
      updateExploitHelperTemplateFields();
      updatePayloadBuilderUi();
      updatePayloadActionVisibility();
      renderExploitHelperOutput();
      options.onRender?.({ mode, builderLevel });
    }

    function setMode(nextMode) {
      mode = normalizeMode(nextMode);
      render();
      return mode;
    }

    function setBuilderLevel(nextLevel) {
      builderLevel = normalizeBuilderLevel(nextLevel, builderLevel);
      updatePayloadBuilderUi();
      options.onBuilderLevelRender?.({ mode, builderLevel });
      return builderLevel;
    }

    function bindEvents(callbacks = {}) {
      tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
          setMode(tab.dataset.payloadMode || 'payload_builder');
          callbacks.onTabClick?.({ mode, builderLevel });
        });
      });

      payloadFileSource?.addEventListener('change', () => {
        updatePayloadFilePanels();
        callbacks.onFileSourceChange?.({ mode, builderLevel });
      });

      exploitHelperTemplate?.addEventListener('change', () => {
        updateExploitHelperTemplateFields();
        renderExploitHelperOutput();
        callbacks.onHelperTemplateChange?.({ mode, builderLevel });
      });

      builderLevelButtons.forEach((button) => {
        button.addEventListener('click', () => {
          setBuilderLevel(button.dataset.payloadBuilderLevel || 'beginner');
          callbacks.onBuilderLevelClick?.({ mode, builderLevel });
        });
      });
    }

    return {
      bindEvents,
      getMode,
      getBuilderLevel,
      setMode,
      setBuilderLevel,
      render,
      renderBuilderUi: updatePayloadBuilderUi,
      renderFilePanels: updatePayloadFilePanels,
      renderHelperFields: updateExploitHelperTemplateFields,
      renderHelperOutput: renderExploitHelperOutput,
      renderActionVisibility: updatePayloadActionVisibility,
    };
  }

  global.POFHubPayloadTabsController = {
    create: createPayloadTabsController,
  };
})(window);
