// SPDX-License-Identifier: AGPL-3.0-only
(function initIdaKeymap() {
  'use strict';

  let keymap = 'default';

  function isEditable(target) {
    if (!target || typeof target.closest !== 'function') return false;
    return Boolean(target.closest('input, textarea, select, [contenteditable="true"], [role="textbox"]'));
  }

  function isAnalysisViewActive() {
    const staticPanel = document.getElementById('panel-static');
    if (!staticPanel?.classList.contains('active')) return false;
    return Boolean(document.querySelector('#staticDisasm.active, #staticDecompile.active'));
  }

  function activeAddress() {
    const candidates = [
      document.getElementById('annotationAddrBadge')?.dataset.addr,
      document.getElementById('decompileAddrSelect')?.value,
      window._lastDisasmAddr,
      window.decompileUiState?.selectedAddr,
    ];
    for (const candidate of candidates) {
      const value = typeof window.normalizeHexAddress === 'function'
        ? window.normalizeHexAddress(candidate || '')
        : String(candidate || '').trim();
      if (value) return value;
    }
    return '';
  }

  function focusAnnotation(addr, fieldId) {
    if (!addr || typeof window.focusAnnotationEditor !== 'function') return false;
    if (!document.getElementById('staticDisasm')?.classList.contains('active')) {
      window.PileOuFaceHostApi?.navigateTo?.('showGroup', { group: 'code', tab: 'disasm' });
    }
    window.focusAnnotationEditor(addr, null, { focus: fieldId === 'annotationComment' });
    const field = document.getElementById(fieldId);
    if (!field) return false;
    field.focus();
    field.select?.();
    return true;
  }

  function runAction(key) {
    if (key === 'g') {
      const input = document.getElementById('goToAddrInput');
      if (!input) return false;
      input.focus();
      input.select?.();
      return true;
    }

    const addr = activeAddress();
    if (key === 'n') return focusAnnotation(addr, 'annotationName');
    if (key === ';') return focusAnnotation(addr, 'annotationComment');
    if (key === 'x' && addr && window.PileOuFaceHostApi?.navigateTo) {
      window.PileOuFaceHostApi.navigateTo('openXrefs', { addr, mode: 'to' });
      return true;
    }
    return false;
  }

  window.addEventListener('message', (event) => {
    if (event.data?.type === 'hubKeymapConfig') {
      keymap = event.data.keymap === 'ida' ? 'ida' : 'default';
    }
  });

  document.addEventListener('keydown', (event) => {
    if (keymap !== 'ida' || event.defaultPrevented || event.repeat) return;
    if (event.ctrlKey || event.metaKey || event.altKey || isEditable(event.target)) return;
    if (!isAnalysisViewActive()) return;
    const key = String(event.key || '').toLowerCase();
    if (!['n', 'x', ';', 'g'].includes(key)) return;
    if (runAction(key)) {
      event.preventDefault();
      event.stopPropagation();
    }
  });

  window.POFIdaKeymap = { activeAddress, isAnalysisViewActive, runAction };
})();
