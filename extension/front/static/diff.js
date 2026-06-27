// ── Binary Diff / Func Similarity moved to offensive-research-pro plugin ──

// ── Script panel ──────────────────────────────────────────────────
(function initScriptPanel() {
  const editor = document.getElementById('scriptEditor');
  const output = document.getElementById('scriptOutput');
  const status = document.getElementById('scriptStatus');
  const runBtn = document.getElementById('btnRunScript');
  const saveBtn = document.getElementById('btnSaveScript');
  const loadBtn = document.getElementById('btnLoadScript');
  const clearBtn = document.getElementById('btnClearScript');
  const splitter = document.getElementById('scriptSplitter');
  if (!editor) return;

  const saved = _loadStorage();
  if (saved.scriptCode) editor.value = saved.scriptCode;

  let _saveTimer;
  editor.addEventListener('input', () => {
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(() => _saveStorage({ scriptCode: editor.value }), 500);
  });

  function runScript() {
    const code = editor.value.trim();
    if (!code) return;
    runBtn.setAttribute('disabled', 'true');
    status.textContent = '⏳ Exécution…';
    output.textContent = '';
    output.className = 'sc-output';

    const binaryPath = document.querySelector('input[name="binaryPath"]')?.value || '';
    const b64 = btoa(unescape(encodeURIComponent(code)));
    vscode.postMessage({ type: 'hubRunScript', code: b64, binaryPath });
  }

  runBtn?.addEventListener('click', runScript);

  editor.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runScript();
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = editor.selectionStart;
      editor.value = editor.value.substring(0, start) + '    ' + editor.value.substring(editor.selectionEnd);
      editor.selectionStart = editor.selectionEnd = start + 4;
    }
  });

  saveBtn?.addEventListener('click', () => {
    const name = prompt('Nom du script :', 'script.py');
    if (!name) return;
    vscode.postMessage({ type: 'hubSaveScript', name, content: editor.value });
  });

  loadBtn?.addEventListener('click', () => {
    vscode.postMessage({ type: 'hubLoadScript' });
  });

  clearBtn?.addEventListener('click', () => {
    editor.value = '';
    output.textContent = '';
    output.className = 'sc-output';
    status.textContent = '';
    _saveStorage({ scriptCode: '' });
  });

  if (splitter) {
    const editorWrap = editor.closest('.sc-editor-wrap');
    const outputWrap = output.closest('.sc-output-wrap');
    let dragging = false;

    splitter.addEventListener('mousedown', (e) => {
      e.preventDefault();
      dragging = true;
      document.body.style.cursor = 'row-resize';
      document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging || !editorWrap || !outputWrap) return;
      const container = editorWrap.parentElement;
      const rect = container.getBoundingClientRect();
      const y = e.clientY - rect.top;
      const toolbarH = container.querySelector('.sc-toolbar')?.offsetHeight || 0;
      const splitterH = splitter.offsetHeight;
      const available = rect.height - toolbarH - splitterH;
      const editorH = Math.max(60, Math.min(available - 60, y - toolbarH));
      editorWrap.style.flex = 'none';
      editorWrap.style.height = editorH + 'px';
      outputWrap.style.flex = '1';
      _saveStorage({ scriptSplitH: editorH });
    });

    document.addEventListener('mouseup', () => {
      if (dragging) {
        dragging = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      }
    });

    if (saved.scriptSplitH) {
      editorWrap.style.flex = 'none';
      editorWrap.style.height = saved.scriptSplitH + 'px';
    }
  }
})();


function initHexListeners() {
document.getElementById('btnHexGo')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const raw = document.getElementById('hexOffsetInput')?.value?.trim() || '0';
  const offset = parseInt(raw, raw.startsWith('0x') ? 16 : 10) || 0;
  const length = parseInt(document.getElementById('hexLengthSelect')?.value || '512', 10);
  tabDataCache.hex = null;
  loadHexView(bp, offset, length);
});
document.getElementById('btnHexPrev')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  tabDataCache.hex = null;
  loadHexView(bp, Math.max(0, hexCurrentOffset - hexCurrentLength), hexCurrentLength);
});
document.getElementById('btnHexNext')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  tabDataCache.hex = null;
  loadHexView(bp, hexCurrentOffset + hexCurrentLength, hexCurrentLength);
});
document.getElementById('btnHexToggleMeta')?.addEventListener('click', () => {
  hexUiState.compact = !hexUiState.compact;
  _saveStorage({ hexCompact: hexUiState.compact });
  applyHexLayoutMode();
});
document.getElementById('btnHexOpenSelection')?.addEventListener('click', () => {
  openHexSelectionInDisasm();
});
document.getElementById('btnHexResetSelection')?.addEventListener('click', () => {
  collapseHexSelectionToActive();
});
document.getElementById('btnHexPatch')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath(); if (!bp) return;
  const raw = document.getElementById('hexPatchOffset')?.value?.trim() || '0';
  const offset = parseInt(raw, raw.startsWith('0x') ? 16 : 10);
  if (isNaN(offset)) {
    const status = document.getElementById('hexPatchStatus');
    if (status) { status.className = 'hex-patch-status error'; status.textContent = 'Offset invalide'; }
    return;
  }
  const bytesHex = document.getElementById('hexPatchBytes')?.value?.trim() || '';
  if (!bytesHex) return;
  vscode.postMessage({ type: 'hubPatchBytes', binaryPath: bp, offset, bytesHex });
});
document.getElementById('btnHexUndo')?.addEventListener('click', () => {
  if (!hexPatchHistory.length) return;
  const bp = getStaticBinaryPath(); if (!bp) return;
  const last = hexPatchHistory[hexPatchHistory.length - 1];
  if (!last?.id) return;
  vscode.postMessage({ type: 'hubRevertPatch', binaryPath: bp, patchId: last.id });
});
document.getElementById('btnHexRedo')?.addEventListener('click', () => {
  if (!hexPatchRedoHistory.length) return;
  const bp = getStaticBinaryPath(); if (!bp) return;
  const entry = hexPatchRedoHistory[hexPatchRedoHistory.length - 1];
  if (!entry?.id) return;
  vscode.postMessage({ type: 'hubRedoPatch', binaryPath: bp, patchId: entry.id });
});
document.getElementById('hexContent')?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    openHexSelectionInDisasm();
  } else if (event.key === 'Escape') {
    event.preventDefault();
    collapseHexSelectionToActive();
  }
});
document.getElementById('btnRevertAll')?.addEventListener('click', function() {
  const bp = getStaticBinaryPath();
  if (bp) vscode.postMessage({ type: 'hubRevertAllPatches', binaryPath: bp });
});
applyHexLayoutMode();
updateHexSelectionButtons();

// ── Binary Diff buttons ──────────────────────────────────────────────────────
document.getElementById('btnBindiffBrowseA')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubPickFile', target: 'bindiffPathA' });
});
document.getElementById('btnBindiffBrowseB')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubPickFile', target: 'bindiffPathB' });
});
document.getElementById('btnRunBindiff')?.addEventListener('click', () => {
  const binaryA = document.getElementById('bindiffPathA')?.value?.trim();
  const binaryB = document.getElementById('bindiffPathB')?.value?.trim();
  if (!binaryA || !binaryB) {
    const resultsEl = document.getElementById('bindiffResults');
    if (resultsEl) {
      while (resultsEl.firstChild) resultsEl.removeChild(resultsEl.firstChild);
      const p = document.createElement('p');
      p.className = 'error-text';
      p.textContent = 'Renseignez les chemins des deux binaires.';
      resultsEl.appendChild(p);
    }
    return;
  }
  const threshold = parseFloat(document.getElementById('bindiffThreshold')?.value || '0.60');
  document.getElementById('btnRunBindiff')?.setAttribute('disabled', 'true');
  vscode.postMessage({ type: 'hubLoadBindiff', binaryA, binaryB, threshold });
});

document.getElementById('btnFuncSimilarityRefresh')?.addEventListener('click', () => {
  reloadFuncSimilarityPanel();
});
document.getElementById('btnFuncSimilarityAddRef')?.addEventListener('click', () => {
  const binaryPath = getStaticBinaryPath();
  setStaticLoading('funcSimilarityContent', 'Indexation de la référence…');
  vscode.postMessage({
    type: 'hubFuncSimilarityIndexReference',
    binaryPath,
    threshold: parseFloat(document.getElementById('funcSimilarityThreshold')?.value || '0.4'),
    top: parseInt(document.getElementById('funcSimilarityTop')?.value || '3', 10),
  });
});
document.getElementById('funcSimilarityThreshold')?.addEventListener('change', () => {
  if (getActiveStaticTab() === 'func_similarity') reloadFuncSimilarityPanel();
});

// ====== Typed Data toolbar ===================================================
document.getElementById('typedDataSection')?.addEventListener('change', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const section = document.getElementById('typedDataSection').value;
  if (!section) return;
  typedDataUiState.appliedStructAddr = '';
  tabDataCache.typed_data = null;
  vscode.postMessage(buildTypedDataRequest(bp, { section, page: 0 }));
});

document.querySelectorAll('.typed-type-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.typed-type-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const bp = getStaticBinaryPath();
    if (!bp) return;
    const section = document.getElementById('typedDataSection')?.value;
    if (!section) return;
    typedDataUiState.appliedStructName = '';
    typedDataUiState.appliedStructAddr = '';
    setTypedDataStructStatus('');
    tabDataCache.typed_data = null;
    vscode.postMessage(buildTypedDataRequest(bp, {
      section,
      page: 0,
      valueType: btn.dataset.type,
      structName: '',
    }));
  });
});


document.getElementById('btnTypedApplyStruct')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  const section = document.getElementById('typedDataSection')?.value;
  const structName = document.getElementById('typedDataStructSelect')?.value;
  const structOffset = document.getElementById('typedDataStructOffset')?.value || '0x0';
  if (!section && !structName) {
    setTypedDataStructStatus('Sélectionnez une section et un struct.', true);
    return;
  }
  if (!section) {
    setTypedDataStructStatus('Sélectionnez une section dans le menu.', true);
    return;
  }
  if (!structName) {
    setTypedDataStructStatus('Sélectionnez un struct dans le menu déroulant.', true);
    return;
  }
  typedDataUiState.appliedStructName = structName;
  typedDataUiState.appliedStructOffset = structOffset;
  typedDataUiState.appliedStructAddr = '';
  tabDataCache.typed_data = null;
  setStaticLoading('typedDataContent', 'Application du type…');
  vscode.postMessage(buildTypedDataRequest(bp, { section, page: 0, structName, structOffset }));
});

document.getElementById('typedDataStructOffset')?.addEventListener('input', () => {
  typedDataUiState.appliedStructAddr = '';
});

document.getElementById('btnTypedEditStructs')?.addEventListener('click', () => {
  typedDataUiState.pendingEditorOpen = true;
  typedDataUiState.loadingStructs = true;
  vscode.postMessage({ type: 'hubLoadStructs' });
});

document.getElementById('funcSimilarityTop')?.addEventListener('change', () => {
  if (getActiveStaticTab() === 'func_similarity') reloadFuncSimilarityPanel();
});
}
