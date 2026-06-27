// ====== Annotation note popup (disasm context-menu) ==========================

function showNotePopup(addr, x, y) {
  document.getElementById('pof-note-popup')?.remove();
  const popup = document.createElement('div');
  popup.id = 'pof-note-popup';
  popup.className = 'note-popup';
  popup.style.cssText = `position:fixed;left:${x}px;top:${y}px;z-index:200;` +
    `background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);` +
    `padding:8px;border-radius:4px;min-width:240px;`;
  const label = document.createElement('div');
  label.className = 'note-popup-addr';
  label.style.cssText = 'font-family:monospace;font-size:12px;margin-bottom:6px;opacity:0.8;';
  label.textContent = addr;
  const textarea = document.createElement('textarea');
  textarea.className = 'note-popup-input';
  textarea.rows = 3;
  textarea.style.cssText = 'width:100%;box-sizing:border-box;background:var(--vscode-input-background);' +
    'color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border);padding:4px;';
  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn btn-sm btn-primary';
  saveBtn.style.marginTop = '6px';
  saveBtn.textContent = 'Sauvegarder';
  saveBtn.addEventListener('click', () => {
    vscode.postMessage({
      type: 'hubSaveAnnotation',
      binaryPath: getStaticBinaryPath(),
      addr,
      comment: textarea.value,
    });
    popup.remove();
  });
  popup.appendChild(label);
  popup.appendChild(textarea);
  popup.appendChild(saveBtn);
  document.body.appendChild(popup);
  textarea.focus();
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') popup.remove();
  }, { once: true });
}

function initAnnotationsListeners() {
  // ── Annotations (Ctrl+click) ───────────────────────────────────────────────
  document.addEventListener('click', (e) => {
    if (!e.ctrlKey) return;
    const addrEl = e.target.closest('[data-addr]');
    if (!addrEl) return;
    const addr = addrEl.dataset.addr;
    e.preventDefault();
    showNotePopup(addr, e.clientX, e.clientY);
  });
}

initAnnotationsListeners();
