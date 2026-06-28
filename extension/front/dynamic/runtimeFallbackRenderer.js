/**
 * Runtime fallback renderer.
 *
 * Used only if the full runtime workspace module is not ready when a
 * dynamicTraceReady message reaches runtimeSessionController.
 */
(function initRuntimeFallbackRenderer(global) {
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function hexAddr(v) {
    if (v === null || v === undefined) return '—';
    var n = typeof v === 'number' ? v : parseInt(String(v), 16);
    if (!isFinite(n)) return esc(String(v));
    return '0x' + (n >>> 0).toString(16).padStart(8, '0');
  }

  function renderStep(documentRef, session, currentStep) {
    if (!documentRef || !session || !session.snapshots.length) return;
    var total = session.snapshots.length;
    var idx = Math.max(0, Math.min(currentStep - 1, total - 1));
    var snap = session.snapshots[idx];

    var labelEl = documentRef.getElementById('runtimePanelLabel');
    if (labelEl) labelEl.textContent = session.label + ' · ' + session.binaryName;

    var stepChip = documentRef.getElementById('runtimeStepChip');
    if (stepChip) stepChip.textContent = currentStep + '/' + total;

    var prevBtn = documentRef.getElementById('runtimePrev');
    var nextBtn = documentRef.getElementById('runtimeNext');
    if (prevBtn) prevBtn.disabled = currentStep <= 1;
    if (nextBtn) nextBtn.disabled = currentStep >= total;

    var crashBadge = documentRef.getElementById('runtimeCrashBadge');
    if (crashBadge) {
      crashBadge.hidden = !(session.crash && Number(session.crash.step) === currentStep);
    }

    var instrEl = documentRef.getElementById('runtimePanelInstr');
    if (instrEl) {
      var rip = (snap.rip !== undefined ? snap.rip : snap.eip);
      var func = snap.func ? esc(snap.func) : '?';
      var ripStr = rip !== undefined && rip !== null ? hexAddr(rip) : '?';
      instrEl.textContent = func + '()  ' + ripStr;
    }

    renderStack(documentRef, snap);
    renderRegisters(documentRef, snap);

    var bodyEl = documentRef.getElementById('runtimePanelBody');
    var emptyEl = documentRef.getElementById('runtimePanelEmpty');
    if (bodyEl) bodyEl.hidden = false;
    if (emptyEl) emptyEl.hidden = true;
  }

  function renderStack(documentRef, snap) {
    var stackEl = documentRef.getElementById('runtimeStackList');
    if (!stackEl) return;
    var stack = Array.isArray(snap.stack) ? snap.stack.slice(0, 8) : [];
    if (!stack.length) {
      stackEl.innerHTML = '<span class="hint">Aucun slot visible</span>';
      return;
    }
    stackEl.innerHTML = stack.map(function(slot) {
      return '<div class="runtime-stack-slot">'
        + '<span class="runtime-slot-name">' + esc(String(slot.name || slot.label || '?')) + '</span>'
        + '<span class="runtime-slot-value">' + esc(String(slot.value !== undefined ? slot.value : '—')) + '</span>'
        + '</div>';
    }).join('');
  }

  function renderRegisters(documentRef, snap) {
    var regsEl = documentRef.getElementById('runtimeRegsList');
    if (!regsEl) return;
    var regs = Array.isArray(snap.registers) ? snap.registers
      : (Array.isArray(snap.regs) ? snap.regs : []);
    var priority = ['rip','rsp','rbp','rax','rbx','rcx','rdx','eip','esp','ebp','eax','ebx','ecx','edx'];
    var shown = regs.filter(function(r) {
      return priority.indexOf(String(r.name || '').toLowerCase()) >= 0;
    }).slice(0, 10);
    if (!shown.length) shown = regs.slice(0, 8);
    if (!shown.length) {
      regsEl.innerHTML = '<span class="hint">Aucun registre</span>';
      return;
    }
    regsEl.innerHTML = shown.map(function(r) {
      var name = esc(String(r.name || '?').toUpperCase());
      var val = typeof r.value === 'number'
        ? hexAddr(r.value)
        : esc(String(r.value !== undefined ? r.value : '—'));
      return '<div class="runtime-reg-row">'
        + '<span class="runtime-reg-name">' + name + '</span>'
        + '<span class="runtime-reg-value">' + val + '</span>'
        + '</div>';
    }).join('');
  }

  function clearPanel(documentRef) {
    if (!documentRef) return;
    var bodyEl = documentRef.getElementById('runtimePanelBody');
    var emptyEl = documentRef.getElementById('runtimePanelEmpty');
    var labelEl = documentRef.getElementById('runtimePanelLabel');
    var stepChip = documentRef.getElementById('runtimeStepChip');
    var instrEl = documentRef.getElementById('runtimePanelInstr');
    if (bodyEl) bodyEl.hidden = true;
    if (emptyEl) emptyEl.hidden = false;
    if (labelEl) labelEl.textContent = '';
    if (stepChip) stepChip.textContent = '0/0';
    if (instrEl) instrEl.textContent = '';
  }

  var api = {
    renderStep: renderStep,
    clearPanel: clearPanel
  };
  global.POFHubRuntimeFallbackRenderer = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.runtimeFallbackRenderer = api;
  }
})(window);
