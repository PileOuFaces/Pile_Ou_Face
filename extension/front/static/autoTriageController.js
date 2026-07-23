/**
 * Auto-triage IA (#124) — self-contained overlay panel.
 * Deliberately independent from the group-tabs/subtabs machinery in
 * panel-static.html: this feature can be triggered from a command
 * (no binary tab open yet) so it owns its own floating panel instead.
 */
(function initAutoTriageController(global) {
  const MAX_LOG_LINES = 300;

  function buildPanel() {
    const el = document.createElement('div');
    el.id = 'autoTriagePanel';
    el.className = 'auto-triage-panel modern-card';
    el.style.cssText = [
      'position:fixed', 'top:48px', 'right:16px', 'width:420px', 'max-height:70vh',
      'display:flex', 'flex-direction:column', 'z-index:9999', 'padding:12px',
      'overflow:hidden', 'box-shadow:0 4px 24px rgba(0,0,0,0.4)',
    ].join(';');

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;';
    const title = document.createElement('strong');
    title.textContent = 'Auto-triage IA';
    const closeBtn = document.createElement('button');
    closeBtn.id = 'autoTriageClose';
    closeBtn.className = 'btn btn-sm';
    closeBtn.title = 'Fermer';
    closeBtn.textContent = '×';
    header.appendChild(title);
    header.appendChild(closeBtn);

    const binaryLabel = document.createElement('div');
    binaryLabel.id = 'autoTriageBinaryLabel';
    binaryLabel.style.cssText = 'font-size:12px;opacity:0.8;margin-bottom:8px;word-break:break-all;';

    const progress = document.createElement('div');
    progress.id = 'autoTriageProgress';
    progress.style.cssText = 'font-size:12px;margin-bottom:8px;';

    const log = document.createElement('div');
    log.id = 'autoTriageLog';
    log.style.cssText = 'flex:1;overflow-y:auto;font-family:monospace;font-size:11px;background:rgba(0,0,0,0.15);padding:6px;border-radius:4px;min-height:120px;max-height:320px;';

    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:8px;margin-top:8px;';
    const startBtn = document.createElement('button');
    startBtn.id = 'autoTriageStart';
    startBtn.className = 'btn btn-primary btn-sm';
    startBtn.textContent = 'Lancer';
    const cancelBtn = document.createElement('button');
    cancelBtn.id = 'autoTriageCancel';
    cancelBtn.className = 'btn btn-secondary btn-sm';
    cancelBtn.disabled = true;
    cancelBtn.textContent = 'Annuler';
    const exportBtn = document.createElement('button');
    exportBtn.id = 'autoTriageExport';
    exportBtn.className = 'btn btn-secondary btn-sm';
    exportBtn.disabled = true;
    exportBtn.textContent = 'Ouvrir le rapport';
    actions.appendChild(startBtn);
    actions.appendChild(cancelBtn);
    actions.appendChild(exportBtn);

    el.appendChild(header);
    el.appendChild(binaryLabel);
    el.appendChild(progress);
    el.appendChild(log);
    el.appendChild(actions);

    closeBtn.addEventListener('click', () => { el.style.display = 'none'; });
    document.body.appendChild(el);
    return el;
  }

  function ensurePanel() {
    return document.getElementById('autoTriagePanel') || buildPanel();
  }

  function appendLog(panel, text) {
    const log = panel.querySelector('#autoTriageLog');
    if (!log) return;
    const line = document.createElement('div');
    line.textContent = text;
    log.appendChild(line);
    while (log.childNodes.length > MAX_LOG_LINES) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
  }

  function describeEvent(event) {
    switch (event.type) {
      case 'selection_done':
        return `Sélection: ${event.count ?? '?'} fonction(s) à analyser.`;
      case 'function_start':
        return `→ ${event.name || event.addr || '?'}`;
      case 'function_done':
        return `✓ ${event.name || event.addr || '?'}`;
      case 'function_error':
        return `✗ ${event.name || event.addr || '?'} : ${event.error || 'erreur'}`;
      case 'budget_warning':
        return `⚠ ${event.message || 'budget bientôt atteint'}`;
      case 'cancelled':
        return 'Triage annulé.';
      case 'summary':
        return 'Synthèse générée.';
      case 'done':
        return 'Terminé.';
      default:
        return JSON.stringify(event);
    }
  }

  function initAutoTriage() {
    const bus = global.POFHubMessageBus;
    if (!bus) return;
    let currentRequestId = '';
    let currentBinaryPath = '';
    let total = 0;
    let done = 0;

    function setProgress(panel) {
      const progressEl = panel.querySelector('#autoTriageProgress');
      if (progressEl) progressEl.textContent = total ? `Progression : ${done}/${total}` : '';
    }

    function openForBinary(binaryPath) {
      const panel = ensurePanel();
      panel.style.display = 'flex';
      currentBinaryPath = binaryPath || currentBinaryPath;
      panel.querySelector('#autoTriageBinaryLabel').textContent = currentBinaryPath;
      panel.querySelector('#autoTriageExport').disabled = true;
      return panel;
    }

    function resolveProviderAndModel() {
      // Mirrors submitOllamaChatPrompt's "provider@model" convention (front/shared/outils.js)
      const selected = typeof getCurrentOllamaModel === 'function' ? getCurrentOllamaModel() : '';
      const raw = String(selected || (typeof ollamaUiState !== 'undefined' ? ollamaUiState.lastModel : '') || '').trim();
      const atIdx = raw.indexOf('@');
      if (atIdx > 0) {
        return { provider: raw.slice(0, atIdx), model: raw.slice(atIdx + 1) };
      }
      return { provider: 'ollama', model: raw };
    }

    function startRun(panel) {
      if (panel.querySelector('#autoTriageStart').disabled) return;
      const { provider, model } = resolveProviderAndModel();
      if (!model) {
        appendLog(panel, "Aucun modèle sélectionné : choisis un modèle IA dans l'onglet Assistant avant de lancer l'auto-triage.");
        return;
      }
      currentRequestId = `triage-${Date.now()}`;
      panel.querySelector('#autoTriageLog').replaceChildren();
      panel.querySelector('#autoTriageStart').disabled = true;
      panel.querySelector('#autoTriageCancel').disabled = false;
      panel.querySelector('#autoTriageExport').disabled = true;
      total = 0;
      done = 0;
      bus.postMessage({
        type: 'hubAutoTriageStart',
        requestId: currentRequestId,
        binaryPath: currentBinaryPath,
        provider,
        model,
      });
    }

    bus.onMessage((event) => {
      const msg = event.data;
      if (!msg?.type) return;
      if (msg.type === 'hubAutoTriageOpenPanel') {
        const panel = openForBinary(msg.binaryPath);
        if (msg.autoStart) startRun(panel);
        return;
      }
      if (msg.type === 'hubAutoTriageEvent') {
        if (msg.requestId !== currentRequestId) return;
        const panel = ensurePanel();
        const ev = msg.event || {};
        appendLog(panel, describeEvent(ev));
        if (ev.type === 'selection_done') { total = ev.count || 0; done = 0; }
        if (ev.type === 'function_done' || ev.type === 'function_error') { done += 1; }
        setProgress(panel);
        return;
      }
      if (msg.type === 'hubAutoTriageDone') {
        if (msg.requestId !== currentRequestId) return;
        const panel = ensurePanel();
        appendLog(panel, msg.ok ? 'Auto-triage terminé avec succès.' : `Échec : ${msg.error || 'erreur inconnue'}`);
        panel.querySelector('#autoTriageStart').disabled = false;
        panel.querySelector('#autoTriageCancel').disabled = true;
        const exportBtn = panel.querySelector('#autoTriageExport');
        exportBtn.disabled = !msg.ok || !msg.reportPath;
        exportBtn.dataset.reportPath = msg.reportPath || '';
      }
    });

    document.addEventListener('click', (e) => {
      const panel = document.getElementById('autoTriagePanel');
      if (!panel || !panel.contains(e.target)) return;
      if (e.target.id === 'autoTriageStart') {
        startRun(panel);
      } else if (e.target.id === 'autoTriageCancel') {
        bus.postMessage({ type: 'hubAiCancel', requestId: currentRequestId });
        e.target.disabled = true;
      } else if (e.target.id === 'autoTriageExport') {
        const reportPath = e.target.dataset.reportPath;
        if (reportPath) bus.postMessage({ type: 'hubAutoTriageOpenReport', reportPath });
      }
    });
  }

  global.POFHubAutoTriageController = { initAutoTriage };
})(window);
