/**
 * Front-end logic for the "Connect Agents" (MCP) webview panel.
 * Talks to extension/src/static/mcpAgentsPanel.ts via POFHubMessageBus.
 */
(function initMcpAgentsPanel() {
  const bus = window.POFHubMessageBus;
  const agentSelect = document.getElementById('agentSelect');
  const scopeSelect = document.getElementById('scopeSelect');
  const statusEl = document.getElementById('status');
  const outputEl = document.getElementById('output');
  const buttons = {
    mcpPreview: document.getElementById('btnPreview'),
    mcpApply: document.getElementById('btnApply'),
    mcpRollback: document.getElementById('btnRollback'),
    mcpRunDoctor: document.getElementById('btnDoctor'),
  };

  const RESULT_TYPE_BY_REQUEST = {
    mcpPreview: 'mcpPreviewResult',
    mcpApply: 'mcpApplyResult',
    mcpRollback: 'mcpRollbackResult',
    mcpRunDoctor: 'mcpDoctorResult',
  };

  let requestSeq = 0;
  let pendingType = null;

  function setBusy(busy) {
    Object.values(buttons).forEach((btn) => { btn.disabled = busy; });
  }

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.className = kind || '';
  }

  function send(type) {
    const requestId = `${type}-${++requestSeq}`;
    pendingType = type;
    setBusy(true);
    setStatus('Working…', '');
    bus.postMessage({
      type,
      requestId,
      agent: agentSelect.value,
      scope: scopeSelect.value,
    });
  }

  buttons.mcpPreview.addEventListener('click', () => send('mcpPreview'));
  buttons.mcpApply.addEventListener('click', () => send('mcpApply'));
  buttons.mcpRollback.addEventListener('click', () => send('mcpRollback'));
  buttons.mcpRunDoctor.addEventListener('click', () => send('mcpRunDoctor'));

  bus.onMessage((event) => {
    const msg = event.data || {};
    const expectedType = pendingType ? RESULT_TYPE_BY_REQUEST[pendingType] : null;
    if (!expectedType || msg.type !== expectedType) return;
    setBusy(false);
    pendingType = null;
    if (msg.error) {
      setStatus(`Error: ${msg.error}`, 'error');
      outputEl.textContent = msg.error;
      return;
    }
    setStatus('Done', 'ok');
    outputEl.textContent = JSON.stringify(msg.result, null, 2);
  });
})();
