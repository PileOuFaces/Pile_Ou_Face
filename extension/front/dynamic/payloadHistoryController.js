/**
 * Classic-script controller for dynamic payload/trace history orchestration.
 * Keeps hub.js as the compatibility shell and acts only on injected deps.
 */
(function initHubPayloadHistoryController(global) {
  function initPayloadHistoryController(deps) {
    const {
      document,
      postMessage,
      dynamicTraceHistory,
      btnRefreshDynamicTraceHistory,
      btnClearDynamicTraceHistory,
      getDynamicTraceHistoryState,
      setDynamicTraceHistoryState,
      setDynamicTraceStatus,
      getBinaryPath,
      runBtn,
      openVisualizer,
    } = deps || {};

    let fallbackHistoryState = {
      items: [],
      activeTracePath: ''
    };

    function readHistoryState() {
      return typeof getDynamicTraceHistoryState === 'function'
        ? (getDynamicTraceHistoryState() || fallbackHistoryState)
        : fallbackHistoryState;
    }

    function writeHistoryState(nextState) {
      fallbackHistoryState = nextState || fallbackHistoryState;
      if (typeof setDynamicTraceHistoryState === 'function') {
        setDynamicTraceHistoryState(fallbackHistoryState);
      }
      return fallbackHistoryState;
    }

    function safePostMessage(message) {
      if (typeof postMessage === 'function') postMessage(message);
    }

    function refreshHistory() {
      safePostMessage({ type: 'requestDynamicTraceHistory' });
    }

    function clearHistory() {
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Nettoyage des anciennes traces...');
      }
      safePostMessage({ type: 'clearDynamicTraceHistory' });
    }

    function renderHistory(entries = null) {
      if (!dynamicTraceHistory) return;
      dynamicTraceHistory.replaceChildren();

      const currentState = readHistoryState();
      const items = Array.isArray(entries)
        ? entries
        : (Array.isArray(currentState.items) ? currentState.items : []);

      if (btnClearDynamicTraceHistory) btnClearDynamicTraceHistory.disabled = items.length === 0;
      if (!items.length) {
        const empty = document.createElement('p');
        empty.className = 'hint';
        empty.textContent = 'Aucune trace temporaire pour le moment.';
        dynamicTraceHistory.appendChild(empty);
        return;
      }

      items.forEach((item) => {
        const row = document.createElement('div');
        row.className = 'dynamic-history-item';
        if (item.active) row.classList.add('active');

        const main = document.createElement('div');
        main.className = 'dynamic-history-main';

        const title = document.createElement('div');
        title.className = 'dynamic-history-title';
        const runLabel = item.runId ? `#${item.runId}` : item.fileName || 'run';
        const stepsLabel = `${Number(item.steps || 0)} step(s)`;
        const payloadName = item.payloadLabel || 'payload';
        const argvLabel = item.argvBytes ? `${payloadName}: ${Number(item.argvBytes)} byte(s)` : 'sans payload';
        title.textContent = `${runLabel} • ${stepsLabel} • ${argvLabel}`;

        const meta = document.createElement('div');
        meta.className = 'dynamic-history-meta';
        const binaryLabel = item.binaryName || 'binaire inconnu';
        const whenLabel = item.updatedAtLabel || 'date inconnue';
        meta.textContent = `${binaryLabel} • ${whenLabel}`;

        const subline = document.createElement('div');
        subline.className = 'dynamic-history-subline';
        const extra = [];
        if (item.startSymbol) extra.push(`start ${item.startSymbol}`);
        if (item.sourceName) extra.push(`source ${item.sourceName}`);
        if (item.argvPreview) extra.push(`argv "${item.argvPreview}"`);
        subline.textContent = extra.length ? extra.join(' • ') : (item.path || '');

        main.appendChild(title);
        main.appendChild(meta);
        main.appendChild(subline);

        const actions = document.createElement('div');
        actions.className = 'dynamic-history-actions';

        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'btn btn-secondary btn-sm';
        openBtn.textContent = item.active ? 'Ouverte' : 'Ouvrir';
        openBtn.addEventListener('click', () => {
          if (typeof openVisualizer === 'function') {
            openVisualizer(item, { runLabel });
            return;
          }
          if (typeof setDynamicTraceStatus === 'function') {
            setDynamicTraceStatus(`Ouverture de la trace ${runLabel}...`);
          }
          safePostMessage({ type: 'openDynamicTraceHistory', tracePath: item.path });
        });

        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'btn btn-secondary btn-sm';
        deleteBtn.textContent = 'Supprimer';
        deleteBtn.addEventListener('click', () => {
          if (typeof setDynamicTraceStatus === 'function') {
            setDynamicTraceStatus(`Suppression de la trace ${runLabel}...`);
          }
          safePostMessage({ type: 'deleteDynamicTraceHistory', tracePath: item.path });
        });

        actions.appendChild(openBtn);
        actions.appendChild(deleteBtn);

        row.appendChild(main);
        row.appendChild(actions);
        dynamicTraceHistory.appendChild(row);
      });
    }

    function handleHistoryMessage(msg) {
      if (!msg || typeof msg !== 'object') return false;
      if (msg.type !== 'dynamicTraceHistory') return false;
      writeHistoryState({
        items: Array.isArray(msg.items) ? msg.items : [],
        activeTracePath: String(msg.activeTracePath || '').trim()
      });
      renderHistory();
      if (!runBtn?.disabled && typeof setDynamicTraceStatus === 'function') {
        const binaryPath = typeof getBinaryPath === 'function' ? getBinaryPath() : '';
        setDynamicTraceStatus(binaryPath ? 'Prêt.' : 'Sélectionnez un binaire pour lancer la trace.');
      }
      return true;
    }

    btnRefreshDynamicTraceHistory?.addEventListener('click', () => {
      if (typeof setDynamicTraceStatus === 'function') {
        setDynamicTraceStatus('Actualisation des traces...');
      }
      refreshHistory();
    });

    btnClearDynamicTraceHistory?.addEventListener('click', clearHistory);

    return {
      clearHistory,
      handleHistoryMessage,
      refreshHistory,
      renderHistory,
    };
  }

  const api = { initPayloadHistoryController };
  global.POFHubPayloadHistoryController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.payloadHistoryController = api;
  }
})(window);
