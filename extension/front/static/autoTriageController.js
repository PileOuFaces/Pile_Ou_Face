/** Auto-triage IA (#124) — carte, confirmation et synchronisation du suivi. */
(function initAutoTriageController(global) {
  function resolveProviderAndModel() {
    // Mirrors submitOllamaChatPrompt's "provider@model" convention (front/shared/outils.js).
    // Only trust the chat widget's model if the user actually picked it this
    // session (ollamaUiState.modelUserSelected) — otherwise it just holds an
    // auto-filled default (first model in the Ollama list) that can diverge
    // from the model the user actually configured/saved in AI Provider
    // settings. Sending an empty provider/model lets the host/Python side
    // resolve POF_DEFAULT_AI_PROVIDER and that provider's saved model.
    const hasExplicitSelection = typeof ollamaUiState !== 'undefined' && ollamaUiState.modelUserSelected;
    const selected = hasExplicitSelection && typeof getCurrentOllamaModel === 'function' ? getCurrentOllamaModel() : '';
    const raw = String(selected || '').trim();
    const atIdx = raw.indexOf('@');
    if (atIdx > 0) {
      return { provider: raw.slice(0, atIdx), model: raw.slice(atIdx + 1) };
    }
    return raw ? { provider: 'ollama', model: raw } : { provider: '', model: '' };
  }

  const controller = { initAutoTriage };

  function initAutoTriage() {
    const bus = global.POFHubMessageBus;
    if (!bus) return;

    const reportBtn = document.querySelector('[data-action="auto-triage-open-report"]');
    const exportReportBtn = document.querySelector('[data-action="auto-triage-export-report"]');
    const prepareBtn = document.querySelector('[data-action="auto-triage"]');
    const cancelBtn = document.querySelector('[data-action="auto-triage-cancel"]');
    const modal = document.querySelector('[data-auto-triage-modal]');
    const modalDialog = modal?.querySelector('[role="dialog"]');
    const confirmBtn = document.querySelector('[data-action="auto-triage-confirm"]');
    const stateBadge = document.querySelector('[data-auto-triage-state]');
    const helpEl = document.querySelector('[data-auto-triage-help]');
    const resultEl = document.querySelector('[data-auto-triage-result]');
    let reportPath = '';
    let preflight = null;
    let pendingBinaryPath = '';
    let functionCount = 0;
    let previousFocus = null;
    let lastRunError = '';
    let lastRunErrorBinaryPath = '';

    const currentBinaryPath = () => (
      typeof getStaticBinaryPath === 'function' ? getStaticBinaryPath() : ''
    );

    const setText = (selector, value) => {
      const el = document.querySelector(selector);
      if (el) el.textContent = String(value ?? '—');
    };

    function setState(label, kind = '') {
      if (!stateBadge) return;
      stateBadge.textContent = label;
      stateBadge.className = `auto-triage-state${kind ? ` is-${kind}` : ''}`;
    }

    function budgetLabel(data = preflight || {}) {
      const fn = Number(data.maxFunctions || data.max_functions) || 0;
      const seconds = Number(data.maxSeconds || data.max_seconds) || 0;
      const tokens = Number(data.maxTotalTokens || data.max_total_tokens) || 0;
      return `${fn || '—'} fonctions · ${seconds || '—'}s · ${tokens || '—'} tokens/run`;
    }

    function updateCard(path = currentBinaryPath()) {
      const cleanPath = String(path || '').trim();
      setText('[data-auto-triage-binary]', cleanPath ? cleanPath.split(/[\\/]/).pop() : 'Aucun binaire');
      setText('[data-auto-triage-functions]', functionCount ? `${functionCount} détectée(s)` : 'À calculer');
      if (preflight) {
        setText('[data-auto-triage-model]', `${preflight.provider}@${preflight.model}`);
        setText('[data-auto-triage-budget]', budgetLabel(preflight));
      }
      const available = Boolean(cleanPath && preflight?.available);
      if (prepareBtn && !activeRuns.has(cleanPath)) prepareBtn.disabled = !available;
      if (helpEl) helpEl.textContent = cleanPath && cleanPath === lastRunErrorBinaryPath && lastRunError
        ? lastRunError
        : cleanPath
          ? (preflight && !preflight.available ? 'Désassemble d’abord ce binaire pour activer l’auto-triage.' : '')
          : 'Choisis d’abord un binaire dans l’analyse statique.';
    }

    function closePreflight() {
      pendingBinaryPath = '';
      if (!modal || modal.hidden) return;
      modal.hidden = true;
      previousFocus?.focus?.();
    }

    function openPreflight(path) {
      if (!modal || !preflight?.available) return;
      pendingBinaryPath = path;
      previousFocus = document.activeElement;
      setText('[data-auto-triage-confirm-binary]', path);
      setText('[data-auto-triage-confirm-model]', `${preflight.provider}@${preflight.model}`);
      setText('[data-auto-triage-confirm-functions]', functionCount ? `${functionCount} détectée(s), ${preflight.maxFunctions} maximum` : `${preflight.maxFunctions} maximum`);
      setText('[data-auto-triage-confirm-budget]', budgetLabel(preflight));
      setText('[data-auto-triage-confirm-warning]', `Le code décompilé sera transmis à « ${preflight.provider} ». Les suggestions resteront marquées IA jusqu’à validation.`);
      modal.hidden = false;
      modalDialog?.focus();
    }

    function setReportButton(path) {
      reportPath = String(path || '').trim();
      if (resultEl) resultEl.hidden = !reportPath;
    }

    function refreshReportButton() {
      const path = currentBinaryPath();
      if (!path) {
        setReportButton('');
        preflight = null;
        functionCount = 0;
        updateCard('');
        return;
      }
      bus.postMessage({ type: 'hubAutoTriageGetReport', binaryPath: path });
      bus.postMessage({ type: 'hubAutoTriagePreflight', binaryPath: path, ...resolveProviderAndModel() });
      bus.postMessage({ type: 'hubLoadAnnotations', binaryPath: path });
    }

    reportBtn?.addEventListener('click', () => {
      if (!reportPath) return;
      bus.postMessage({ type: 'hubAutoTriageOpenReport', reportPath });
    });
    exportReportBtn?.addEventListener('click', () => {
      if (!reportPath) return;
      bus.postMessage({ type: 'hubAutoTriageExportReport', reportPath });
    });
    prepareBtn?.addEventListener('click', () => {
      const path = currentBinaryPath();
      if (path) openPreflight(path);
    });
    modal?.querySelectorAll('[data-action="auto-triage-close-preflight"]').forEach((button) => {
      button.addEventListener('click', closePreflight);
    });
    modalDialog?.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closePreflight();
    });

    // Un seul run actif a la fois : changer de fichier de travail annule le
    // run de l'ancien binaire (meme mecanisme hubAiCancel que le bouton
    // Annuler du widget de suivi) plutot que de le laisser tourner en
    // parallele. Les annotations sont ecrites fonction par fonction cote
    // backend, donc rien n'est perdu ; relancer plus tard sur ce binaire
    // reprend automatiquement a la prochaine fonction non annotee
    // (select_candidate_functions exclut toute fonction deja annotee, cote
    // auto_triage.py).
    const activeRuns = new Map(); // binaryPath -> requestId
    let seq = 0;

    function cancelRun(path) {
      const requestId = activeRuns.get(path);
      if (!requestId) return;
      bus.postMessage({ type: 'hubAiCancel', requestId });
      // On ne retire pas l'entree ici : tant que hubAutoTriageDone (cancelled:
      // true) n'est pas revenu, le host garde ce binaryPath comme actif
      // (_activeTriageRuns cote staticHandlers.ts) et rejetterait un restart
      // premature.
    }

    function confirmRun(binaryPath) {
      const path = String(binaryPath || '').trim();
      if (!path) return;
      // Un run est deja en cours pour CE binaire : le widget de suivi (bas
      // gauche) l'affiche deja - pas besoin d'un second popup ici, et un toast
      // redeclenche a chaque tentative finirait par s'empiler a l'infini.
      if (activeRuns.has(path)) return;
      // Changer de fichier de travail : on stoppe le run de l'ancien binaire
      // (un seul actif a la fois), il reprendra plus tard la ou il s'est arrete.
      for (const other of Array.from(activeRuns.keys())) {
        if (other !== path) cancelRun(other);
      }
      // Le host peut appliquer un modèle dédié (pileOuFace.autoTriage.model) même si
      // aucun modèle de chat n'est sélectionné ici — la validation finale se fait
      // côté host, qui remonte l'erreur via hubAutoTriageDone (widget de suivi).
      const { provider, model } = resolveProviderAndModel();
      const requestId = `triage-${Date.now()}-${++seq}`;
      if (lastRunErrorBinaryPath === path) {
        lastRunError = '';
        lastRunErrorBinaryPath = '';
        if (helpEl) helpEl.textContent = '';
      }
      activeRuns.set(path, requestId);
      closePreflight();
      setState('En cours', 'running');
      if (prepareBtn) { prepareBtn.disabled = true; prepareBtn.textContent = 'Auto-triage en cours'; }
      if (cancelBtn) cancelBtn.hidden = false;
      bus.postMessage({
        type: 'hubAutoTriageStart',
        requestId,
        binaryPath: path,
        provider,
        model,
      });
    }

    function startRun(binaryPath) {
      const path = String(binaryPath || '').trim();
      if (!path || activeRuns.has(path)) return;
      if (!preflight || preflight.binaryPath !== path) {
        pendingBinaryPath = path;
        bus.postMessage({ type: 'hubAutoTriagePreflight', binaryPath: path, ...resolveProviderAndModel() });
        return;
      }
      openPreflight(path);
    }

    confirmBtn?.addEventListener('click', () => confirmRun(pendingBinaryPath));
    cancelBtn?.addEventListener('click', () => {
      const path = currentBinaryPath();
      cancelRun(path);
      if (helpEl) helpEl.textContent = 'Cancellation requested…';
    });

    bus.onMessage((event) => {
      const msg = event.data;
      if (msg?.type === 'hubAutoTriageOpenPanel') {
        startRun(msg.binaryPath);
        return;
      }
      if (msg?.type === 'hubAutoTriageReportInfo') {
        const path = currentBinaryPath();
        if (String(msg?.binaryPath || '').trim() === path) {
          setReportButton(msg.reportPath || '');
          const result = msg.result || {};
          if (result.completedAt) {
            const stats = result.stats || {};
            setText('[data-auto-triage-result-title]', result.cancelled ? 'Analysis interrupted — resume available' : 'Latest auto-triage completed');
            setText('[data-auto-triage-result-meta]', `${new Date(result.completedAt).toLocaleString()} · ${stats.processed || 0} function(s) · ${stats.tokens_used || 0} tokens · ${result.provider}${result.model ? `@${result.model}` : ''}`);
            if (!activeRuns.has(path)) {
              setState(result.cancelled ? 'Resume required' : 'Completed', result.cancelled ? 'running' : 'done');
              if (prepareBtn) prepareBtn.textContent = result.cancelled ? 'Resume auto-triage' : 'Run auto-triage again';
            }
          }
        }
        return;
      }
      if (msg?.type === 'hubAutoTriagePreflight') {
        const path = currentBinaryPath();
        if (String(msg.binaryPath || '') !== path) return;
        preflight = msg;
        updateCard(path);
        if (pendingBinaryPath === path && modal?.hidden) openPreflight(path);
        return;
      }
      if (msg?.type === 'hubAnnotations') {
        const path = currentBinaryPath();
        if (String(msg.binaryPath || '') !== path) return;
        functionCount = Array.isArray(msg.functionAddrs) ? msg.functionAddrs.length : 0;
        updateCard(path);
        return;
      }
      if (msg?.type === 'hubAutoTriageEvent') {
        // Rendre chaque nom/commentaire IA visible des qu'il est ecrit en
        // base (function_done), au compte-goutte, plutot que d'attendre la
        // fin du run entier (hubAutoTriageDone) pour tout afficher d'un coup.
        const path = String(msg?.binaryPath || '').trim();
        if (path && activeRuns.get(path) === msg?.requestId && msg.event?.type === 'function_done') {
          bus.postMessage({ type: 'hubLoadAnnotations', binaryPath: path });
        }
        if (path && activeRuns.get(path) === msg?.requestId) {
          const ev = msg.event || {};
          const position = Math.min(Number(ev.total) || 0, (Number(ev.index) || 0) + 1);
          if (prepareBtn && ev.type === 'function_start') prepareBtn.textContent = `Auto-triage in progress · ${position}/${ev.total}`;
          if (ev.type === 'selection_done') {
            setText('[data-auto-triage-model]', `${ev.provider}@${ev.model}`);
            setText('[data-auto-triage-budget]', budgetLabel(ev));
          }
        }
        return;
      }
      if (msg?.type !== 'hubAutoTriageDone' && msg?.type !== 'hubError') return;
      const path = String(msg?.binaryPath || '').trim();
      if (path) {
        if (activeRuns.get(path) !== msg?.requestId) return;
        activeRuns.delete(path);
      } else {
        let matched = '';
        for (const [p, id] of activeRuns) {
          if (id === msg?.requestId) { matched = p; break; }
        }
        if (!matched) return;
        activeRuns.delete(matched);
      }
      // Les renommages/commentaires IA sont ecrits en base au fil du run (par
      // fonction), mais la vue disasm ouverte n'est jamais notifiee toute
      // seule : on force un rechargement des annotations une fois le run
      // termine (succes, erreur ou annulation) pour rendre visible ce qui a
      // deja ete ecrit.
      if (msg?.type === 'hubAutoTriageDone' && msg.binaryPath) {
        bus.postMessage({ type: 'hubLoadAnnotations', binaryPath: msg.binaryPath });
        const currentPath = currentBinaryPath();
        if (msg.binaryPath === currentPath) {
          lastRunError = msg.ok ? '' : String(msg.error || 'Auto-triage failed.');
          lastRunErrorBinaryPath = msg.ok ? '' : msg.binaryPath;
          setReportButton(msg.ok ? msg.reportPath : '');
          setState(msg.ok ? (msg.cancelled ? 'Resume required' : 'Completed') : 'Failed', msg.ok ? (msg.cancelled ? 'running' : 'done') : 'error');
          if (prepareBtn) { prepareBtn.disabled = false; prepareBtn.textContent = msg.cancelled ? 'Resume auto-triage' : 'Run auto-triage again'; }
          if (cancelBtn) cancelBtn.hidden = true;
          if (helpEl) helpEl.textContent = lastRunError;
          refreshReportButton();
        }
      }
    });

    // Expose startRun so a UI button (ex. le bouton "Auto-triage IA" du
    // dashboard) peut declencher un run directement, sans repasser par
    // hubAutoTriageOpenPanel (qui n'existe que dans le sens host -> webview).
    controller.startRun = startRun;
    controller.refreshReportButton = refreshReportButton;
    refreshReportButton();
  }

  global.POFHubAutoTriageController = controller;
})(window);
