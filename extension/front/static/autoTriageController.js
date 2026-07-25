/**
 * Auto-triage IA (#124) — pas d'UI dédiée : le suivi/cancel se fait via le
 * widget générique de front/shared/taskProgressController.js (en bas à
 * gauche). Ce contrôleur ne fait que résoudre le provider/modèle courant et
 * déclencher le run quand on lui demande d'ouvrir un binaire.
 */
(function initAutoTriageController(global) {
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

  function initAutoTriage() {
    const bus = global.POFHubMessageBus;
    if (!bus) return;

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

    function startRun(binaryPath) {
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
      activeRuns.set(path, requestId);
      bus.postMessage({
        type: 'hubAutoTriageStart',
        requestId,
        binaryPath: path,
        provider,
        model,
      });
    }

    bus.onMessage((event) => {
      const msg = event.data;
      if (msg?.type === 'hubAutoTriageOpenPanel') {
        startRun(msg.binaryPath);
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
      }
    });
  }

  global.POFHubAutoTriageController = { initAutoTriage };
})(window);
