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

    // Suivi par binaire (pas un seul verrou global) : le host supporte deja
    // des runs concurrents par binaryPath (_activeTriageRuns cote staticHandlers.ts),
    // donc changer de fichier de travail pendant qu'un run tourne sur l'ancien
    // ne doit pas bloquer le declenchement d'un nouveau run sur le nouveau fichier.
    const activeRuns = new Map(); // binaryPath -> requestId
    let seq = 0;

    function startRun(binaryPath) {
      const path = String(binaryPath || '').trim();
      if (!path) return;
      // Un run est deja en cours pour CE binaire : le widget de suivi (bas
      // gauche) l'affiche deja - pas besoin d'un second popup ici, et un toast
      // redeclenche a chaque tentative finirait par s'empiler a l'infini.
      if (activeRuns.has(path)) return;
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
