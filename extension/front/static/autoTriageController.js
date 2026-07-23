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

    let activeRequestId = '';

    function startRun(binaryPath) {
      if (activeRequestId) {
        if (typeof _showToast === 'function') {
          _showToast({
            title: 'Auto-triage IA',
            sub: 'Un auto-triage est déjà en cours — attends sa fin ou annule-le avant de relancer.',
            icon: 'ℹ️',
            variant: 'info',
          });
        }
        return;
      }
      const { provider, model } = resolveProviderAndModel();
      if (!model) {
        if (typeof _showToast === 'function') {
          _showToast({
            title: 'Auto-triage IA',
            sub: "Aucun modèle sélectionné : choisis un modèle IA dans l'onglet Assistant avant de lancer l'auto-triage.",
            icon: '⚠️',
            variant: 'error',
          });
        }
        return;
      }
      activeRequestId = `triage-${Date.now()}`;
      bus.postMessage({
        type: 'hubAutoTriageStart',
        requestId: activeRequestId,
        binaryPath,
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
      if ((msg?.type === 'hubAutoTriageDone' || msg?.type === 'hubError') && msg?.requestId === activeRequestId) {
        activeRequestId = '';
      }
    });
  }

  global.POFHubAutoTriageController = { initAutoTriage };
})(window);
