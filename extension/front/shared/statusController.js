/**
 * Classic-script controller for dynamic user-facing status/messages in the hub.
 * Centralizes status text and generic warning/error rendering without owning business logic.
 */
(function initHubStatusController(global) {
  function initStatusController(deps) {
    const {
      document,
      dynamicTraceStatus,
    } = deps || {};

    function setStatus(message, level = 'info') {
      if (!dynamicTraceStatus) return;
      dynamicTraceStatus.textContent = String(message || '');
      dynamicTraceStatus.dataset.level = String(level || 'info');
    }

    function clearStatus() {
      if (!dynamicTraceStatus) return;
      dynamicTraceStatus.textContent = '';
      delete dynamicTraceStatus.dataset.level;
    }

    function setError(message) {
      setStatus(message, 'error');
    }

    function setWarning(message) {
      setStatus(message, 'warning');
    }

    function setSuccess(message) {
      setStatus(message, 'success');
    }

    function renderWarnings(warnings, options = {}) {
      const {
        container = null,
        error = false,
        emptyMessage = 'Aucun warning.',
        joiner = ' • ',
      } = options;
      const items = Array.isArray(warnings)
        ? warnings.map((item) => String(item || '').trim()).filter(Boolean)
        : [];
      if (!container) return items;

      const tagName = String(container.tagName || '').toUpperCase();
      if (tagName === 'UL' || tagName === 'OL') {
        container.replaceChildren();
        container.classList.toggle('error', !!error);
        container.classList.toggle('warning', !error && items.length > 0);
        const lines = items.length ? items : [String(emptyMessage)];
        lines.forEach((message) => {
          const line = document.createElement('li');
          line.textContent = message;
          container.appendChild(line);
        });
        return items;
      }

      container.textContent = items.join(joiner);
      container.classList.toggle('error', !!error);
      container.classList.toggle('warning', !error && items.length > 0);
      return items;
    }

    return {
      clearStatus,
      renderWarnings,
      setError,
      setStatus,
      setSuccess,
      setWarning,
    };
  }

  const api = { initStatusController };
  global.POFHubStatusController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.statusController = api;
  }
})(window);
