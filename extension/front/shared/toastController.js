/**
 * Classic-script controller for the toast notification system.
 * Handles container creation, toast insertion, dismissal, and auto-expiry.
 */
(function initHubToastController(global) {
  function initToastController() {
    function init() {
      if (document.getElementById('pof-toast-container')) return;
      const el = document.createElement('div');
      el.id = 'pof-toast-container';
      document.body.appendChild(el);
    }

    function showToast({ title, sub = '', icon = 'ℹ️', variant = 'info', duration = 5000 }) {
      const container = document.getElementById('pof-toast-container');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = `pof-toast pof-toast--${variant}`;
      toast.innerHTML = `
    <span class="pof-toast-icon">${icon}</span>
    <div class="pof-toast-body">
      <div class="pof-toast-title">${title}</div>
      ${sub ? `<div class="pof-toast-sub">${sub}</div>` : ''}
    </div>
    <button class="pof-toast-close" title="Fermer">✕</button>
  `;

      const dismiss = () => {
        toast.classList.add('pof-toast--out');
        setTimeout(() => toast.remove(), 350);
      };
      toast.querySelector('.pof-toast-close').addEventListener('click', dismiss);
      container.appendChild(toast);
      if (duration > 0) setTimeout(dismiss, duration);
    }

    return { init, showToast };
  }

  const api = { initToastController };
  global.POFHubToastController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.toastController = api;
  }
})(window);
