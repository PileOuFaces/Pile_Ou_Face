// SPDX-License-Identifier: AGPL-3.0-only
/* global POFHubMessageBus */

function _isVisibleElement(element) {
  if (!element) return false;
  if (element.hidden) return false;
  if (element.closest('[hidden]')) return false;
  return true;
}

function _getAccountRoots() {
  return Array.from(document.querySelectorAll('[data-pof-account-root]'));
}

function _getPreferredAccountRoot() {
  const roots = _getAccountRoots();
  return roots.find((root) => _isVisibleElement(root.closest('.panel.active') || root)) || roots[0] || null;
}

function _readLoginPayload(form) {
  const scope = form || _getPreferredAccountRoot();
  if (!scope) return null;
  const emailInput = scope.querySelector('[data-pof-login-email]');
  const passwordInput = scope.querySelector('[data-pof-login-password]');
  const email = String(emailInput?.value || '').trim();
  const password = String(passwordInput?.value || '');
  if (!email || !password) return null;
  return { email, password };
}

function _doLogin(form) {
  const payload = _readLoginPayload(form);
  if (!payload) return;
  POFHubMessageBus.postMessage({ type: 'pof.auth.login', email: payload.email, password: payload.password });
}

function _doLogout() {
  POFHubMessageBus.postMessage({ type: 'pof.auth.logout' });
}

// Attach on DOMContentLoaded to ensure fragments are injected
window.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-pof-login-form]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      _doLogin(e.currentTarget);
    });
  });

  document.querySelectorAll('[data-pof-logout-btn]').forEach(function (logoutBtn) {
    logoutBtn.addEventListener('click', _doLogout);
  });
});

// Also handle clicks delegated from document (in case form loads after DOMContentLoaded)
document.addEventListener('click', function (e) {
  const target = /** @type {HTMLElement} */ (e.target);
  if (target?.closest?.('[data-pof-logout-btn]')) {
    _doLogout();
  }
});

document.addEventListener('keydown', function (e) {
  if (e.key !== 'Enter') return;
  const t = /** @type {HTMLElement} */ (e.target);
  if (t?.closest?.('[data-pof-login-form]')) {
    e.preventDefault();
    _doLogin(t.closest('[data-pof-login-form]'));
  }
});

window.addEventListener('message', function (event) {
  const msg = /** @type {{ type: string, loggedIn?: boolean, email?: string, plugins?: string[], error?: string }} */ (event.data);
  if (msg.type === 'accountState') {
    _renderAccountState(msg);
    POFHubMessageBus.postMessage({ type: 'hubLoadPluginState' });
  }
});

function _renderAccountState(state) {
  const loggedIn   = state.loggedIn;
  _getAccountRoots().forEach(function (root) {
    const loggedOutEl = root.querySelector('[data-pof-account-logged-out]');
    const loggedInEl  = root.querySelector('[data-pof-account-logged-in]');
    if (loggedOutEl) { loggedOutEl.style.display = loggedIn ? 'none' : ''; }
    if (loggedInEl)  { loggedInEl.style.display  = loggedIn ? '' : 'none'; }

    const errEl = root.querySelector('[data-pof-login-error]');
    if (errEl) {
      errEl.textContent = state.error || '';
      errEl.style.display = state.error ? '' : 'none';
    }

    if (loggedIn) {
      const emailEl = root.querySelector('[data-pof-account-email]');
      if (emailEl) { emailEl.textContent = state.email || ''; }

      const list = root.querySelector('[data-pof-plugin-list]');
      if (list) {
        list.textContent = '';
        (state.plugins || []).forEach(function (p) {
          const li = document.createElement('li');
          li.textContent = p;
          list.appendChild(li);
        });
      }
    }
  });
}
