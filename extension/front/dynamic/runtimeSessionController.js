/**
 * Runtime Session — gère la sidebar item et le panel runtime dans le hub.
 *
 * Après un Run Trace réussi (dynamicTraceReady), ajoute un item dans la
 * sidebar sous l'icône Dynamic et bascule vers le panel #panel-runtime.
 * Le visualiseur standalone reste accessible depuis l'historique Dynamic.
 */
(function initHubRuntimeSessionController(global) {
  function initRuntimeSessionController(deps) {
    const { document, postMessage, showPanel, fallbackRenderer, getBinaryPath } = deps || {};

    var session = null;
    var currentStep = 1;

    function postMsg(msg) {
      if (typeof postMessage === 'function') postMessage(msg);
    }

    function normalizeBinaryPathForCompare(value) {
      return String(value || '').trim().replace(/\\/g, '/');
    }

    function getCurrentBinaryPath() {
      return typeof getBinaryPath === 'function' ? String(getBinaryPath() || '').trim() : '';
    }

    function getMessageBinaryPath(msg) {
      return String(
        msg?.binaryPath
        || msg?.meta?.binaryPath
        || msg?.meta?.binary_path
        || msg?.meta?.binary
        || ''
      ).trim();
    }

    function isStaleRuntimeBinaryResponse(msg, scope) {
      var responseBinaryPath = getMessageBinaryPath(msg);
      var currentBinaryPath = getCurrentBinaryPath();
      if (
        !responseBinaryPath
        || !currentBinaryPath
        || normalizeBinaryPathForCompare(responseBinaryPath) === normalizeBinaryPathForCompare(currentBinaryPath)
      ) {
        return false;
      }
      postMsg({
        type: 'hubDebugLog',
        scope,
        event: 'ignored-stale-response',
        details: { currentBinaryPath, responseBinaryPath },
      });
      return true;
    }

    // --- Sidebar nav item ---

    function getNavSlot() {
      return document ? document.getElementById('runtimeNavSlot') : null;
    }

    function updateNavItem() {
      var slot = getNavSlot();
      if (!slot) return;
      // Only one session shown at a time (replace previous)
      slot.replaceChildren();
      if (!session) return;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'runtime-nav-item';
      btn.dataset.panel = 'runtime';
      btn.title = session.label + ' — ' + (session.binaryName || 'binaire');
      btn.setAttribute('aria-label', session.label);
      btn.textContent = '⚡';
      btn.addEventListener('click', function() {
        activateRuntimePanel();
      });
      slot.appendChild(btn);
    }

    function activateRuntimePanel() {
      if (typeof showPanel === 'function') showPanel('runtime');
      // Mark nav item active (showPanel deactivates icon-nav-items but not .runtime-nav-item)
      document.querySelectorAll('.runtime-nav-item').forEach(function(n) {
        n.classList.toggle('active', n.dataset.panel === 'runtime');
      });
    }

    // --- Session management ---

    function setSession(data) {
      var snapshots = Array.isArray(data.snapshots) ? data.snapshots : [];
      var binaryRaw = String(data.meta && (data.meta.binary_path || data.meta.binary || data.meta.output_path) || '—').split('/').pop() || '—';
      var sessionCount = (session ? session.id.replace(/[^0-9]/g, '') : '0');
      var nextCount = (parseInt(sessionCount, 10) || 0) + 1;

      session = {
        id: 'runtime-' + nextCount,
        label: 'Trace #' + nextCount,
        binaryName: binaryRaw,
        snapshots: snapshots,
        traceRunId: data.traceRunId || null,
        tracePath: String(data.tracePath || ''),
        crash: data.crash && typeof data.crash === 'object' ? data.crash : null,
        stepCount: snapshots.length,
      };
      currentStep = 1;

      updateNavItem();
      activateRuntimePanel();

      // Delegate full rendering to runtime workspace (app/main.js loaded as module)
      if (window.POFHubRuntime && typeof window.POFHubRuntime.loadTrace === 'function') {
        window.POFHubRuntime.loadTrace(data);
      } else {
        // Fallback compact rendering if module not yet loaded
        fallbackRenderer?.renderStep?.(document, session, currentStep);
      }
    }

    function clearSession() {
      session = null;
      currentStep = 1;
      updateNavItem();
      if (window.POFHubRuntime && typeof window.POFHubRuntime.clearTrace === 'function') {
        window.POFHubRuntime.clearTrace();
      } else {
        fallbackRenderer?.clearPanel?.(document);
      }
    }

    // --- Button event bindings (called once on init) ---

    function initEvents() {
      // Step prev/next are handled by app/main.js (dom.btnPrev / dom.btnNext).
      // "Ouvrir en grand" removed — use History in Dynamic panel to reopen a trace.
    }

    // --- Message handler ---

    function handleMessage(msg) {
      if (!msg || typeof msg !== 'object') return false;
      if (msg.type === 'dynamicTraceReady') {
        if (isStaleRuntimeBinaryResponse(msg, 'dynamic-trace-ready')) return true;
        setSession(msg);
        return true;
      }
      if (msg.type === 'dynamicTraceCleared' || msg.type === 'clearTrace' || msg.type === 'noTrace') {
        clearSession();
        return true;
      }
      return false;
    }

    fallbackRenderer?.clearPanel?.(document);
    initEvents();

    return { clearSession, handleMessage };
  }

  var api = { initRuntimeSessionController: initRuntimeSessionController };
  global.POFHubRuntimeSessionController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.runtimeSessionController = api;
  }
})(window);
