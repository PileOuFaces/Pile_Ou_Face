/**
 * Runtime workspace layout controller for the hub-integrated runtime panel.
 *
 * Kept outside hub.html because the hub CSP does not allow inline scripts.
 */
(function initRuntimeWorkspaceLayoutController() {
  var root = document.getElementById('panel-runtime');

  var RESIZE_KEY = 'pof-col-widths-v2';
  var LEFT_HEIGHTS_KEY = 'pof-left-panel-heights-v1';
  var MIN_LEFT = 260;
  var MIN_STACK = 360;
  var currentFocus = null;
  var leftPanelResizeHandles = [];

  var visStates = { explain: true, dump: true, registers: true, stack: true };
  var LEFT_PANEL_KEYS = ['explain', 'dump', 'registers'];
  var LEFT_PANEL_MIN_HEIGHTS = { explain: 140, dump: 120, registers: 120 };
  var LEFT_PANEL_DEFAULT_HEIGHTS = { explain: 260, dump: 160, registers: 180 };
  var leftPanelHeights = readLeftPanelHeights();

  var STORAGE_KEYS = {
    explain: 'pof-panel-visible-explain',
    dump: 'pof-panel-visible-dump',
    registers: 'pof-panel-visible-registers',
    stack: 'pof-panel-visible-stack'
  };

  function readVisible(key) {
    try {
      var stored = localStorage.getItem(key);
      return stored === null ? true : stored === 'true';
    } catch (_) {
      return true;
    }
  }

  function writeVisible(key, visible) {
    try {
      localStorage.setItem(key, visible ? 'true' : 'false');
    } catch (_) {
      // Ignore storage failures inside restricted webview contexts.
    }
  }

  function readLeftPanelHeights() {
    try {
      var parsed = JSON.parse(localStorage.getItem(LEFT_HEIGHTS_KEY) || '{}');
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (_) {
      return {};
    }
  }

  function writeLeftPanelHeights() {
    try {
      localStorage.setItem(LEFT_HEIGHTS_KEY, JSON.stringify(leftPanelHeights));
    } catch (_) {
      // Ignore storage failures inside restricted webview contexts.
    }
  }

  function getLeftPanel(key) {
    return root ? root.querySelector('[data-runtime-panel="' + key + '"]') : null;
  }

  function getVisibleLeftPanelKeys() {
    return LEFT_PANEL_KEYS.filter(function (key) {
      return Boolean(visStates[key]);
    });
  }

  function clampLeftPanelHeight(key, value) {
    var min = LEFT_PANEL_MIN_HEIGHTS[key] || 120;
    var parsed = Number(value);
    if (!Number.isFinite(parsed)) parsed = LEFT_PANEL_DEFAULT_HEIGHTS[key] || min;
    return Math.max(min, parsed);
  }

  function ensureLeftPanelHeight(key) {
    leftPanelHeights[key] = clampLeftPanelHeight(key, leftPanelHeights[key]);
    return leftPanelHeights[key];
  }

  function syncLeftPanelRows() {
    if (!root) return;
    var leftCol = root.querySelector('.left-col');
    if (!leftCol) return;

    var visibleKeys = getVisibleLeftPanelKeys();
    var handleByPreviousPanel = {};
    leftPanelResizeHandles.forEach(function (handle) {
      handle.hidden = true;
      delete handle.dataset.previousPanel;
      delete handle.dataset.nextPanel;
    });

    visibleKeys.slice(0, -1).forEach(function (previousKey, index) {
      var handle = leftPanelResizeHandles.find(function (candidate) {
        return candidate.dataset.afterPanel === previousKey;
      });
      if (!handle) return;
      handle.hidden = false;
      handle.dataset.previousPanel = previousKey;
      handle.dataset.nextPanel = visibleKeys[index + 1];
      handleByPreviousPanel[previousKey] = handle;
    });

    if (!visibleKeys.length) {
      leftCol.style.gridTemplateRows = '';
      return;
    }

    var rows = [];
    LEFT_PANEL_KEYS.forEach(function (key) {
      if (!visStates[key]) return;
      var min = LEFT_PANEL_MIN_HEIGHTS[key] || 120;
      rows.push('minmax(' + min + 'px, ' + ensureLeftPanelHeight(key) + 'fr)');
      if (handleByPreviousPanel[key]) rows.push('8px');
    });
    leftCol.style.gridTemplateRows = rows.join(' ');
  }

  function updateLayout() {
    if (!root) return;
    var visuals = root.querySelector('.visuals');
    var leftCol = root.querySelector('.left-col');
    if (!visuals || !leftCol) return;

    var leftCount = (visStates.explain ? 1 : 0)
      + (visStates.dump ? 1 : 0)
      + (visStates.registers ? 1 : 0);

    leftCol.hidden = leftCount === 0;
    leftCol.dataset.visibleCount = String(leftCount);
    leftCol.dataset.hasExplain = visStates.explain ? 'true' : 'false';
    visuals.dataset.leftCount = String(leftCount);
    visuals.classList.toggle('layout-no-left', leftCount === 0);
    visuals.classList.toggle('layout-compact-left', leftCount > 0 && leftCount < 3);
    visuals.classList.toggle('layout-slim-left', leftCount === 1 || (leftCount === 2 && !visStates.explain));
    visuals.classList.toggle('layout-single-left', leftCount === 1);
    visuals.classList.toggle('layout-dual-left', leftCount === 2);
    visuals.classList.toggle('layout-no-right', !visStates.stack);
    visuals.classList.toggle('layout-has-dump', visStates.dump && leftCount > 0);
    visuals.classList.toggle('layout-explain-only', visStates.explain && !visStates.dump && !visStates.registers);
    visuals.style.gridTemplateColumns = '';
    syncLeftPanelRows();
  }

  function setRuntimePanelVisible(key, visible) {
    if (!root) return;
    var panel = root.querySelector('[data-runtime-panel="' + key + '"]');
    var btn = root.querySelector('[data-runtime-toggle="' + key + '"]');
    if (!panel || !btn) {
      console.warn('[runtime toggles] missing target', key, { panel: !!panel, btn: !!btn });
      return;
    }

    visStates[key] = visible;
    panel.hidden = !visible;
    btn.setAttribute('aria-pressed', String(visible));
    btn.classList.toggle('is-active', visible);
    updateLayout();
  }

  function initToggles() {
    if (!root) return;
    Object.keys(STORAGE_KEYS).forEach(function (key) {
      visStates[key] = readVisible(STORAGE_KEYS[key]);
      setRuntimePanelVisible(key, visStates[key]);
    });
    root.querySelectorAll('[data-runtime-toggle]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var key = btn.dataset.runtimeToggle;
        var next = !visStates[key];
        writeVisible(STORAGE_KEYS[key], next);
        setRuntimePanelVisible(key, next);
      });
    });
  }

  function setFocus(name) {
    if (!root) return;
    var visuals = root.querySelector('.visuals');
    if (!visuals) return;
    currentFocus = name;
    visuals.dataset.panelFocus = name;
    root.querySelectorAll('.panel-focus-btn').forEach(function (button) {
      var active = button.dataset.focusPanel === name;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
  }

  function clearFocus() {
    if (!root) return;
    var visuals = root.querySelector('.visuals');
    if (!visuals) return;
    currentFocus = null;
    delete visuals.dataset.panelFocus;
    root.querySelectorAll('.panel-focus-btn').forEach(function (button) {
      button.classList.remove('is-active');
      button.setAttribute('aria-pressed', 'false');
    });
  }

  function initFocus() {
    if (!root) return;
    root.querySelectorAll('.panel-focus-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (currentFocus === btn.dataset.focusPanel) {
          clearFocus();
        } else {
          setFocus(btn.dataset.focusPanel);
        }
      });
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && currentFocus) clearFocus();
    });
  }

  function initResize() {
    if (!root) return;
    var visuals = root.querySelector('.visuals');
    var leftCol = root.querySelector('.left-col');
    var disasmEl = root.querySelector('#disasmPanel');
    if (!visuals || !leftCol || !disasmEl) return;

    function makeHandle(parent, type) {
      var handle = document.createElement('div');
      handle.className = 'col-resize-handle';
      handle.dataset.resizeType = type;
      handle.setAttribute('aria-hidden', 'true');
      parent.appendChild(handle);
      return handle;
    }

    function startDrag(handle, event) {
      event.preventDefault();
      var isLeft = handle.dataset.resizeType === 'left';
      var startX = event.clientX;
      var leftRect = leftCol.getBoundingClientRect();
      var asmRect = disasmEl.getBoundingClientRect();
      var stackEl = root.querySelector('#stackPanel');
      var stackRect = stackEl ? stackEl.getBoundingClientRect() : { width: MIN_STACK };
      var initialWidths = { left: leftRect.width, asm: asmRect.width, stack: stackRect.width };

      handle.classList.add('is-dragging');
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';

      function onMove(moveEvent) {
        var delta = moveEvent.clientX - startX;
        var left = initialWidths.left;
        var stack = initialWidths.stack;
        var effectiveMinLeft = visStates.dump ? 420 : MIN_LEFT;
        var hasLeft = visStates.explain || visStates.dump || visStates.registers;
        var hasStack = visStates.stack;

        if (isLeft) {
          if (!hasLeft) return;
          left = Math.max(effectiveMinLeft, initialWidths.left + delta);
        } else {
          if (!hasStack) return;
          stack = Math.max(MIN_STACK, initialWidths.stack - delta);
        }

        if (hasLeft && hasStack) {
          visuals.style.gridTemplateColumns = left + 'px minmax(0, 1fr) ' + stack + 'px';
        } else if (hasLeft) {
          visuals.style.gridTemplateColumns = left + 'px minmax(0, 1fr)';
        } else if (hasStack) {
          visuals.style.gridTemplateColumns = 'minmax(0, 1fr) ' + stack + 'px';
        }
      }

      function onUp() {
        handle.classList.remove('is-dragging');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        try {
          localStorage.setItem(RESIZE_KEY, visuals.style.gridTemplateColumns);
        } catch (_) {
          // Ignore storage failures inside restricted webview contexts.
        }
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }

      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    }

    var leftHandle = makeHandle(leftCol, 'left');
    var asmHandle = makeHandle(disasmEl, 'asm');
    leftHandle.addEventListener('mousedown', function (event) { startDrag(leftHandle, event); });
    asmHandle.addEventListener('mousedown', function (event) { startDrag(asmHandle, event); });
    initLeftPanelResize();
  }

  function initLeftPanelResize() {
    if (!root) return;
    var leftCol = root.querySelector('.left-col');
    var explainPanel = getLeftPanel('explain');
    var dumpPanel = getLeftPanel('dump');
    if (!leftCol || !explainPanel || !dumpPanel) return;

    function makeVerticalHandle() {
      var handle = document.createElement('div');
      handle.className = 'left-panel-resize-handle';
      handle.setAttribute('aria-hidden', 'true');
      handle.addEventListener('mousedown', function (event) {
        startLeftPanelDrag(handle, event);
      });
      return handle;
    }

    leftPanelResizeHandles = [makeVerticalHandle(), makeVerticalHandle()];
    leftPanelResizeHandles[0].dataset.afterPanel = 'explain';
    leftPanelResizeHandles[1].dataset.afterPanel = 'dump';
    leftCol.insertBefore(leftPanelResizeHandles[0], dumpPanel);
    leftCol.insertBefore(leftPanelResizeHandles[1], getLeftPanel('registers'));
    syncLeftPanelRows();
  }

  function startLeftPanelDrag(handle, event) {
    if (!root || handle.hidden) return;
    var previousKey = handle.dataset.previousPanel;
    var nextKey = handle.dataset.nextPanel;
    var previousPanel = getLeftPanel(previousKey);
    var nextPanel = getLeftPanel(nextKey);
    if (!previousPanel || !nextPanel) return;

    event.preventDefault();
    var startY = event.clientY;
    var previousRect = previousPanel.getBoundingClientRect();
    var nextRect = nextPanel.getBoundingClientRect();
    var initialPrevious = Math.max(LEFT_PANEL_MIN_HEIGHTS[previousKey] || 120, previousRect.height);
    var initialNext = Math.max(LEFT_PANEL_MIN_HEIGHTS[nextKey] || 120, nextRect.height);
    var pairTotal = initialPrevious + initialNext;

    handle.classList.add('is-dragging');
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';

    function onMove(moveEvent) {
      var delta = moveEvent.clientY - startY;
      var previousMin = LEFT_PANEL_MIN_HEIGHTS[previousKey] || 120;
      var nextMin = LEFT_PANEL_MIN_HEIGHTS[nextKey] || 120;
      var previousHeight = Math.max(previousMin, Math.min(pairTotal - nextMin, initialPrevious + delta));
      var nextHeight = pairTotal - previousHeight;
      leftPanelHeights[previousKey] = previousHeight;
      leftPanelHeights[nextKey] = nextHeight;
      syncLeftPanelRows();
    }

    function onUp() {
      handle.classList.remove('is-dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      writeLeftPanelHeights();
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }

  function restoreResize() {
    if (!root) return;
    var visuals = root.querySelector('.visuals');
    if (!visuals) return;
    var hasLeft = visStates.explain || visStates.dump || visStates.registers;
    if (!hasLeft || !visStates.stack) return;

    try {
      var stored = localStorage.getItem(RESIZE_KEY);
      if (!stored) return;
      var parts = stored.split(' ');
      var leftPx = parseInt(parts[0], 10);
      var stackPx = parseInt(parts[parts.length - 1], 10);
      if (!isFinite(leftPx) || !isFinite(stackPx)) return;
      leftPx = Math.max(MIN_LEFT, leftPx);
      stackPx = Math.max(MIN_STACK, stackPx);
      visuals.style.gridTemplateColumns = leftPx + 'px minmax(0, 1fr) ' + stackPx + 'px';
    } catch (_) {
      // Ignore storage failures inside restricted webview contexts.
    }
  }

  function initPresets() {
    var presets = {
      debutant: { explain: true, dump: false, registers: false, stack: true },
      debug: { explain: false, dump: true, registers: true, stack: false },
      exploit: { explain: false, dump: true, registers: false, stack: true },
      minimal: { explain: false, dump: false, registers: false, stack: false }
    };
    var select = root ? root.querySelector('#layoutPreset') : null;
    if (!select) return;

    select.addEventListener('change', function () {
      var preset = presets[select.value];
      if (preset) {
        Object.keys(preset).forEach(function (key) {
          writeVisible(STORAGE_KEYS[key], preset[key]);
          setRuntimePanelVisible(key, preset[key]);
        });
      }
      select.value = '';
    });
  }

  function init() {
    root = document.getElementById('panel-runtime');
    initToggles();
    initFocus();
    initResize();
    initPresets();
    restoreResize();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
