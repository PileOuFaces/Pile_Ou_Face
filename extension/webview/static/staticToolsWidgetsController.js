/**
 * Classic-script controller for static UI utility widgets:
 * - Offset calculator (hex/dec conversion + address arithmetic)
 * - Static tab overflow menu
 */
(function initHubStaticToolsWidgetsController(global) {
  function initStaticToolsWidgetsController() {
    function updateOffsetCalc() {
      const hexInput = document.getElementById('offsetHex');
      const decInput = document.getElementById('offsetDec');
      const baseInput = document.getElementById('offsetBase');
      const deltaInput = document.getElementById('offsetDelta');
      const resultInput = document.getElementById('offsetResult');

      function hexToDec(hex) {
        const s = String(hex).replace(/^0x/i, '').trim();
        if (!s) return null;
        const n = parseInt(s, 16);
        return isNaN(n) ? null : n;
      }

      function decToHex(dec) {
        const n = parseInt(dec, 10);
        if (isNaN(n)) return null;
        return '0x' + (n >= 0 ? n : (0xFFFFFFFF + n + 1)).toString(16);
      }

      hexInput?.addEventListener('input', () => {
        const dec = hexToDec(hexInput.value);
        if (dec !== null) decInput.value = dec;
      });

      decInput?.addEventListener('input', () => {
        const hex = decToHex(decInput.value);
        if (hex !== null) hexInput.value = hex;
      });

      function computeAddr() {
        const base = hexToDec(baseInput?.value || '0');
        const delta = hexToDec(deltaInput?.value) ?? parseInt(deltaInput?.value, 10);
        if (base === null || (delta === undefined || isNaN(delta))) return;
        resultInput.value = '0x' + (base + delta).toString(16);
      }

      baseInput?.addEventListener('input', computeAddr);
      deltaInput?.addEventListener('input', computeAddr);
    }

    const MAX_VISIBLE_TABS = 7;

    function updateTabOverflow() {
      const tabs = Array.from(document.querySelectorAll('.static-tab'));
      if (tabs.length <= MAX_VISIBLE_TABS) {
        // Remove overflow button if not needed
        const ob = document.getElementById('staticTabOverflow');
        if (ob) ob.style.display = 'none';
        tabs.forEach(t => { t.style.display = ''; });
        return;
      }
      const activeTab = tabs.find(t => t.classList.contains('active'));
      let ordered = [...tabs];
      if (activeTab) {
        ordered = [activeTab, ...ordered.filter(t => t !== activeTab)];
      }
      const visible = ordered.slice(0, MAX_VISIBLE_TABS);
      const hidden = ordered.slice(MAX_VISIBLE_TABS);
      tabs.forEach(t => { t.style.display = 'none'; });
      visible.forEach(t => { t.style.display = ''; });
      let overflowBtn = document.getElementById('staticTabOverflow');
      if (!overflowBtn) {
        overflowBtn = document.createElement('button');
        overflowBtn.id = 'staticTabOverflow';
        overflowBtn.className = 'static-tab-overflow';
        tabs[0]?.parentElement?.appendChild(overflowBtn);
      }
      overflowBtn.style.display = '';
      overflowBtn.textContent = '⋯ (' + hidden.length + ')';
      overflowBtn.onclick = (e) => {
        e.stopPropagation();
        let menu = document.getElementById('staticTabOverflowMenu');
        if (menu) { menu.remove(); return; }
        menu = document.createElement('div');
        menu.id = 'staticTabOverflowMenu';
        menu.className = 'static-tab-overflow-menu';
        hidden.forEach(t => {
          const item = document.createElement('button');
          item.className = 'overflow-menu-item';
          item.textContent = t.textContent;
          item.addEventListener('click', () => { t.click(); menu.remove(); });
          menu.appendChild(item);
        });
        overflowBtn.parentElement?.appendChild(menu);
        document.addEventListener('click', () => menu.remove(), { once: true });
      };
    }

    function init() {
      updateOffsetCalc();

      // Calculette: Enter, copier résultat
      document.getElementById('offsetBase')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
      document.getElementById('offsetDelta')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
      document.getElementById('offsetResult')?.addEventListener('click', () => {
        const v = document.getElementById('offsetResult')?.value;
        if (v && navigator.clipboard) navigator.clipboard.writeText(v).then(() => { /* ok */ });
      });
      document.getElementById('offsetResult')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.preventDefault(); });
    }

    return { init, updateOffsetCalc, updateTabOverflow };
  }

  const api = { initStaticToolsWidgetsController };
  global.POFHubStaticToolsWidgetsController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.staticToolsWidgetsController = api;
  }
})(window);
