/**
 * Classic-script controller for architecture support badge and tooltip rendering.
 * Reads arch support data via getCurrentArchSupport() — does not own that state.
 */
(function initHubArchBadgeController(global) {
  function initArchBadgeController({ getCurrentArchSupport, getTabFeatures }) {
    const FEATURE_LABELS = {
      disasm: 'Désassemblage',
      cfg: 'CFG',
      call_graph: 'Call Graph',
      discover_functions: 'Découverte fonctions',
      stack_frame: 'Stack Frame',
      calling_convention: "Convention d'appel",
      xrefs: 'Références croisées',
    };
    const _SUPPORT_RANK = { full: 3, partial: 2, 'disasm-only': 1, unsupported: 0 };

    function _worstSupportEntry(features) {
      const archSupport = getCurrentArchSupport();
      if (!archSupport?.support) return null;
      let worst = null;
      for (const f of features) {
        const entry = archSupport.support[f];
        if (!entry) continue;
        if (!worst || (_SUPPORT_RANK[entry.level] ?? 0) < (_SUPPORT_RANK[worst.level] ?? 0)) worst = entry;
      }
      return worst;
    }

    // Tooltip body-level pour éviter le clipping par overflow:hidden des parents
    let _archTooltipEl = null;
    function _getArchTooltipEl() {
      if (!_archTooltipEl) {
        _archTooltipEl = document.createElement('div');
        _archTooltipEl.className = 'arch-support-tooltip';
        _archTooltipEl.style.display = 'none';
        document.body.appendChild(_archTooltipEl);
      }
      return _archTooltipEl;
    }

    function showTooltip(badge, features) {
      const archSupport = getCurrentArchSupport();
      if (!archSupport?.support) return;
      const tip = _getArchTooltipEl();
      tip.replaceChildren();
      const arch = archSupport.display_name || archSupport.key || '';
      if (arch) {
        const header = document.createElement('span');
        header.className = 'arch-support-tooltip-arch';
        header.textContent = arch;
        tip.appendChild(header);
      }
      for (const f of features) {
        const entry = archSupport.support[f];
        if (!entry) continue;
        const row = document.createElement('div');
        row.className = 'arch-support-tooltip-row';
        const dot = document.createElement('span');
        dot.className = `arch-support-tooltip-dot arch-support-${entry.level}`;
        const label = document.createElement('span');
        label.className = 'arch-support-tooltip-label';
        label.textContent = FEATURE_LABELS[f] || f;
        const lvl = document.createElement('span');
        lvl.className = `arch-support-tooltip-level arch-support-level-${entry.level}`;
        lvl.textContent = entry.level;
        row.appendChild(dot);
        row.appendChild(label);
        row.appendChild(lvl);
        if (entry.note) {
          const note = document.createElement('div');
          note.className = 'arch-support-tooltip-note';
          note.textContent = entry.note;
          row.appendChild(note);
        }
        tip.appendChild(row);
      }
      tip.style.display = 'flex';
      const rect = badge.getBoundingClientRect();
      const tw = tip.offsetWidth;
      let left = rect.left + rect.width / 2 - tw / 2;
      left = Math.max(6, Math.min(left, window.innerWidth - tw - 6));
      tip.style.left = `${left}px`;
      tip.style.top = `${rect.top - tip.offsetHeight - 8 + window.scrollY}px`;
    }

    function hideTooltip() {
      if (_archTooltipEl) _archTooltipEl.style.display = 'none';
    }

    function buildArchBadge(features) {
      const archSupport = getCurrentArchSupport();
      if (!archSupport?.support) return null;
      const worst = _worstSupportEntry(features);
      if (!worst || worst.level === 'full') return null;
      const badge = document.createElement('span');
      badge.className = `arch-support-badge arch-support-${worst.level}`;
      badge.setAttribute('aria-label', `Support ${worst.level}`);
      badge.addEventListener('mouseenter', () => showTooltip(badge, features));
      badge.addEventListener('mouseleave', hideTooltip);
      return badge;
    }

    function refreshBadges() {
      const bar = document.getElementById('subTabsBar');
      if (!bar) return;
      bar.querySelectorAll('.sub-tab').forEach((btn) => {
        btn.querySelectorAll('.arch-support-badge').forEach((b) => b.remove());
        const tid = btn.dataset.subTab;
        const badge = buildArchBadge(getTabFeatures ? getTabFeatures(tid) : []);
        if (badge) btn.appendChild(badge);
      });
    }

    return { buildArchBadge, showTooltip, hideTooltip, refreshBadges };
  }

  const api = { initArchBadgeController };
  global.POFHubArchBadgeController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.archBadgeController = api;
  }
})(window);
