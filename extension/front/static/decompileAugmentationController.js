(function (root) {
  'use strict';

  function flattenItems(proposal) {
    const items = [];
    if (proposal?.summary) items.push({ id: 'summary', text: proposal.summary, kind: 'summary' });
    for (const kind of ['renames', 'comments', 'types']) {
      for (const item of proposal?.[kind] || []) items.push({ ...item, kind });
    }
    if (proposal?.prototype) items.push({ ...proposal.prototype, kind: 'prototype' });
    return items;
  }

  function itemLabel(item) {
    if (item.kind === 'summary') return `Résumé : ${item.text}`;
    if (item.kind === 'renames') return `${item.from} → ${item.to}`;
    if (item.kind === 'comments') return `Commentaire : ${item.text}`;
    if (item.kind === 'types') return `${item.name} : ${item.type}`;
    return `Prototype : ${item.value}`;
  }

  function createController(options) {
    const document = options.document;
    const postMessage = options.postMessage;
    const state = { source: null, result: null, loading: false, view: 'augmented' };
    const el = (id) => document.getElementById(id);

    function setStatus(text, tone) {
      const node = el('decompileAugmentStatus');
      if (!node) return;
      node.textContent = text || '';
      node.dataset.tone = tone || '';
    }

    function setBusy(value) {
      state.loading = Boolean(value);
      const button = el('btnAugmentDecompile');
      if (button) {
        button.disabled = state.loading || !state.source?.addr;
        button.textContent = state.loading ? '✦ Analyse…' : '✦ Augmenter';
      }
    }

    function renderCode() {
      const code = el('decompileAugmentCode');
      if (!code || !state.result) return;
      code.textContent = state.view === 'raw' ? state.result.raw_code : state.result.augmented_code;
      for (const button of document.querySelectorAll('[data-augment-view]')) {
        button.classList.toggle('active', button.dataset.augmentView === state.view);
      }
    }

    function renderResult(result) {
      state.result = result;
      const panel = el('decompileAugmentReview');
      const list = el('decompileAugmentSuggestions');
      if (!panel || !list) return;
      list.replaceChildren();
      const items = flattenItems(result.proposal);
      for (const item of items) {
        const label = document.createElement('label');
        label.className = 'decompile-augment-suggestion';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = result.accepted_ids?.length ? result.accepted_ids.includes(item.id) : true;
        checkbox.dataset.suggestionId = item.id;
        const body = document.createElement('span');
        const title = document.createElement('strong');
        title.textContent = itemLabel(item);
        const reason = document.createElement('small');
        reason.textContent = item.reason || '';
        body.append(title, reason);
        label.append(checkbox, body);
        list.appendChild(label);
      }
      panel.hidden = false;
      const summary = el('decompileAugmentSummary');
      if (summary) summary.textContent = result.proposal?.summary || `${items.length} suggestion(s)`;
      setStatus(result.cached ? 'Proposition chargée depuis le cache.' : 'Proposition prête à vérifier.', 'success');
      renderCode();
    }

    function request() {
      if (!state.source?.addr || state.loading) return false;
      setBusy(true);
      setStatus('Analyse structurée en cours…', 'progress');
      postMessage({ type: 'hubAugmentDecompile', ...state.source });
      return true;
    }

    function accept() {
      if (!state.result || state.loading) return false;
      const selectedIds = Array.from(document.querySelectorAll('[data-suggestion-id]:checked'))
        .map((node) => node.dataset.suggestionId);
      if (!selectedIds.length) {
        setStatus('Sélectionnez au moins une suggestion.', 'warning');
        return false;
      }
      setBusy(true);
      setStatus('Enregistrement de la sélection…', 'progress');
      postMessage({
        type: 'hubAcceptDecompileAugmentation',
        cacheKey: state.result.cache_key,
        selectedIds,
        binaryPath: state.source.binaryPath,
        addr: state.source.addr,
      });
      return true;
    }

    function setSource(source) {
      const changed = !state.source
        || state.source.binaryPath !== source?.binaryPath
        || state.source.addr !== source?.addr
        || state.source.code !== source?.code;
      state.source = source?.addr ? { ...source } : null;
      if (changed) {
        state.result = null;
        const panel = el('decompileAugmentReview');
        if (panel) panel.hidden = true;
        setStatus(state.source ? 'Optionnel : obtenez des noms, types et commentaires proposés par l’IA.' : 'Sélectionnez une fonction pour activer l’augmentation.', '');
      }
      setBusy(false);
    }

    function receive(message) {
      if (message.type !== 'hubDecompileAugmented') return false;
      setBusy(false);
      if (!message.ok) {
        setStatus(message.error || 'Augmentation impossible.', 'error');
        return true;
      }
      renderResult(message.result);
      if (message.accepted) setStatus('Sélection enregistrée et réutilisable.', 'success');
      return true;
    }

    function bind() {
      el('btnAugmentDecompile')?.addEventListener('click', request);
      el('btnAcceptDecompileAugment')?.addEventListener('click', accept);
      for (const button of document.querySelectorAll('[data-augment-view]')) {
        button.addEventListener('click', () => {
          state.view = button.dataset.augmentView;
          renderCode();
        });
      }
      setBusy(false);
    }

    return { accept, bind, flattenItems, receive, request, setSource, state };
  }

  function mountController(target) {
    const vscodeApi = target?.POFHubMessageBus?.vscode;
    if (!target?.document || !vscodeApi) return null;
    const controller = createController({
      document: target.document,
      postMessage: (message) => vscodeApi.postMessage(message),
    });
    controller.bind();
    target.decompileAugmentationController = controller;
    return controller;
  }

  const api = { createController, flattenItems, itemLabel, mountController };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  mountController(root);
})(typeof window !== 'undefined' ? window : globalThis);
