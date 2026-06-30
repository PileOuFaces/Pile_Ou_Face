// ── Outils sub-tabs ──────────────────────────────────────────────────────────
let activeAiRequestId = '';
let activeConversationRevisionBackup = null;

function showOutilsTab(tabId) {
  document.querySelectorAll('.outils-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.outils-panel').forEach((p) => p.classList.remove('active'));
  const panelId = 'outilsPanel' + tabId.charAt(0).toUpperCase() + tabId.slice(1);
  document.getElementById(panelId)?.classList.add('active');
  if (tabId === 'fichiers') vscode.postMessage({ type: 'listGeneratedFiles' });
  _saveStorage({ outilsTab: tabId });
}

document.querySelectorAll('.outils-tab').forEach((btn) => {
  btn.addEventListener('click', () => showOutilsTab(btn.dataset.tab));
});

function setOllamaBusy(busy) {
  ollamaUiState.busy = !!busy;
  const runBtn = document.getElementById('btnOllamaRunPrompt');
  const refreshBtn = document.getElementById('btnOllamaRefreshModels');
  const clearHistoryBtn = document.getElementById('btnOllamaClearHistory');
  const quickRunBtn = document.getElementById('btnOllamaQuickSend');
  const quickRefreshBtn = document.getElementById('btnOllamaQuickRefresh');
  if (runBtn) {
    runBtn.disabled = ollamaUiState.busy;
    runBtn.classList.toggle('loading', ollamaUiState.busy);
  }
  if (refreshBtn) refreshBtn.disabled = ollamaUiState.busy;
  document.querySelectorAll('[data-ollama-new-conversation="true"]').forEach((button) => {
    button.disabled = ollamaUiState.busy;
  });
  if (clearHistoryBtn) clearHistoryBtn.disabled = ollamaUiState.busy;
  if (quickRunBtn) quickRunBtn.disabled = ollamaUiState.busy;
  if (quickRefreshBtn) quickRefreshBtn.disabled = ollamaUiState.busy;
  document.querySelectorAll('[data-ollama-cancel="true"]').forEach((button) => {
    button.hidden = !ollamaUiState.busy;
    button.disabled = !ollamaUiState.busy;
  });
  document.querySelectorAll('[data-ollama-message-action="true"]').forEach((button) => {
    button.disabled = ollamaUiState.busy;
  });
  document.querySelectorAll('[data-ollama-export="true"]').forEach((button) => {
    button.disabled = ollamaUiState.busy || !ollamaUiState.conversation.length;
  });
  document.querySelectorAll('[data-ollama-history-action="true"]').forEach((button) => {
    button.disabled = ollamaUiState.busy;
  });
  document.querySelectorAll('[data-ai-generation-scope="true"], [data-ai-generation-key]').forEach(
    (control) => {
      const isConversationValue = control.matches('[data-ai-generation-key]');
      const entry = getActiveOllamaHistoryEntry();
      control.disabled = ollamaUiState.busy || (isConversationValue && !entry?.generationSettings);
    },
  );
}

function setOllamaStatus(text, isError = false) {
  const targets = Array.from(document.querySelectorAll('[data-ollama-status="true"]'));
  if (!targets.length) {
    const fallback = document.getElementById('ollamaPromptStatus');
    if (fallback) targets.push(fallback);
  }
  targets.forEach((el) => {
    el.textContent = text || '';
    el.classList.toggle('error', !!isError);
  });
}

function formatOllamaRoleLabel(role, model) {
  if (role === 'user') return 'Toi';
  if (role === 'assistant') return model || 'IA';
  return 'Système';
}

const OLLAMA_SCROLL_FOLLOW_THRESHOLD_PX = 48;

function shouldFollowOllamaStream(history) {
  if (!history) return false;
  const distanceFromBottom =
    history.scrollHeight - history.clientHeight - history.scrollTop;
  return distanceFromBottom <= OLLAMA_SCROLL_FOLLOW_THRESHOLD_PX;
}

function restoreOllamaScroll(history, shouldFollow, previousScrollTop = 0) {
  if (!history) return;
  history.scrollTop = shouldFollow ? history.scrollHeight : previousScrollTop;
}

function showOllamaTypingIndicator(modelName) {
  hideOllamaTypingIndicator();
  const targets = Array.from(document.querySelectorAll('[data-ollama-chat-history="true"]'));
  targets.forEach((el) => {
    const shouldFollow = shouldFollowOllamaStream(el);
    const wrap = document.createElement('article');
    wrap.className = 'ollama-chat-message assistant';
    wrap.dataset.typingIndicator = 'true';
    const role = document.createElement('span');
    role.className = 'ollama-chat-role';
    role.textContent = modelName || '…';
    const dots = document.createElement('div');
    dots.className = 'ollama-typing-dots';
    for (let i = 0; i < 3; i++) dots.appendChild(document.createElement('span'));
    wrap.append(role, dots);
    el.appendChild(wrap);
    if (shouldFollow) el.scrollTop = el.scrollHeight;
  });
}

function hideOllamaTypingIndicator() {
  document.querySelectorAll('[data-typing-indicator="true"]').forEach((el) => el.remove());
}

/**
 * Insert or update a live tool call badge in the streaming bubble.
 * ok === null → pending (spinner dots), ok === true/false → done (✓ / ✗).
 */
function upsertStreamingToolBubble(name, ok) {
  const targets = Array.from(document.querySelectorAll('[data-ollama-chat-history="true"]'));
  targets.forEach((history) => {
    const shouldFollow = shouldFollowOllamaStream(history);
    let container = history.querySelector('[data-streaming-tools="true"]');
    if (!container) {
      container = document.createElement('article');
      container.className = 'ollama-chat-message system';
      container.dataset.streamingTools = 'true';
      const label = document.createElement('span');
      label.className = 'ollama-chat-role';
      label.textContent = 'Outils MCP';
      container.appendChild(label);
      // Insert before typing indicator if present, otherwise append
      const typingEl = history.querySelector('[data-typing-indicator="true"]');
      if (typingEl) history.insertBefore(container, typingEl);
      else history.appendChild(container);
    }
    let badge = container.querySelector(`[data-tool-name="${CSS.escape(name)}"]`);
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'ollama-tool-badge pending';
      badge.dataset.toolName = name;
      container.appendChild(badge);
    }
    if (ok === null) {
      badge.className = 'ollama-tool-badge pending';
      badge.textContent = name + ' …';
    } else {
      badge.className = `ollama-tool-badge ${ok ? 'ok' : 'err'}`;
      badge.textContent = name + (ok ? ' ✓' : ' ✗');
    }
    if (shouldFollow) history.scrollTop = history.scrollHeight;
  });
}

/** Remove the live streaming container — called when hubOllamaResult arrives. */
function finalizeStreamingToolBubbles() {
  document.querySelectorAll('[data-streaming-tools="true"]').forEach((el) => el.remove());
}

let _streamingResponseLocked = false;
const _streamTokenQueue = [];
let _streamRafId = null;
let _pendingResultCallback = null;
let _streamFragmentCount = 0;
let _renderedStreamChars = 0;

function ensureStreamingResponseBubbles() {
  if (_streamingResponseLocked) return false;
  const targets = Array.from(document.querySelectorAll('[data-ollama-chat-history="true"]'));
  targets.forEach((history) => {
    let bubble = history.querySelector('[data-streaming-response="true"]');
    if (!bubble) {
      bubble = document.createElement('div');
      bubble.className = 'ollama-chat-message assistant';
      bubble.dataset.streamingResponse = 'true';
      const role = document.createElement('div');
      role.className = 'ollama-chat-role';
      role.textContent = 'assistant · LIVE';
      bubble.appendChild(role);
      const meta = document.createElement('div');
      meta.className = 'ollama-stream-meta';
      meta.textContent = '0 fragment · 0 caractère';
      bubble.appendChild(meta);
      const content = document.createElement('div');
      content.className = 'ollama-chat-content';
      bubble.appendChild(content);
      const typingEl = history.querySelector('[data-typing-indicator="true"]');
      if (typingEl) history.insertBefore(bubble, typingEl);
      else history.appendChild(bubble);
    }
  });
  return targets.length > 0;
}

function _drainStreamToken() {
  _streamRafId = null;
  const content = _streamTokenQueue.splice(0).join('');
  if (content) {
    const bubbles = Array.from(
      document.querySelectorAll('[data-streaming-response="true"]'),
    );
    bubbles.forEach((bubble) => {
      const history = bubble.parentElement;
      const shouldFollow = shouldFollowOllamaStream(history);
      const contentEl = bubble.querySelector('.ollama-chat-content');
      if (contentEl) {
        contentEl.textContent += content;
        _renderedStreamChars = contentEl.textContent.length;
      }
      const metaEl = bubble.querySelector('.ollama-stream-meta');
      if (metaEl) {
        metaEl.textContent =
          `${_streamFragmentCount} fragments · ${_renderedStreamChars} caractères`;
      }
      if (shouldFollow && history) history.scrollTop = history.scrollHeight;
    });
  }
  if (_streamTokenQueue.length > 0) {
    _streamRafId = setTimeout(_drainStreamToken, 16);
  } else if (_pendingResultCallback) {
    // All fragments are visible before the final conversation render.
    const cb = _pendingResultCallback;
    _pendingResultCallback = null;
    cb();
  }
}

function appendStreamingToken(content, fragmentCount = 1) {
  const isFirstStreamBatch = _streamFragmentCount === 0;
  _streamFragmentCount += Math.max(1, Number(fragmentCount) || 1);
  if (isFirstStreamBatch) hideOllamaTypingIndicator();
  setOllamaStatus(
    `● STREAM LIVE — ${_streamFragmentCount} fragments reçus · ${_renderedStreamChars} caractères affichés`,
  );
  if (!ensureStreamingResponseBubbles()) return;
  _streamTokenQueue.push(content);
  if (_streamRafId === null) {
    _streamRafId = setTimeout(_drainStreamToken, 16);
  }
}

/**
 * If token fragments are waiting for the next paint, defer the callback until
 * the last token is on screen. Otherwise call it immediately.
 */
function queueOrHandleOllamaResult(callback) {
  if (_streamRafId !== null || _streamTokenQueue.length > 0) {
    _pendingResultCallback = callback;
  } else {
    callback();
  }
}

function _cancelStreamQueue() {
  if (_streamRafId !== null) {
    clearTimeout(_streamRafId);
    _streamRafId = null;
  }
  _streamTokenQueue.length = 0;
  _pendingResultCallback = null;
}

function rollbackStreamingTokens() {
  _cancelStreamQueue();
  _streamFragmentCount = 0;
  _renderedStreamChars = 0;
  document.querySelectorAll('[data-streaming-response="true"]').forEach((el) => el.remove());
}

function finalizeStreamingResponseBubbles() {
  _streamingResponseLocked = true;
  _cancelStreamQueue();
  document.querySelectorAll('[data-streaming-response="true"]').forEach((el) => {
    el.removeAttribute('data-streaming-response');
  });
}

function createOllamaConversationId() {
  return `conv-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

function buildOllamaConversationTitle(messages = []) {
  const firstUser = messages.find((item) => item?.role === 'user' && item?.content);
  const fallback = messages.find((item) => item?.content);
  const source = String(firstUser?.content || fallback?.content || '').trim();
  if (!source) return 'Nouvelle discussion';
  return source.length > 72 ? `${source.slice(0, 72)}...` : source;
}

function formatOllamaHistoryTime(ts) {
  const date = new Date(Number(ts || Date.now()));
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function normalizeStoredOllamaHistory(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const normalized = [];
  raw.forEach((entry) => {
    const id = String(entry?.id || '').trim();
    if (!id || seen.has(id)) return;
    seen.add(id);
    const messages = _normalizeOllamaConversationMessages(entry?.messages);
    const updatedAt = Number(entry?.updatedAt || Date.now());
    const title = String(entry?.title || '').trim() || buildOllamaConversationTitle(messages);
    normalized.push({
      id,
      title,
      customTitle: entry?.customTitle === true,
      generationSettings: entry?.generationSettings
        ? window.POFAiGenerationSettings.normalize(entry.generationSettings)
        : null,
      updatedAt: Number.isFinite(updatedAt) ? updatedAt : Date.now(),
      messages,
      model: String(entry?.model || '').trim(),
    });
  });
  normalized.sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
  return normalized.slice(0, OLLAMA_HISTORY_MAX_THREADS);
}

function syncActiveOllamaConversationInHistory(touch = true) {
  if (!ollamaUiState.activeConversationId) {
    ollamaUiState.activeConversationId = createOllamaConversationId();
  }
  const currentId = ollamaUiState.activeConversationId;
  const now = Date.now();
  const existing = ollamaUiState.history.find((entry) => entry.id === currentId);
  if (!existing) {
    ollamaUiState.history.unshift({
      id: currentId,
      title: buildOllamaConversationTitle(ollamaUiState.conversation),
      customTitle: false,
      generationSettings: null,
      updatedAt: now,
      messages: [...ollamaUiState.conversation],
      model: getCurrentOllamaModel() || ollamaUiState.lastModel || '',
    });
  } else {
    existing.messages = [...ollamaUiState.conversation];
    if (!existing.customTitle) {
      existing.title = buildOllamaConversationTitle(existing.messages);
    }
    existing.model = getCurrentOllamaModel() || ollamaUiState.lastModel || existing.model || '';
    if (touch) existing.updatedAt = now;
  }
  ollamaUiState.history.sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
  if (ollamaUiState.history.length > OLLAMA_HISTORY_MAX_THREADS) {
    ollamaUiState.history = ollamaUiState.history.slice(0, OLLAMA_HISTORY_MAX_THREADS);
  }
}

function persistOllamaConversation() {
  _saveStorage({
    ollamaConversation: ollamaUiState.conversation,
    ollamaConversationHistory: ollamaUiState.history,
    ollamaActiveConversationId: ollamaUiState.activeConversationId,
  });
}

function hydrateOllamaConversationHistory() {
  const stored = _loadStorage();
  let history = normalizeStoredOllamaHistory(stored.ollamaConversationHistory);
  let changed = false;
  if (!history.length) {
    const legacyMessages = _normalizeOllamaConversationMessages(stored.ollamaConversation);
    history = [
      {
        id: createOllamaConversationId(),
        title: buildOllamaConversationTitle(legacyMessages),
        customTitle: false,
        generationSettings: null,
        updatedAt: Date.now(),
        messages: legacyMessages,
        model: String(stored.ollamaModel || '').trim(),
      },
    ];
    changed = true;
  }
  const savedActiveId = String(stored.ollamaActiveConversationId || '').trim();
  let active = history.find((entry) => entry.id === savedActiveId) || history[0];
  if (!active) {
    active = {
      id: createOllamaConversationId(),
      title: 'Nouvelle discussion',
      customTitle: false,
      generationSettings: null,
      updatedAt: Date.now(),
      messages: [],
      model: String(stored.ollamaModel || '').trim(),
    };
    history = [active];
    changed = true;
  }
  ollamaUiState.history = history;
  ollamaUiState.activeConversationId = active.id;
  ollamaUiState.conversation = _normalizeOllamaConversationMessages(active.messages);
  if (changed) persistOllamaConversation();
}

function switchOllamaConversation(conversationId) {
  if (ollamaUiState.busy) return;
  const id = String(conversationId || '').trim();
  if (!id || id === ollamaUiState.activeConversationId) return;
  const target = ollamaUiState.history.find((entry) => entry.id === id);
  if (!target) return;
  syncActiveOllamaConversationInHistory(false);
  ollamaUiState.activeConversationId = target.id;
  ollamaUiState.conversation = _normalizeOllamaConversationMessages(target.messages);
  if (target.model) {
    rememberOllamaModel(target.model, true);
    renderOllamaModels(ollamaUiState.models, target.model);
  }
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
  setOllamaStatus(`Conversation chargée: ${target.title || 'sans titre'}`);
}

function renameOllamaConversation(conversationId, nextTitle) {
  if (ollamaUiState.busy) return false;
  const entry = ollamaUiState.history.find((item) => item.id === conversationId);
  const title = window.POFChatHistory?.normalizeConversationTitle(nextTitle) || '';
  if (!entry || !title) return false;
  entry.title = title;
  entry.customTitle = true;
  persistOllamaConversation();
  renderOllamaConversationHistory();
  setOllamaStatus(`Conversation renommée : ${title}`);
  return true;
}

function showOllamaConversationRename(item, entry) {
  if (ollamaUiState.busy || !item || !entry) return;
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'input-inner ollama-history-rename-input';
  input.value = entry.title || '';
  input.maxLength = 80;
  input.setAttribute('aria-label', 'Nouveau titre de la conversation');
  const actions = document.createElement('div');
  actions.className = 'ollama-history-rename-actions';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'btn btn-secondary btn-sm';
  cancel.textContent = 'Annuler';
  cancel.addEventListener('click', renderOllamaConversationHistory);
  const save = document.createElement('button');
  save.type = 'button';
  save.className = 'btn btn-primary btn-sm';
  save.textContent = 'Enregistrer';
  const submit = () => {
    if (!renameOllamaConversation(entry.id, input.value)) {
      input.focus();
      setOllamaStatus('Le titre de la conversation ne peut pas être vide.', true);
    }
  };
  save.addEventListener('click', submit);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      renderOllamaConversationHistory();
    } else if (event.key === 'Enter') {
      event.preventDefault();
      submit();
    }
  });
  actions.append(cancel, save);
  item.replaceChildren(input, actions);
  input.focus();
  input.select();
}

function renderOllamaConversationHistory() {
  const el = document.getElementById('ollamaConversationHistoryList');
  if (!el) return;
  el.replaceChildren();
  if (!ollamaUiState.history.length) {
    const empty = document.createElement('p');
    empty.className = 'ollama-history-empty';
    empty.textContent = 'Pas encore de conversations enregistrées.';
    el.appendChild(empty);
    return;
  }
  const visibleHistory = window.POFChatHistory?.filterAndSortConversations(
    ollamaUiState.history,
    ollamaUiState.historyQuery,
    ollamaUiState.historySort,
  ) || [...ollamaUiState.history];
  if (!visibleHistory.length) {
    const empty = document.createElement('p');
    empty.className = 'ollama-history-empty';
    empty.textContent = 'Aucune conversation ne correspond à cette recherche.';
    el.appendChild(empty);
    return;
  }
  const frag = document.createDocumentFragment();
  visibleHistory.forEach((entry) => {
    const item = document.createElement('div');
    item.className = 'ollama-history-item';
    if (entry.id === ollamaUiState.activeConversationId) item.classList.add('active');
    item.dataset.conversationId = entry.id;
    const open = document.createElement('button');
    open.type = 'button';
    open.className = 'ollama-history-open';
    open.dataset.ollamaHistoryAction = 'true';
    open.disabled = ollamaUiState.busy;
    open.title = entry.title;
    const title = document.createElement('span');
    title.className = 'ollama-history-title';
    title.textContent = entry.title || 'Nouvelle discussion';
    const meta = document.createElement('span');
    meta.className = 'ollama-history-meta';
    const messages = Array.isArray(entry.messages) ? entry.messages : [];
    const messageCount = messages.length;
    const totalTokens = getOllamaConversationUsage(messages).requestTotalTokens;
    meta.textContent = `${messageCount} msg • ${totalTokens} tok • ${formatOllamaHistoryTime(entry.updatedAt)}`;
    open.append(title, meta);
    open.addEventListener('click', () => switchOllamaConversation(entry.id));
    const itemActions = document.createElement('div');
    itemActions.className = 'ollama-history-item-actions';
    const rename = document.createElement('button');
    rename.type = 'button';
    rename.className = 'ollama-history-item-action';
    rename.dataset.ollamaHistoryAction = 'true';
    rename.disabled = ollamaUiState.busy;
    rename.textContent = '✎';
    rename.title = 'Renommer cette conversation';
    rename.setAttribute('aria-label', `Renommer ${entry.title || 'cette conversation'}`);
    rename.addEventListener('click', () => showOllamaConversationRename(item, entry));
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'ollama-history-remove';
    remove.dataset.ollamaHistoryAction = 'true';
    remove.disabled = ollamaUiState.busy;
    remove.textContent = '×';
    remove.title = 'Supprimer cette conversation';
    remove.setAttribute('aria-label', `Supprimer ${entry.title || 'cette conversation'}`);
    remove.addEventListener('click', () => deleteOllamaConversation(entry.id));
    itemActions.append(rename, remove);
    item.append(open, itemActions);
    frag.appendChild(item);
  });
  el.appendChild(frag);
}

function normalizeOllamaUsage(raw) {
  const usage = raw && typeof raw === 'object' ? raw : {};
  const promptTokens = Math.max(0, Number(usage.promptTokens || usage.prompt_tokens || 0));
  const completionTokens = Math.max(0, Number(usage.completionTokens || usage.completion_tokens || 0));
  const reportedTotal = Math.max(0, Number(usage.totalTokens || usage.total_tokens || 0));
  const requestTotalTokens = Math.max(
    0,
    Number(usage.requestTotalTokens || usage.request_total_tokens || 0),
  );
  const requestPromptTokens = Math.max(
    0,
    Number(usage.requestPromptTokens || usage.request_prompt_tokens || 0),
  );
  const requestCompletionTokens = Math.max(
    0,
    Number(usage.requestCompletionTokens || usage.request_completion_tokens || 0),
  );
  const hasRequestBreakdown = (
    requestPromptTokens > 0
    || requestCompletionTokens > 0
    || requestTotalTokens === promptTokens + completionTokens
  );
  return {
    promptTokens,
    completionTokens,
    totalTokens: reportedTotal || promptTokens + completionTokens,
    requestPromptTokens: requestPromptTokens || promptTokens,
    requestCompletionTokens: requestCompletionTokens || completionTokens,
    requestTotalTokens: requestTotalTokens || reportedTotal || promptTokens + completionTokens,
    hasRequestBreakdown,
  };
}

function formatOllamaTokenCount(value) {
  return Math.max(0, Number(value || 0)).toLocaleString('fr-FR');
}

function getOllamaConversationUsage(messages = ollamaUiState.conversation) {
  return (Array.isArray(messages) ? messages : []).reduce(
    (total, entry) => {
      const usage = normalizeOllamaUsage(entry?.usage);
      total.promptTokens += usage.requestPromptTokens;
      total.completionTokens += usage.requestCompletionTokens;
      total.totalTokens += usage.totalTokens;
      total.requestTotalTokens += usage.requestTotalTokens;
      total.hasCompleteBreakdown = total.hasCompleteBreakdown && usage.hasRequestBreakdown;
      return total;
    },
    {
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      requestTotalTokens: 0,
      hasCompleteBreakdown: true,
    },
  );
}

function renderOllamaConversationUsage() {
  const usage = getOllamaConversationUsage();
  const cost = window.POFAiPricing.estimateConversationCost(
    ollamaUiState.conversation,
    ollamaUiState.pricingRules,
    normalizeOllamaUsage,
  );
  document.querySelectorAll('[data-ollama-conversation-usage="true"]').forEach((el) => {
    if (!usage.requestTotalTokens) {
      el.textContent = '0 token consommé';
    } else if (usage.hasCompleteBreakdown) {
      el.textContent = [
        'Conversation',
        `${formatOllamaTokenCount(usage.promptTokens)} entrée`,
        `${formatOllamaTokenCount(usage.completionTokens)} sortie`,
        `${formatOllamaTokenCount(usage.requestTotalTokens)} total`,
      ].join(' · ');
    } else {
      el.textContent =
        `Conversation · ${formatOllamaTokenCount(usage.requestTotalTokens)} total`;
    }
    if (cost.pricedMessages) {
      const partial = cost.unpricedMessages ? ' partiel' : '';
      el.textContent += ` · coût${partial} ~${window.POFAiPricing.formatUsd(cost.totalCost)}`;
    } else if (cost.unpricedMessages) {
      el.textContent += ' · coût non configuré';
    }
    el.title = usage.requestTotalTokens
      ? (
          usage.hasCompleteBreakdown
            ? 'Consommation cumulée de cette conversation'
            : 'Le détail entrée/sortie est indisponible pour certains anciens messages'
        )
      : 'Aucun token consommé dans cette conversation';
    if (cost.unpricedMessages) {
      el.title += ` · ${cost.unpricedMessages} réponse(s) sans tarif correspondant`;
    }
  });
}

function getActiveOllamaHistoryEntry() {
  return ollamaUiState.history.find(
    (entry) => entry.id === ollamaUiState.activeConversationId,
  ) || null;
}

function getOllamaGenerationSettings() {
  const entry = getActiveOllamaHistoryEntry();
  return window.POFAiGenerationSettings.normalize(
    entry?.generationSettings || ollamaUiState.globalGenerationSettings,
    ollamaUiState.globalGenerationSettings,
  );
}

function renderOllamaGenerationSettings() {
  const entry = getActiveOllamaHistoryEntry();
  const usesConversationSettings = !!entry?.generationSettings;
  const settings = getOllamaGenerationSettings();
  document.querySelectorAll('[data-ai-generation-scope="true"]').forEach((select) => {
    select.value = usesConversationSettings ? 'conversation' : 'global';
    select.disabled = ollamaUiState.busy;
  });
  document.querySelectorAll('[data-ai-generation-key]').forEach((input) => {
    const key = input.dataset.aiGenerationKey;
    input.value = String(settings[key]);
    input.disabled = ollamaUiState.busy || !usesConversationSettings;
    input.title = usesConversationSettings
      ? 'Valeur propre à cette conversation'
      : 'Valeur globale — modifiable dans Options > Intelligence artificielle';
  });
}

function applyGlobalAiGenerationSettings(settings = {}) {
  ollamaUiState.globalGenerationSettings =
    window.POFAiGenerationSettings.fromGlobalSettings(settings);
  renderOllamaGenerationSettings();
}

function applyGlobalAiPricingRules(rules = []) {
  ollamaUiState.pricingRules = window.POFAiPricing.normalizeRules(rules);
  renderOllamaConversation();
}

function setOllamaGenerationScope(scope) {
  if (ollamaUiState.busy) return;
  syncActiveOllamaConversationInHistory(false);
  const entry = getActiveOllamaHistoryEntry();
  if (!entry) return;
  entry.generationSettings = scope === 'conversation'
    ? { ...getOllamaGenerationSettings() }
    : null;
  persistOllamaConversation();
  renderOllamaGenerationSettings();
}

function updateOllamaConversationGenerationSetting(key, value) {
  if (ollamaUiState.busy) return;
  const entry = getActiveOllamaHistoryEntry();
  if (!entry?.generationSettings || !['temperature', 'top_p', 'max_tokens'].includes(key)) {
    return;
  }
  entry.generationSettings = window.POFAiGenerationSettings.normalize({
    ...entry.generationSettings,
    [key]: value,
  }, ollamaUiState.globalGenerationSettings);
  persistOllamaConversation();
  renderOllamaGenerationSettings();
}

function getOllamaContextBudget(messages = ollamaUiState.conversation) {
  return window.POFChatContextBudget.buildContextWindow(messages, {
    maxMessages: OLLAMA_CHAT_CONTEXT_MESSAGES,
    maxChars: OLLAMA_CHAT_CONTEXT_MAX_CHARS,
    maxMessageChars: 700,
  });
}

function renderOllamaContextBudget() {
  const budget = getOllamaContextBudget();
  document.querySelectorAll('[data-ollama-context-budget="true"]').forEach((el) => {
    el.textContent = window.POFChatContextBudget.formatBudgetLabel(budget);
    el.classList.toggle('warning', budget.truncated);
    el.title = budget.truncated
      ? [
          `${budget.omittedMessages} message(s) ancien(s) ignoré(s)`,
          `${budget.clippedMessages} message(s) raccourci(s)`,
          `Budget interne : ${OLLAMA_CHAT_CONTEXT_MAX_CHARS} caractères`,
        ].join(' · ')
      : `Tout l'historique sera envoyé · budget interne ${OLLAMA_CHAT_CONTEXT_MAX_CHARS} caractères`;
  });
}

function exportOllamaConversation() {
  if (ollamaUiState.busy || !ollamaUiState.conversation.length) {
    setOllamaStatus('Aucune conversation à exporter.', true);
    return;
  }
  const activeHistory = ollamaUiState.history.find(
    (entry) => entry.id === ollamaUiState.activeConversationId,
  );
  const title = String(
    activeHistory?.title || buildOllamaConversationTitle(ollamaUiState.conversation),
  ).trim();
  const binaryPath = typeof getStaticBinaryPath === 'function' ? getStaticBinaryPath() : '';
  const snapshot = window.POFChatExport?.buildConversationExport({
    id: ollamaUiState.activeConversationId,
    title,
    model: activeHistory?.model || getCurrentOllamaModel() || ollamaUiState.lastModel || '',
    binaryPath,
    messages: ollamaUiState.conversation,
  });
  if (!snapshot) {
    setOllamaStatus("L'export de cette conversation est indisponible.", true);
    return;
  }
  vscode.postMessage({
    type: 'hubExportConversation',
    markdown: window.POFChatExport.formatConversationMarkdown(snapshot),
    json: snapshot,
    suggestedName: window.POFChatExport.buildSuggestedName(title),
  });
  setOllamaStatus("Choisis le format et l'emplacement de l'export.");
}

function renderOllamaConversation() {
  const targets = Array.from(document.querySelectorAll('[data-ollama-chat-history="true"]'));
  if (!targets.length) return;
  targets.forEach((el) => {
    const shouldFollow = shouldFollowOllamaStream(el);
    const previousScrollTop = el.scrollTop;
    el.replaceChildren();
    if (!ollamaUiState.conversation.length) {
      const empty = document.createElement('p');
      empty.className = 'ollama-chat-empty';
      empty.textContent = "Aucune discussion pour l'instant. Pose une première question.";
      el.appendChild(empty);
      document.querySelectorAll('[data-ollama-export="true"]').forEach((button) => {
        button.disabled = true;
      });
      return;
    }
    const frag = document.createDocumentFragment();
    ollamaUiState.conversation.forEach((entry, messageIndex) => {
      const wrap = document.createElement('article');
      wrap.className = `ollama-chat-message ${entry.role}`;
      const role = document.createElement('span');
      role.className = 'ollama-chat-role';
      role.textContent = formatOllamaRoleLabel(entry.role, entry.model);
      const content = document.createElement(entry.role === 'assistant' ? 'div' : 'pre');
      content.className = 'ollama-chat-content';
      if (entry.role === 'assistant' && window.POFMarkdownRenderer?.renderMarkdown) {
        content.classList.add('markdown-rendered');
        window.POFMarkdownRenderer.renderMarkdown(content, entry.content);
      } else {
        content.textContent = entry.content;
      }
      wrap.append(role, content);
      const usage = normalizeOllamaUsage(entry.usage);
      if (entry.role === 'assistant' && usage.totalTokens) {
        const meta = document.createElement('div');
        meta.className = 'ollama-message-usage';
        if (usage.hasRequestBreakdown) {
          meta.textContent = [
            `${formatOllamaTokenCount(usage.requestPromptTokens)} entrée`,
            `${formatOllamaTokenCount(usage.requestCompletionTokens)} sortie`,
            `${formatOllamaTokenCount(usage.requestTotalTokens)} total`,
          ].join(' · ');
          meta.title = 'Consommation de cette requête';
        } else {
          meta.textContent = [
            `${formatOllamaTokenCount(usage.promptTokens)} entrée dernière génération`,
            `${formatOllamaTokenCount(usage.completionTokens)} sortie dernière génération`,
            `${formatOllamaTokenCount(usage.requestTotalTokens)} requête cumulée`,
          ].join(' · ');
          meta.title = 'Ancien message : le détail cumulé entrée/sortie n’était pas enregistré';
        }
        const cost = window.POFAiPricing.estimateUsageCost(
          usage,
          entry.model,
          ollamaUiState.pricingRules,
          entry.ts ? new Date(Number(entry.ts)).toISOString() : '',
        );
        if (cost) {
          meta.textContent += ` · ~${window.POFAiPricing.formatUsd(cost.totalCost)}`;
          meta.title += [
            '',
            `Tarif: ${cost.rule.inputPerMillion} USD/1M entrée`,
            `${cost.rule.outputPerMillion} USD/1M sortie`,
            cost.rule.effectiveDate ? `date d’effet ${cost.rule.effectiveDate}` : 'date non renseignée',
          ].join(' · ');
        } else if (String(entry.model || '').includes('@')) {
          meta.textContent += ' · coût non configuré';
          meta.title += ' · Ajoute un tarif dans Options > Intelligence artificielle';
        }
        wrap.appendChild(meta);
      }
      if (entry.role === 'user' || entry.role === 'assistant') {
        const actions = document.createElement('div');
        actions.className = 'ollama-message-actions';
        if (entry.role === 'user') {
          const editBtn = document.createElement('button');
          editBtn.type = 'button';
          editBtn.className = 'ollama-message-action';
          editBtn.dataset.ollamaMessageAction = 'true';
          editBtn.textContent = 'Modifier';
          editBtn.title = 'Modifier ce message et recréer la suite de la conversation';
          editBtn.disabled = ollamaUiState.busy;
          editBtn.addEventListener('click', () => {
            showOllamaMessageEditor(wrap, messageIndex, entry);
          });
          actions.appendChild(editBtn);
        } else {
          const regeneratePlan = window.POFChatMessageActions?.prepareRegeneration(
            ollamaUiState.conversation,
            messageIndex,
          );
          if (regeneratePlan) {
            const regenerateBtn = document.createElement('button');
            regenerateBtn.type = 'button';
            regenerateBtn.className = 'ollama-message-action';
            regenerateBtn.dataset.ollamaMessageAction = 'true';
            regenerateBtn.textContent = 'Régénérer';
            regenerateBtn.title = 'Régénérer cette réponse depuis le prompt associé';
            regenerateBtn.disabled = ollamaUiState.busy;
            regenerateBtn.addEventListener('click', () => {
              runOllamaConversationRevision(regeneratePlan);
            });
            actions.appendChild(regenerateBtn);
          }
          const copyBtn = document.createElement('button');
          copyBtn.type = 'button';
          copyBtn.className = 'ollama-message-action';
          copyBtn.dataset.ollamaMessageAction = 'true';
          copyBtn.title = 'Copier la réponse';
          copyBtn.textContent = 'Copier';
          copyBtn.disabled = ollamaUiState.busy;
          copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(entry.content).then(() => {
              copyBtn.classList.add('copied');
              copyBtn.textContent = 'Copié';
              setTimeout(() => {
                copyBtn.classList.remove('copied');
                copyBtn.textContent = 'Copier';
              }, 1500);
            });
          });
          actions.appendChild(copyBtn);
        }
        if (actions.childElementCount) wrap.appendChild(actions);
      }
      frag.appendChild(wrap);
    });
    el.appendChild(frag);
    restoreOllamaScroll(el, shouldFollow, previousScrollTop);
  });
  renderOllamaConversationUsage();
  renderOllamaContextBudget();
  renderOllamaGenerationSettings();
  document.querySelectorAll('[data-ollama-export="true"]').forEach((button) => {
    button.disabled = ollamaUiState.busy || !ollamaUiState.conversation.length;
  });
}

function runOllamaConversationRevision(plan) {
  if (ollamaUiState.busy || !plan?.prompt) return;
  const model = String(
    plan.model || getCurrentOllamaModel() || ollamaUiState.lastModel || '',
  ).trim();
  if (!model) {
    setOllamaStatus("Sélectionne d'abord un modèle pour relancer ce message.", true);
    return;
  }
  activeConversationRevisionBackup = [...ollamaUiState.conversation];
  ollamaUiState.conversation = Array.isArray(plan.context) ? [...plan.context] : [];
  const submitted = submitOllamaChatPrompt({
    prompt: plan.prompt,
    model,
    keepInput: true,
  });
  if (!submitted) restoreOllamaConversationRevision();
}

function completeOllamaConversationRevision() {
  activeConversationRevisionBackup = null;
}

function restoreOllamaConversationRevision() {
  if (!activeConversationRevisionBackup) return false;
  ollamaUiState.conversation = activeConversationRevisionBackup;
  activeConversationRevisionBackup = null;
  syncActiveOllamaConversationInHistory(true);
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
  return true;
}

function showOllamaMessageEditor(wrap, messageIndex, entry) {
  if (ollamaUiState.busy || !wrap || entry?.role !== 'user') return;
  const role = wrap.querySelector('.ollama-chat-role');
  const editor = document.createElement('div');
  editor.className = 'ollama-message-editor';
  const input = document.createElement('textarea');
  input.className = 'input-inner ollama-message-editor-input';
  input.rows = 4;
  input.value = String(entry.content || '');
  input.setAttribute('aria-label', 'Modifier le message');
  const actions = document.createElement('div');
  actions.className = 'ollama-message-editor-actions';
  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'btn btn-secondary btn-sm';
  cancelBtn.textContent = 'Annuler';
  cancelBtn.addEventListener('click', renderOllamaConversation);
  const submitBtn = document.createElement('button');
  submitBtn.type = 'button';
  submitBtn.className = 'btn btn-primary btn-sm';
  submitBtn.textContent = 'Enregistrer et relancer';
  const submitEdit = () => {
    const plan = window.POFChatMessageActions?.prepareMessageEdit(
      ollamaUiState.conversation,
      messageIndex,
      input.value,
    );
    if (!plan) {
      input.focus();
      setOllamaStatus('Le message modifié ne peut pas être vide.', true);
      return;
    }
    runOllamaConversationRevision(plan);
  };
  submitBtn.addEventListener('click', submitEdit);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      renderOllamaConversation();
    } else if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      submitEdit();
    }
  });
  actions.append(cancelBtn, submitBtn);
  editor.append(input, actions);
  wrap.replaceChildren();
  if (role) wrap.appendChild(role);
  wrap.appendChild(editor);
  input.focus();
  input.setSelectionRange(input.value.length, input.value.length);
}

function pushOllamaMessage(role, text, model, metadata = {}) {
  const normalizedRole = ['user', 'assistant', 'system'].includes(role) ? role : 'system';
  const content = String(text || '').trim();
  if (!content) return;
  const entry = { role: normalizedRole, content, ts: Date.now() };
  if (model) entry.model = String(model);
  const usage = normalizeOllamaUsage(metadata.usage);
  if (usage.totalTokens) entry.usage = usage;
  ollamaUiState.conversation.push(entry);
  if (ollamaUiState.conversation.length > OLLAMA_CHAT_MAX_MESSAGES) {
    ollamaUiState.conversation = ollamaUiState.conversation.slice(-OLLAMA_CHAT_MAX_MESSAGES);
  }
  syncActiveOllamaConversationInHistory(true);
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
}

function deleteOllamaConversation(conversationId) {
  if (ollamaUiState.busy) return;
  const id = String(conversationId || '').trim();
  if (!id) return;
  ollamaUiState.history = ollamaUiState.history.filter((entry) => entry.id !== id);
  if (id === ollamaUiState.activeConversationId) {
    const next = ollamaUiState.history[0];
    if (next) {
      ollamaUiState.activeConversationId = next.id;
      ollamaUiState.conversation = _normalizeOllamaConversationMessages(next.messages);
      if (next.model) {
        rememberOllamaModel(next.model, true);
        renderOllamaModels(ollamaUiState.models, next.model);
      }
    } else {
      ollamaUiState.activeConversationId = createOllamaConversationId();
      ollamaUiState.conversation = [];
      syncActiveOllamaConversationInHistory(true);
    }
  }
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
  setOllamaStatus('Conversation supprimée.');
}

function clearOllamaConversation() {
  if (ollamaUiState.busy) return;
  if (ollamaUiState.conversation.length) {
    syncActiveOllamaConversationInHistory(false);
  } else if (ollamaUiState.activeConversationId) {
    ollamaUiState.history = ollamaUiState.history.filter(
      (entry) => entry.id !== ollamaUiState.activeConversationId
    );
  }
  ollamaUiState.activeConversationId = createOllamaConversationId();
  ollamaUiState.conversation = [];
  syncActiveOllamaConversationInHistory(true);
  persistOllamaConversation();
  renderOllamaConversation();
  renderOllamaConversationHistory();
  setOllamaStatus('Nouvelle discussion prête.');
}

function clearOllamaConversationHistory() {
  if (ollamaUiState.busy) return;
  ollamaUiState.history = [];
  ollamaUiState.activeConversationId = '';
  clearOllamaConversation();
  setOllamaStatus('Historique vidé. Nouvelle discussion prête.');
}

function buildOllamaPromptRequest(userPrompt) {
  const prompt = String(userPrompt || '').trim();
  if (!prompt) return { prompt: '', budget: getOllamaContextBudget() };

  // Build binary context block with path + meta (format/arch)
  const binPath = (typeof getStaticBinaryPath === 'function') ? getStaticBinaryPath() : '';
  const meta = binarySourceController?.getCurrentBinaryMeta?.();
  const ctxLines = [];
  if (binPath) {
    ctxLines.push(`Binaire actuellement ouvert dans l'application : ${binPath}`);
    if (meta?.format) ctxLines.push(`Format : ${meta.format}`);
    if (meta?.arch)   ctxLines.push(`Architecture : ${meta.arch}`);
  }
  const projectCtx = ctxLines.join('\n');
  const budget = getOllamaContextBudget();
  const parts = [];
  if (projectCtx) {
    parts.push(
      'Contexte binaire passif (à utiliser seulement si la demande concerne le binaire) :',
      projectCtx,
    );
  }
  if (budget.lines.length) {
    parts.push(
      'Contexte de conversation à respecter :',
      ...budget.lines,
    );
  }
  parts.push(`Demande utilisateur : ${prompt}`);
  const contextualPrompt = parts.length === 1 && !projectCtx && !budget.lines.length
    ? prompt
    : parts.join('\n');
  return {
    prompt: contextualPrompt,
    budget: {
      ...budget,
      requestChars: contextualPrompt.length,
      requestEstimatedTokens: window.POFChatContextBudget.estimateTokens(contextualPrompt),
    },
  };
}

function submitOllamaChatPrompt(options = {}) {
  _streamingResponseLocked = false;
  _streamFragmentCount = 0;
  _renderedStreamChars = 0;
  _cancelStreamQueue();
  if (ollamaUiState.busy) return false;
  const input = options.inputEl || document.getElementById('ollamaPromptInput');
  const prompt = String(options.prompt ?? input?.value ?? '').trim();
  const model = String(options.model || getCurrentOllamaModel() || ollamaUiState.lastModel || '').trim();
  if (!model) {
    setOllamaStatus("Sélectionne d'abord un modèle Ollama.", true);
    return false;
  }
  if (!prompt) {
    setOllamaStatus("Écris un message avant d'envoyer.", true);
    return false;
  }
  const request = buildOllamaPromptRequest(prompt);
  if (
    request.budget.significantTruncation
    && options.skipContextWarning !== true
    && !window.confirm(window.POFChatContextBudget.formatTruncationWarning(request.budget))
  ) {
    setOllamaStatus('Envoi annulé : ajuste ou résume la conversation avant de continuer.');
    return false;
  }
  const contextualPrompt = request.prompt;
  const generationSettings = getOllamaGenerationSettings();
  pushOllamaMessage('user', prompt);
  if (input && !options.keepInput) {
    input.value = '';
    input.focus();
  }
  setOllamaBusy(true);
  showOllamaTypingIndicator(model);
  activeAiRequestId =
    `ai-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;

  // Cloud provider model: format "provider@model"
  const atIdx = model.indexOf('@');
  if (atIdx > 0) {
    const provider = model.slice(0, atIdx);
    const providerModel = model.slice(atIdx + 1);
    setOllamaStatus(
      `Exécution avec ${provider} / ${providerModel}`
        + ` · requête ~${request.budget.requestEstimatedTokens} tokens…`,
    );
    vscode.postMessage({
      type: 'hubAiProviderPrompt',
      provider,
      model: providerModel,
      prompt: contextualPrompt,
      requestId: activeAiRequestId,
      ...generationSettings,
    });
    return true;
  }

  setOllamaStatus(
    `Exécution avec ${model} · requête ~${request.budget.requestEstimatedTokens} tokens…`,
  );
  vscode.postMessage({
    type: 'hubOllamaPrompt',
    model,
    prompt: contextualPrompt,
    baseUrl: getOllamaBaseUrl(),
    requestId: activeAiRequestId,
    ...generationSettings,
  });
  return true;
}

function cancelOllamaChatPrompt() {
  if (!ollamaUiState.busy || !activeAiRequestId) return;
  setOllamaStatus('Arrêt de la génération…');
  document.querySelectorAll('[data-ollama-cancel="true"]').forEach((button) => {
    button.disabled = true;
  });
  vscode.postMessage({
    type: 'hubAiCancel',
    requestId: activeAiRequestId,
  });
}

function getOllamaBaseUrl() {
  return (ollamaUiState && ollamaUiState.baseUrl) || 'http://127.0.0.1:11434';
}

function getCurrentOllamaModel() {
  const selects = Array.from(document.querySelectorAll('[data-ollama-model-select="true"]'));
  for (const select of selects) {
    const value = String(select?.value || '').trim();
    if (value) return value;
  }
  return String(ollamaUiState.lastModel || '').trim();
}

function rememberOllamaModel(model, notifyHost = false) {
  const normalized = String(model || '').trim();
  if (!normalized) return '';
  ollamaUiState.lastModel = normalized;
  _saveStorage({ ollamaModel: normalized });
  if (notifyHost) {
    vscode.postMessage({ type: 'hubOllamaModelSelected', model: normalized });
  }
  return normalized;
}

function renderOllamaModels(models = [], selected = '') {
  const selects = Array.from(document.querySelectorAll('[data-ollama-model-select="true"]'));
  if (!selects.length) return;
  const normalized = Array.isArray(models) ? models.filter(Boolean) : [];
  const savedModel = String(selected || ollamaUiState.lastModel || _loadStorage().ollamaModel || '').trim();
  selects.forEach((select) => {
    // Preserve cloud provider optgroups before clearing
    const cloudGroups = Array.from(select.querySelectorAll('optgroup[data-cloud-provider]'));
    select.replaceChildren();
    if (!normalized.length) {
      const opt = document.createElement('option');
      opt.value = savedModel;
      opt.textContent = savedModel || 'Aucun modèle Ollama détecté';
      select.appendChild(opt);
      select.disabled = normalized.length === 0 && cloudGroups.length === 0;
    } else {
      normalized.forEach((name) => {
        const opt = document.createElement('option');
        opt.value = String(name);
        opt.textContent = String(name);
        select.appendChild(opt);
      });
      select.disabled = false;
    }
    cloudGroups.forEach((g) => select.appendChild(g));
  });
  const isCloud = savedModel.includes('@');
  const target = isCloud
    ? savedModel
    : (savedModel && normalized.includes(savedModel) ? savedModel : normalized[0]);
  selects.forEach((select) => { if (target) select.value = target; });
  if (target) rememberOllamaModel(target);
}

function injectCloudProviderModels(providers) {
  const selects = Array.from(document.querySelectorAll('[data-ollama-model-select="true"]'));
  if (!selects.length || !Array.isArray(providers)) return;
  selects.forEach((select) => {
    // Remove old cloud optgroups
    Array.from(select.querySelectorAll('optgroup[data-cloud-provider]')).forEach((g) => g.remove());
    providers.forEach((p) => {
      if (!p.valid || !Array.isArray(p.models) || !p.models.length) return;
      const group = document.createElement('optgroup');
      group.label = p.name.charAt(0).toUpperCase() + p.name.slice(1);
      group.dataset.cloudProvider = p.name;
      p.models.forEach((m) => {
        const opt = document.createElement('option');
        opt.value = p.name + '@' + m;
        opt.textContent = m;
        group.appendChild(opt);
      });
      select.appendChild(group);
      select.disabled = false;
    });
    if (ollamaUiState.lastModel && select.querySelector(`option[value="${CSS.escape(ollamaUiState.lastModel)}"]`)) {
      select.value = ollamaUiState.lastModel;
    }
  });
}

function requestOllamaModels() {
  if (ollamaUiState.busy) return;
  setOllamaBusy(true);
  setOllamaStatus('Chargement des modèles Ollama…');
  vscode.postMessage({
    type: 'hubOllamaListModels',
    baseUrl: getOllamaBaseUrl(),
  });
}

// Quick actions
document.querySelectorAll('.action-card').forEach((card) => {
  card.addEventListener('click', () => {
    if (card.dataset.action === 'static-open') {
      showPanel('static');
      if (!getStaticBinaryPath()) openBinaryMenu();
    } else if (card.dataset.action === 'dynamic-run') {
      showPanel('dynamic');
    } else if (card.dataset.action === 'outils-open') {
      showPanel('outils');
    }
  });
});

// Static: binary path shared with dynamic form
const staticBinaryInput = document.getElementById('staticBinaryPath');

function setOption32Availability(selectEl, platform) {
  if (!selectEl) return;
  const option32 = selectEl.querySelector('option[value="32"]');
  if (!option32) return;
  if (platform !== 'linux') {
    option32.disabled = true;
    option32.textContent = `32-bit (non dispo sur ${platform === 'darwin' ? 'macOS' : 'Windows'})`;
    if (selectEl.value === '32') selectEl.value = '64';
  } else {
    option32.disabled = false;
    option32.textContent = '32-bit';
  }
}

// Restore static binary path from storage
try {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    const { staticBinaryPath, binaryMeta } = JSON.parse(saved);
    if (staticBinaryPath && staticBinaryInput) {
      staticBinaryInput.value = staticBinaryPath;
      if (binaryPathInput && !binaryPathInput.value?.trim()) binaryPathInput.value = staticBinaryPath;
      currentBinaryMeta = _normalizeBinaryMeta(binaryMeta || null);
      updateTopBarBinaryDisplay(staticBinaryPath, currentBinaryMeta);
    }
  }
} catch (_) {}
function syncStaticBinary() {
  binarySourceController?.getStaticBinaryPath?.();
}
function getStaticBinaryPath() {
  return binarySourceController ? binarySourceController.getStaticBinaryPath() : (staticBinaryInput?.value?.trim() || '');
}

function getActiveStaticTab() {
  return document.querySelector('#subTabsBar .sub-tab.active')?.dataset.subTab || _loadStorage().tab || 'disasm';
}

function syncStaticWorkspaceSummary(activeTab = getActiveStaticTab()) {
  void activeTab;
  updateDisasmSessionSummary();
}

const DISASM_UI_STATE_KEY = 'pof-disasm-ui-state-v1';
function _basenameFromPath(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return '';
  return normalized.split(/[\\/]/).filter(Boolean).pop() || normalized;
}

function _getSelectDisplayText(id, fallback = '—') {
  const el = document.getElementById(id);
  if (!el) return fallback;
  const opt = el.options?.[el.selectedIndex];
  const label = String(opt?.textContent || opt?.label || '').trim();
  return label || fallback;
}

function _selectedRawArchMeta() {
  return getCurrentBinaryMeta();
}

function _getDisasmArchSummaryText() {
  const meta = getCurrentBinaryMeta();
  if (meta?.kind === 'raw') {
    const selectedArch = String(meta.rawConfig?.arch || meta.arch || '').trim();
    if (selectedArch) return _displayRawArchName(selectedArch);
    return 'Blob brut';
  }
  const detectedArch = String(meta?.rawConfig?.arch || meta?.arch || window.lastBinaryArch || '').trim();
  return detectedArch ? `Auto: ${detectedArch}` : 'Auto';
}

function _countVisibleAnnotations() {
  return Object.values(window._annotations || {}).filter((entry) => entry && (entry.name || entry.comment)).length;
}

function _setTextContent(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function _loadDisasmUiState() {
  try {
    return JSON.parse(localStorage.getItem(DISASM_UI_STATE_KEY) || '{}');
  } catch {
    return {};
  }
}

function _saveDisasmUiState(partial) {
  const next = { ..._loadDisasmUiState(), ...partial };
  localStorage.setItem(DISASM_UI_STATE_KEY, JSON.stringify(next));
  return next;
}

function updateDisasmSessionSummary() {
  const binaryPath = getStaticBinaryPath();
  const summary = getActiveContextSummary(window._lastDisasmAddr);
  const selectionAddr = normalizeHexAddress(document.getElementById('annotationAddrBadge')?.dataset.addr || '');
  const annotationsCount = _countVisibleAnnotations();
  const bookmarksCount = document.querySelectorAll('#bookmarksList .bookmark-item').length;
  const functionLabel = summary.functionName
    ? `${summary.functionName}${summary.functionAddr ? ` @ ${summary.functionAddr}` : ''}`
    : (summary.functionAddr || '—');

  _setTextContent('disasmSummaryBinary', binaryPath ? _basenameFromPath(binaryPath) : 'Aucun fichier');
  _setTextContent('disasmSummaryFunction', functionLabel || '—');
  _setTextContent('disasmSummaryAddress', summary.addr || '—');
  _setTextContent('disasmSummarySelection', selectionAddr || '—');
  _setTextContent('disasmSummarySyntax', _getSelectDisplayText('disasmSyntax', 'Intel'));
  _setTextContent('disasmSummarySection', _getSelectDisplayText('disasmSection', 'Toutes'));
  _setTextContent('disasmSummaryArch', _getDisasmArchSummaryText());
  _setTextContent('disasmSummaryAnnotations', String(annotationsCount));
  _setTextContent('disasmSummaryBookmarks', String(bookmarksCount));
  _setTextContent('disasmSummaryHistory', _navHistory.length ? `${Math.min(_navIndex + 1, _navHistory.length)}/${_navHistory.length}` : '0');
  renderDisasmNavigationHistory();

  const hintEl = document.getElementById('disasmSessionHint');
  if (!hintEl) return;
  if (!binaryPath) {
    hintEl.textContent = 'Choisis un binaire puis ouvre le désassemblage pour démarrer la session.';
  } else if (summary.addr && summary.functionName) {
    const historyHint = _navHistory.length > 1 ? ` Fil actuel: ${Math.min(_navIndex + 1, _navHistory.length)}/${_navHistory.length}.` : '';
    hintEl.textContent = `Tu es positionné sur ${summary.functionName} à ${summary.addr}. Les actions essentielles restent visibles, le reste peut se replier.${historyHint}`;
  } else if (summary.addr) {
    const historyHint = _navHistory.length > 1 ? ` Fil actuel: ${Math.min(_navIndex + 1, _navHistory.length)}/${_navHistory.length}.` : '';
    hintEl.textContent = `Adresse active ${summary.addr}. Tu peux naviguer, annoter ou lancer les xrefs depuis ici.${historyHint}`;
  } else {
    hintEl.textContent = 'Utilise Go, les raccourcis ou le sélecteur de symbole pour te déplacer rapidement dans le binaire.';
  }
}

function setDisasmCardCollapsed(cardId, bodyId, buttonId, collapsed) {
  const card = document.getElementById(cardId);
  const body = document.getElementById(bodyId);
  const button = document.getElementById(buttonId);
  if (card) card.classList.toggle('is-collapsed', collapsed);
  if (body) body.hidden = collapsed;
  if (button) {
    button.textContent = collapsed ? 'Afficher' : 'Masquer';
    button.setAttribute('aria-expanded', String(!collapsed));
  }
}

function bindDisasmCardToggle({ stateKey, cardId, bodyId, buttonId }) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  const state = _loadDisasmUiState();
  setDisasmCardCollapsed(cardId, bodyId, buttonId, state[stateKey] === true);
  button.addEventListener('click', () => {
    const currentState = _loadDisasmUiState();
    const collapsed = !(currentState[stateKey] === true);
    _saveDisasmUiState({ [stateKey]: collapsed });
    setDisasmCardCollapsed(cardId, bodyId, buttonId, collapsed);
  });
}

function initDisasmUxState() {
  bindDisasmCardToggle({
    stateKey: 'labelsCollapsed',
    cardId: 'disasmLabelsCard',
    bodyId: 'disasmLabelsBody',
    buttonId: 'btnToggleDisasmLabels',
  });
  ['disasmSyntax', 'disasmSection'].forEach((id) => {
    document.getElementById(id)?.addEventListener('change', () => {
      updateDisasmSessionSummary();
    });
  });
  updateDisasmSessionSummary();
}

function resetStaticBinaryDerivedState() {
  tabDataCache = {};
  currentArchSupport = null;
  stackFrameCache = {};
  window.sectionsCache = [];
  resetHexPatchSessionState();
  hexSelectionModel = {
    startAddr: '',
    endAddr: '',
    activeAddr: '',
    anchorAddr: '',
    spanLength: 1,
  };
  pendingStackFrameRequests.clear();
  stackUiState.renderedAddr = '';
  stackUiState.renderedBinaryPath = '';
  stackUiState.activeEntryName = '';
  stackUiState.pendingEntryName = '';
  decompileUiState.activeStackEntryName = '';
  decompileUiState.pendingStackEntryName = '';
  typedDataUiState.appliedStructName = '';
  typedDataUiState.appliedStructOffset = '0x0';
  typedDataUiState.appliedStructAddr = '';
  typedDataUiState.hexStructPreview = null;
  clearDecompileCaches();
  window._lastDisasmAddr = '';
  window.lastBinaryArch = '';
  window._annotations = {};
  decompileUiState.renderedAddr = '';
  decompileUiState.renderedBinaryPath = '';
  decompileUiState.renderedQuality = _normalizeDecompileQuality(decompileUiState.quality || 'normal');
  updateActiveContextBars('');
  renderBookmarks();
  updateDisasmSessionSummary();
}

function applyStaticBinarySelectionUi(binaryPath, binaryMeta) {
  binarySourceController?.applyStaticBinarySelectionUi?.(binaryPath, binaryMeta);
}

function queueStaticBinaryAutoload(binaryPath, opts) {
  // Handled internally by binarySourceController via finalizeStaticBinarySelection
  void binaryPath; void opts;
}

function finalizeStaticBinarySelection(binaryPath, binaryMeta, opts) {
  binarySourceController?.finalizeStaticBinarySelection?.(binaryPath, binaryMeta, opts);
}

function triggerStaticQuickAction(action) {
  const config = STATIC_QUICK_ACTIONS[action];
  if (!config) return;
  const hasBinary = !!getStaticBinaryPath();
  pendingStaticQuickAction = hasBinary ? '' : action;
  showGroup(config.group, config.tab);
  if (!hasBinary) {
    vscode.postMessage({ type: 'requestBinarySelection' });
    return;
  }
  if (config.tab === 'disasm') {
    postBinaryAwareMessage('hubOpenDisasm', {
      binaryPath: getStaticBinaryPath(),
      useCache: true,
      openInEditor: false,
    });
  }
}

function postBinaryAwareMessage(type, extra = {}) {
  try { window.POFHubTaskProgressController?.startTask({ type, ...extra }); } catch(e) {}
  if (binarySourceController) {
    binarySourceController.postBinaryAwareMessage(type, extra);
    return;
  }
  const payload = { type, ...extra };
  const binaryPath = payload.binaryPath || getStaticBinaryPath();
  if (binaryPath && payload.binaryPath === undefined) payload.binaryPath = binaryPath;
  const meta = getCurrentBinaryMeta();
  if (binaryPath && payload.binaryMeta === undefined && meta) payload.binaryMeta = meta;
  vscode.postMessage(payload);
}

function isRawBinarySelected() {
  return binarySourceController ? binarySourceController.isRawBinarySelected() : (getCurrentBinaryMeta()?.kind === 'raw');
}

function markRawTabUnavailable(tabId) {
  const contentIds = RAW_UNSUPPORTED_TABS[tabId];
  if (!contentIds) return false;
  const note = getRawTabCapability(tabId)?.note || '';
  const message = note
    ? `${note} Utilisez plutôt Désassemblage, CFG, Call Graph, Fonctions, Strings, Recherche, Infos, Sections, Hex ou Données typées.`
    : "Cette vue n'est pas encore disponible pour un blob brut. Utilisez plutôt Désassemblage, CFG, Call Graph, Fonctions, Strings, Recherche, Infos, Sections, Hex ou Données typées.";
  contentIds.forEach((id) => setStaticLoading(id, message));
  return true;
}

function syncDynamicBinaryFieldMode() {
  binarySourceController?.syncDynamicBinaryFieldMode?.();
}

function loadExploitNotesUiState() {
  try {
    return JSON.parse(localStorage.getItem(EXPLOIT_NOTES_UI_KEY) || '{}');
  } catch (_) {
    return {};
  }
}

function saveExploitNotesUiState(state) {
  try {
    const prev = loadExploitNotesUiState();
    localStorage.setItem(EXPLOIT_NOTES_UI_KEY, JSON.stringify({ ...prev, ...state }));
  } catch (_) {}
}

function openExploitNotesWidget() {
  exploitNotesController?.open?.();
}

function closeExploitNotesWidget() {
  exploitNotesController?.close?.();
}

function toggleExploitNotesCollapsed(forceCollapsed = null) {
  exploitNotesController?.toggleCollapsed?.(forceCollapsed);
}

function initExploitNotesWidget() {
  exploitNotesController?.init?.();
}

function initOllamaChatWidget() {
  const widget = document.getElementById('ollamaChatWidget');
  const fab = document.getElementById('ollamaChatFab');
  if (!widget || !fab) return;
  const closeBtn = document.getElementById('btnOllamaChatWidgetClose');
  const openDashboardBtn = document.getElementById('btnOllamaOpenDashboard');
  const resizeHandle = document.getElementById('ollamaChatWidgetResizeHandle');
  const minWidth = 300;
  const minHeight = 300;

  const getMaxSize = () => ({
    width: Math.max(minWidth, window.innerWidth - 86),
    height: Math.max(minHeight, window.innerHeight - 86),
  });
  const applySize = (width, height, persist = false) => {
    if (window.matchMedia('(max-width: 680px)').matches) return;
    const max = getMaxSize();
    const nextWidth = Math.round(Math.min(max.width, Math.max(minWidth, Number(width) || 360)));
    const nextHeight = Math.round(Math.min(max.height, Math.max(minHeight, Number(height) || 460)));
    widget.style.width = `${nextWidth}px`;
    widget.style.height = `${nextHeight}px`;
    if (persist) {
      try {
        localStorage.setItem(OLLAMA_CHAT_WIDGET_SIZE_KEY, JSON.stringify({
          width: nextWidth,
          height: nextHeight,
        }));
      } catch (_) {}
    }
  };
  const restoreSize = () => {
    try {
      const saved = JSON.parse(localStorage.getItem(OLLAMA_CHAT_WIDGET_SIZE_KEY) || '{}');
      applySize(saved.width, saved.height);
    } catch (_) {
      applySize(360, 460);
    }
  };

  const open = () => {
    widget.classList.add('open');
    restoreSize();
    try { localStorage.setItem(OLLAMA_CHAT_WIDGET_KEY, 'open'); } catch (_) {}
  };
  const close = () => {
    widget.classList.remove('open');
    try { localStorage.setItem(OLLAMA_CHAT_WIDGET_KEY, 'closed'); } catch (_) {}
  };
  const toggle = () => {
    if (widget.classList.contains('open')) close();
    else open();
  };

  try {
    if (localStorage.getItem(OLLAMA_CHAT_WIDGET_KEY) === 'open') open();
    else close();
  } catch (_) {
    close();
  }

  fab.addEventListener('click', toggle);
  closeBtn?.addEventListener('click', close);
  resizeHandle?.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 || window.matchMedia('(max-width: 680px)').matches) return;
    event.preventDefault();
    resizeHandle.setPointerCapture?.(event.pointerId);
    widget.classList.add('is-resizing');
    const startX = event.clientX;
    const startY = event.clientY;
    const startWidth = widget.getBoundingClientRect().width;
    const startHeight = widget.getBoundingClientRect().height;

    const onPointerMove = (moveEvent) => {
      applySize(
        startWidth + (startX - moveEvent.clientX),
        startHeight + (startY - moveEvent.clientY),
      );
    };
    const finishResize = () => {
      resizeHandle.removeEventListener('pointermove', onPointerMove);
      resizeHandle.removeEventListener('pointerup', finishResize);
      resizeHandle.removeEventListener('pointercancel', finishResize);
      widget.classList.remove('is-resizing');
      const rect = widget.getBoundingClientRect();
      applySize(rect.width, rect.height, true);
    };
    resizeHandle.addEventListener('pointermove', onPointerMove);
    resizeHandle.addEventListener('pointerup', finishResize);
    resizeHandle.addEventListener('pointercancel', finishResize);
  });
  resizeHandle?.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
    event.preventDefault();
    const rect = widget.getBoundingClientRect();
    const step = event.shiftKey ? 40 : 10;
    applySize(
      rect.width + (event.key === 'ArrowLeft' ? step : event.key === 'ArrowRight' ? -step : 0),
      rect.height + (event.key === 'ArrowUp' ? step : event.key === 'ArrowDown' ? -step : 0),
      true,
    );
  });
  window.addEventListener('resize', () => {
    if (!widget.classList.contains('open')) return;
    const rect = widget.getBoundingClientRect();
    applySize(rect.width, rect.height);
  });
  openDashboardBtn?.addEventListener('click', () => {
    showPanel('dashboard');
    const input = document.getElementById('ollamaPromptInput');
    if (input) input.focus();
  });
  const activePanel = document.querySelector('.icon-nav-item.active')?.dataset.panel || 'dashboard';
  syncOllamaFloatingWidgetVisibility(activePanel);
}

function syncOllamaFloatingWidgetVisibility(panelId = '') {
  const widget = document.getElementById('ollamaChatWidget');
  const fab = document.getElementById('ollamaChatFab');
  if (!widget || !fab) return;
  const normalized = String(panelId || '').trim().toLowerCase();
  const hideFloating = normalized === 'dashboard';
  if (hideFloating) {
    fab.style.display = 'none';
    widget.style.display = 'none';
    return;
  }
  fab.style.display = '';
  widget.style.display = '';
}

function prefillOllamaPrompt(prompt) {
  showPanel('dashboard');
  const input = document.getElementById('ollamaPromptInput');
  if (!input) return false;
  input.value = String(prompt || '');
  input.focus();
  input.setSelectionRange(input.value.length, input.value.length);
  input.scrollIntoView({ block: 'center', behavior: 'smooth' });
  return true;
}

function getAnalysisAiFilters(view) {
  if (view === 'strings') {
    const encoding = document.getElementById('stringsEncoding')?.selectedOptions?.[0]?.textContent || '';
    const minLength = document.getElementById('stringsMinLen')?.value || '';
    const section = document.getElementById('stringsSection')?.value || 'toutes';
    return `encodage ${encoding || 'auto'}, longueur minimale ${minLength || '—'}, section ${section}`;
  }
  if (view === 'search') {
    const mode = document.querySelector('.search-mode-pill.active')?.dataset.mode || 'text';
    const caseSensitive = document.getElementById('searchCaseSensitive')?.checked ? 'sensible à la casse' : 'insensible à la casse';
    return `mode ${mode}, ${caseSensitive}`;
  }
  return '';
}

function initAnalysisAiContextActions() {
  const contextApi = globalThis.POFAiContextActions;
  if (!contextApi) return;
  document.querySelectorAll('[data-ai-context-view]').forEach((button) => {
    if (button.dataset.aiContextBound === 'true') return;
    button.dataset.aiContextBound = 'true';
    button.addEventListener('click', () => {
      const view = String(button.dataset.aiContextView || '');
      const context = contextApi.collectAnalysisContext(document, view, {
        binaryPath: getStaticBinaryPath(),
        binaryMeta: getCurrentBinaryMeta(),
        filters: getAnalysisAiFilters(view),
      });
      const prompt = contextApi.buildAnalysisPrompt(context);
      if (!prompt) {
        _showToast({
          title: 'Aucun contexte à envoyer',
          sub: 'Lancez ou chargez cette analyse avant de demander à l’IA.',
          icon: '✦',
          variant: 'error',
          duration: 3500,
        });
        return;
      }
      prefillOllamaPrompt(prompt);
      _showToast({
        title: 'Contexte ajouté',
        sub: `La vue ${contextApi.VIEW_CONFIGS[view]?.label || view} est prête dans le composeur IA.`,
        icon: '✦',
        variant: 'ready',
        duration: 2500,
      });
    });
  });
}

function requestSymbols() {
  if (isRawBinarySelected()) return;
  const p = getStaticBinaryPath();
  if (p) vscode.postMessage({ type: 'getSymbols', binaryPath: p });
}

function setDynamicTraceStatus(text) {
  if (statusController?.setStatus) {
    statusController.setStatus(text, 'info');
  } else if (dynamicTraceStatus) {
    dynamicTraceStatus.textContent = text;
  }
  if (dynamicTraceStatus) {
    const t = String(text || '').toLowerCase();
    const state = t.includes('en cours') ? 'launching'
      : t.includes('terminée') ? 'done'
      : t.includes('ouverture') ? 'opening'
      : (t.includes('requis') || t.includes('invalide') || t.includes('bloquant')) ? 'error'
      : 'idle';
    dynamicTraceStatus.dataset.runtimeState = state;
  }
}

function buildDynamicSourceHintText({
  sourcePath = '',
  sourceEnrichmentEnabled = false,
  sourceEnrichmentStatus = '',
  sourceEnrichmentMessage = ''
} = {}) {
  return hubPayloadCore.buildSourceHintText({
    sourcePath,
    sourceEnrichmentEnabled,
    sourceEnrichmentStatus,
    sourceEnrichmentMessage
  });
}

function normalizeDynamicPayloadTargetMode(value) {
  return hubPayloadCore.normalizePayloadTargetMode(value);
}

function normalizeDynamicEffectiveTarget(value) {
  return hubPayloadCore.normalizeEffectiveTarget(value);
}

function dynamicPayloadTargetLabel(target) {
  return hubPayloadCore.payloadTargetLabel(target);
}

function getDynamicPayloadTargetMode() {
  if (payloadStateController?.getPayloadTargetMode) {
    return payloadStateController.getPayloadTargetMode();
  }
  return normalizeDynamicPayloadTargetMode(
    dynamicPayloadTargetMode?.value || dynamicTraceInitState.payloadTargetMode || 'auto'
  );
}

function getDynamicEffectivePayloadTarget() {
  if (payloadStateController?.getEffectivePayloadTarget) {
    return payloadStateController.getEffectivePayloadTarget();
  }
  const mode = getDynamicPayloadTargetMode();
  if (mode !== 'auto') return normalizeDynamicEffectiveTarget(mode);
  return normalizeDynamicEffectiveTarget(dynamicTraceInitState.payloadTargetAuto || dynamicTraceInitState.payloadTargetEffective);
}

function buildDynamicPayloadTargetHint() {
  if (payloadStateController?.getPayloadTargetHint) {
    return payloadStateController.getPayloadTargetHint();
  }
  const mode = getDynamicPayloadTargetMode();
  if (mode !== 'auto') return `${dynamicPayloadTargetLabel(mode)} force manuellement.`;
  return String(dynamicTraceInitState.payloadTargetReason || 'Auto: aucune source claire, fallback sur argv[1]');
}

function requestRunTraceInit(preset = null, forcedBinaryPath = '') {
  if (runTraceController?.requestRunTraceInit) {
    runTraceController.requestRunTraceInit(preset, forcedBinaryPath);
    return;
  }
  vscode.postMessage({
    type: 'requestRunTraceInit',
    binaryPath: forcedBinaryPath || binaryPathInput?.value?.trim() || '',
    sourcePath: dynamicSourcePathInput?.value?.trim() || dynamicTraceInitState.sourcePath || '',
    payloadTargetMode: getDynamicPayloadTargetMode(),
    preset
  });
}


function initSharedWidgetsListeners() {
initAnalysisAiContextActions();
document.getElementById('btnOllamaRefreshModels')?.addEventListener('click', () => {
  requestOllamaModels();
});

const ollamaHistorySearch = document.getElementById('ollamaHistorySearch');
if (ollamaHistorySearch) {
  ollamaHistorySearch.value = ollamaUiState.historyQuery || '';
  ollamaHistorySearch.addEventListener('input', (event) => {
    ollamaUiState.historyQuery = String(event.target?.value || '');
    renderOllamaConversationHistory();
  });
}

const ollamaHistorySort = document.getElementById('ollamaHistorySort');
if (ollamaHistorySort) {
  ollamaHistorySort.value = ollamaUiState.historySort || 'updated_desc';
  ollamaHistorySort.addEventListener('change', (event) => {
    ollamaUiState.historySort = String(event.target?.value || 'updated_desc');
    _saveStorage({ ollamaHistorySort: ollamaUiState.historySort });
    renderOllamaConversationHistory();
  });
}

document.querySelectorAll('[data-ai-generation-scope="true"]').forEach((select) => {
  select.addEventListener('change', (event) => {
    setOllamaGenerationScope(String(event.target?.value || 'global'));
  });
});

document.querySelectorAll('[data-ai-generation-key]').forEach((input) => {
  input.addEventListener('change', (event) => {
    updateOllamaConversationGenerationSetting(
      String(event.target?.dataset.aiGenerationKey || ''),
      event.target?.value,
    );
  });
});


document.querySelectorAll('[data-ollama-model-select="true"]').forEach((selectEl) => {
  selectEl.addEventListener('change', (event) => {
    const value = String(event.target?.value || '').trim();
    if (!value) return;
    if (value.includes('@')) {
      // Cloud model selected — just sync state without re-rendering Ollama list
      rememberOllamaModel(value, true);
      syncActiveOllamaConversationInHistory(false);
      persistOllamaConversation();
      return;
    }
    rememberOllamaModel(value, true);
    syncActiveOllamaConversationInHistory(false);
    persistOllamaConversation();
    renderOllamaModels(ollamaUiState.models, value);
  });
});

document.getElementById('btnOllamaRunPrompt')?.addEventListener('click', () => {
  submitOllamaChatPrompt();
});

document.querySelectorAll('[data-ollama-cancel="true"]').forEach((button) => {
  button.addEventListener('click', cancelOllamaChatPrompt);
});

document.querySelectorAll('[data-ollama-export="true"]').forEach((button) => {
  button.addEventListener('click', exportOllamaConversation);
});

document.querySelectorAll('[data-ollama-new-conversation="true"]').forEach((button) => {
  button.addEventListener('click', () => clearOllamaConversation());
});

document.getElementById('btnOllamaClearHistory')?.addEventListener('click', () => {
  clearOllamaConversationHistory();
});

document.getElementById('btnOllamaQuickRefresh')?.addEventListener('click', () => {
  requestOllamaModels();
});

document.getElementById('btnOllamaQuickSend')?.addEventListener('click', () => {
  const input = document.getElementById('ollamaQuickPromptInput');
  submitOllamaChatPrompt({ prompt: input?.value || '', inputEl: input });
});

document.getElementById('ollamaQuickPromptInput')?.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' || event.shiftKey) return;
  event.preventDefault();
  const input = document.getElementById('ollamaQuickPromptInput');
  submitOllamaChatPrompt({ prompt: input?.value || '', inputEl: input });
});

document.getElementById('ollamaPromptInput')?.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' || event.shiftKey) return;
  event.preventDefault();
  submitOllamaChatPrompt();
});

document.querySelectorAll('.ollama-template-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    const input = document.getElementById('ollamaPromptInput');
    if (input) {
      input.value = chip.dataset.template || '';
      input.focus();
    }
  });
});
}
