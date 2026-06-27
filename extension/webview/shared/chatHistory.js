// SPDX-License-Identifier: AGPL-3.0-only
(function initChatHistory(global) {
  const VALID_SORTS = new Set(['updated_desc', 'updated_asc', 'title_asc', 'model_asc']);

  function normalizeSearchText(value) {
    return String(value || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLocaleLowerCase('fr-FR')
      .trim();
  }

  function normalizeConversationTitle(value) {
    return String(value || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  }

  function matchesConversation(entry, query) {
    const needle = normalizeSearchText(query);
    if (!needle) return true;
    const messageText = (Array.isArray(entry?.messages) ? entry.messages : [])
      .map((message) => message?.content || '')
      .join(' ');
    return normalizeSearchText([
      entry?.title,
      entry?.model,
      messageText,
    ].join(' ')).includes(needle);
  }

  function filterAndSortConversations(history, query = '', sort = 'updated_desc') {
    const mode = VALID_SORTS.has(sort) ? sort : 'updated_desc';
    const entries = (Array.isArray(history) ? history : [])
      .filter((entry) => matchesConversation(entry, query));
    entries.sort((left, right) => {
      if (mode === 'updated_asc') {
        return Number(left?.updatedAt || 0) - Number(right?.updatedAt || 0);
      }
      if (mode === 'title_asc') {
        return String(left?.title || '').localeCompare(
          String(right?.title || ''),
          'fr',
          { sensitivity: 'base' },
        );
      }
      if (mode === 'model_asc') {
        const byModel = String(left?.model || '').localeCompare(
          String(right?.model || ''),
          'fr',
          { sensitivity: 'base' },
        );
        if (byModel) return byModel;
      }
      return Number(right?.updatedAt || 0) - Number(left?.updatedAt || 0);
    });
    return entries;
  }

  const api = {
    filterAndSortConversations,
    matchesConversation,
    normalizeConversationTitle,
    normalizeSearchText,
  };
  global.POFChatHistory = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
