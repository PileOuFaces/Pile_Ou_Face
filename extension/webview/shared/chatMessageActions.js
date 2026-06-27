// SPDX-License-Identifier: AGPL-3.0-only
(function initChatMessageActions(global) {
  function normalizeMessages(messages) {
    return Array.isArray(messages) ? messages : [];
  }

  function findPreviousUserIndex(messages, fromIndex) {
    const source = normalizeMessages(messages);
    const start = Math.min(Number(fromIndex) - 1, source.length - 1);
    for (let index = start; index >= 0; index -= 1) {
      if (source[index]?.role === 'user' && String(source[index]?.content || '').trim()) {
        return index;
      }
    }
    return -1;
  }

  function findFollowingAssistantModel(messages, fromIndex) {
    const source = normalizeMessages(messages);
    for (let index = Number(fromIndex) + 1; index < source.length; index += 1) {
      const entry = source[index];
      if (entry?.role === 'user') break;
      if (entry?.role === 'assistant' && String(entry.model || '').trim()) {
        return String(entry.model).trim();
      }
    }
    return '';
  }

  function prepareRegeneration(messages, assistantIndex) {
    const source = normalizeMessages(messages);
    const index = Number(assistantIndex);
    if (!Number.isInteger(index) || source[index]?.role !== 'assistant') return null;
    const userIndex = findPreviousUserIndex(source, index);
    if (userIndex < 0) return null;
    return {
      context: source.slice(0, userIndex),
      prompt: String(source[userIndex].content || '').trim(),
      model: String(source[index].model || '').trim(),
      sourceIndex: userIndex,
    };
  }

  function prepareMessageEdit(messages, userIndex, nextContent) {
    const source = normalizeMessages(messages);
    const index = Number(userIndex);
    const prompt = String(nextContent || '').trim();
    if (!Number.isInteger(index) || source[index]?.role !== 'user' || !prompt) return null;
    return {
      context: source.slice(0, index),
      prompt,
      model: findFollowingAssistantModel(source, index),
      sourceIndex: index,
    };
  }

  const api = {
    findPreviousUserIndex,
    findFollowingAssistantModel,
    prepareRegeneration,
    prepareMessageEdit,
  };
  global.POFChatMessageActions = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
