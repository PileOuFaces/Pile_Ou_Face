// SPDX-License-Identifier: AGPL-3.0-only
(function initChatContextBudget(global) {
  function estimateTokens(textOrLength) {
    const length = typeof textOrLength === 'number'
      ? textOrLength
      : String(textOrLength || '').length;
    return Math.max(0, Math.ceil(length / 4));
  }

  function roleLabel(role) {
    if (role === 'assistant') return 'Assistant';
    if (role === 'user') return 'Utilisateur';
    return 'Système';
  }

  function buildContextWindow(messages, options = {}) {
    const maxMessages = Math.max(1, Number(options.maxMessages || 12));
    const maxChars = Math.max(1, Number(options.maxChars || 1800));
    const maxMessageChars = Math.max(1, Number(options.maxMessageChars || 700));
    const source = (Array.isArray(messages) ? messages : [])
      .filter((entry) => String(entry?.content || '').trim());
    const selected = [];
    let clippedMessages = 0;
    let omittedChars = 0;
    let contextChars = 0;

    for (let index = source.length - 1; index >= 0; index -= 1) {
      const entry = source[index];
      const original = String(entry.content || '');
      let content = original;
      let clippedChars = 0;
      if (content.length > maxMessageChars) {
        clippedChars = content.length - maxMessageChars;
        content = `${content.slice(0, maxMessageChars)}...`;
      }
      const line = `${roleLabel(entry.role)}: ${content}`;
      if (selected.length >= maxMessages || (contextChars + line.length > maxChars && selected.length)) {
        omittedChars += source
          .slice(0, index + 1)
          .reduce((total, item) => total + String(item?.content || '').length, 0);
        break;
      }
      selected.push(line);
      contextChars += line.length;
      if (clippedChars) {
        omittedChars += clippedChars;
        clippedMessages += 1;
      }
    }

    selected.reverse();
    const includedMessages = selected.length;
    const omittedMessages = Math.max(0, source.length - includedMessages);
    const omittedRatio = source.length ? omittedMessages / source.length : 0;
    const significantTruncation = (
      omittedMessages >= 3
      || omittedRatio >= 0.25
      || clippedMessages >= 2
      || omittedChars >= 1000
    );
    return {
      lines: selected,
      sourceMessages: source.length,
      includedMessages,
      omittedMessages,
      clippedMessages,
      omittedChars,
      contextChars,
      estimatedTokens: estimateTokens(contextChars),
      truncated: omittedMessages > 0 || clippedMessages > 0,
      significantTruncation,
    };
  }

  function formatBudgetLabel(budget) {
    const tokenLabel = budget.estimatedTokens === 1 ? 'token' : 'tokens';
    const messageLabel = budget.sourceMessages === 1 ? 'message' : 'messages';
    const suffix = budget.truncated ? ' · tronqué' : '';
    return `Contexte · ~${budget.estimatedTokens} ${tokenLabel}`
      + ` · ${budget.includedMessages}/${budget.sourceMessages} ${messageLabel}${suffix}`;
  }

  function formatTruncationWarning(budget) {
    const details = [];
    if (budget.omittedMessages) {
      details.push(`${budget.omittedMessages} ancien(s) message(s) ignoré(s)`);
    }
    if (budget.clippedMessages) {
      details.push(`${budget.clippedMessages} message(s) raccourci(s)`);
    }
    return `Le contexte envoyé sera tronqué : ${details.join(' et ')}. Continuer ?`;
  }

  const api = {
    buildContextWindow,
    estimateTokens,
    formatBudgetLabel,
    formatTruncationWarning,
  };
  global.POFChatContextBudget = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
