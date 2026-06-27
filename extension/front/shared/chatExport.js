// SPDX-License-Identifier: AGPL-3.0-only
(function initChatExport(global) {
  function normalizeUsage(raw) {
    const usage = raw && typeof raw === 'object' ? raw : {};
    const promptTokens = Math.max(
      0,
      Number(usage.requestPromptTokens || usage.request_prompt_tokens
        || usage.promptTokens || usage.prompt_tokens || 0),
    );
    const completionTokens = Math.max(
      0,
      Number(usage.requestCompletionTokens || usage.request_completion_tokens
        || usage.completionTokens || usage.completion_tokens || 0),
    );
    const totalTokens = Math.max(
      0,
      Number(usage.requestTotalTokens || usage.request_total_tokens
        || usage.totalTokens || usage.total_tokens || promptTokens + completionTokens),
    );
    return { promptTokens, completionTokens, totalTokens };
  }

  function buildConversationExport(options = {}) {
    const messages = Array.isArray(options.messages) ? options.messages : [];
    const exportedAt = String(options.exportedAt || new Date().toISOString());
    const normalizedMessages = messages.map((entry) => {
      const message = {
        role: String(entry?.role || 'system'),
        content: String(entry?.content || ''),
        timestamp: new Date(Number(entry?.ts || Date.now())).toISOString(),
      };
      if (entry?.model) message.model = String(entry.model);
      const usage = normalizeUsage(entry?.usage);
      if (usage.totalTokens) message.usage = usage;
      return message;
    });
    const usage = normalizedMessages.reduce(
      (total, message) => {
        total.promptTokens += Number(message.usage?.promptTokens || 0);
        total.completionTokens += Number(message.usage?.completionTokens || 0);
        total.totalTokens += Number(message.usage?.totalTokens || 0);
        return total;
      },
      { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
    );
    return {
      schema: 'pile-ou-face.ai-conversation.v1',
      id: String(options.id || ''),
      title: String(options.title || 'Conversation IA'),
      exportedAt,
      model: String(options.model || ''),
      binaryPath: String(options.binaryPath || ''),
      usage,
      messages: normalizedMessages,
    };
  }

  function formatConversationMarkdown(snapshot) {
    const lines = [
      `# ${snapshot.title || 'Conversation IA'}`,
      '',
      `- Exporté le : ${snapshot.exportedAt}`,
    ];
    if (snapshot.model) lines.push(`- Modèle actif : ${snapshot.model}`);
    if (snapshot.binaryPath) lines.push(`- Binaire : \`${snapshot.binaryPath}\``);
    lines.push(
      `- Tokens : ${snapshot.usage.promptTokens} entrée · `
        + `${snapshot.usage.completionTokens} sortie · ${snapshot.usage.totalTokens} total`,
      '',
      '---',
      '',
    );
    snapshot.messages.forEach((message) => {
      const role = message.role === 'user'
        ? 'Utilisateur'
        : (message.role === 'assistant' ? 'Assistant' : 'Système');
      const model = message.model ? ` — ${message.model}` : '';
      lines.push(
        `## ${role}${model}`,
        '',
        `_${message.timestamp}_`,
        '',
        message.content,
      );
      if (message.usage?.totalTokens) {
        lines.push(
          '',
          `> Tokens : ${message.usage.promptTokens} entrée · `
            + `${message.usage.completionTokens} sortie · ${message.usage.totalTokens} total`,
        );
      }
      lines.push('', '---', '');
    });
    return `${lines.join('\n').trim()}\n`;
  }

  function buildSuggestedName(title) {
    const slug = String(title || 'conversation-ia')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 56);
    return slug || 'conversation-ia';
  }

  const api = {
    buildConversationExport,
    buildSuggestedName,
    formatConversationMarkdown,
    normalizeUsage,
  };
  global.POFChatExport = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
