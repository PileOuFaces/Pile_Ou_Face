// SPDX-License-Identifier: AGPL-3.0-only
(function initAiPricing(global) {
  function normalizeModel(value) {
    return String(value || '').trim().toLocaleLowerCase('en-US');
  }

  function normalizeRule(rule, index = 0) {
    const model = String(rule?.model || '').trim();
    const inputPerMillion = Math.max(0, Number(rule?.inputPerMillion || 0));
    const outputPerMillion = Math.max(0, Number(rule?.outputPerMillion || 0));
    if (!model || (!inputPerMillion && !outputPerMillion)) return null;
    return {
      id: String(rule?.id || `pricing-${index}`),
      model,
      inputPerMillion,
      outputPerMillion,
      effectiveDate: String(rule?.effectiveDate || '').trim(),
      currency: 'USD',
    };
  }

  function normalizeRules(rules) {
    return (Array.isArray(rules) ? rules : [])
      .map(normalizeRule)
      .filter(Boolean);
  }

  function modelMatches(pattern, model) {
    const normalizedPattern = normalizeModel(pattern);
    const normalizedModel = normalizeModel(model);
    if (!normalizedPattern || !normalizedModel) return false;
    if (!normalizedPattern.includes('*')) return normalizedPattern === normalizedModel;
    const escaped = normalizedPattern
      .split('*')
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*');
    return new RegExp(`^${escaped}$`, 'i').test(normalizedModel);
  }

  function findRule(rules, model, atDate = '') {
    const targetTime = atDate ? new Date(atDate).getTime() : Date.now();
    const matches = normalizeRules(rules).filter((rule) => {
      if (!modelMatches(rule.model, model)) return false;
      if (!rule.effectiveDate || Number.isNaN(targetTime)) return true;
      const effectiveTime = new Date(`${rule.effectiveDate}T00:00:00Z`).getTime();
      return Number.isNaN(effectiveTime) || effectiveTime <= targetTime;
    });
    matches.sort((left, right) => {
      const leftSpecificity = left.model.replace(/\*/g, '').length;
      const rightSpecificity = right.model.replace(/\*/g, '').length;
      if (rightSpecificity !== leftSpecificity) {
        return rightSpecificity - leftSpecificity;
      }
      return String(right.effectiveDate || '').localeCompare(String(left.effectiveDate || ''));
    });
    return matches[0] || null;
  }

  function estimateUsageCost(usage, model, rules, atDate = '') {
    const rule = findRule(rules, model, atDate);
    if (!rule) return null;
    const promptTokens = Math.max(
      0,
      Number(usage?.requestPromptTokens || usage?.promptTokens || 0),
    );
    const completionTokens = Math.max(
      0,
      Number(usage?.requestCompletionTokens || usage?.completionTokens || 0),
    );
    const inputCost = (promptTokens / 1000000) * rule.inputPerMillion;
    const outputCost = (completionTokens / 1000000) * rule.outputPerMillion;
    return {
      model: String(model || ''),
      rule,
      promptTokens,
      completionTokens,
      inputCost,
      outputCost,
      totalCost: inputCost + outputCost,
      currency: rule.currency,
    };
  }

  function estimateConversationCost(messages, rules, normalizeUsage) {
    const result = {
      totalCost: 0,
      pricedMessages: 0,
      unpricedMessages: 0,
      currency: 'USD',
    };
    (Array.isArray(messages) ? messages : []).forEach((entry) => {
      if (entry?.role !== 'assistant' || !entry?.usage) return;
      const usage = typeof normalizeUsage === 'function'
        ? normalizeUsage(entry.usage)
        : entry.usage;
      const estimate = estimateUsageCost(
        usage,
        entry.model,
        rules,
        entry.ts ? new Date(Number(entry.ts)).toISOString() : '',
      );
      if (!estimate) {
        result.unpricedMessages += 1;
        return;
      }
      result.totalCost += estimate.totalCost;
      result.pricedMessages += 1;
    });
    return result;
  }

  function formatUsd(value) {
    const amount = Math.max(0, Number(value || 0));
    const digits = amount < 0.01 ? 6 : 4;
    return `$${amount.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: digits,
    })}`;
  }

  const api = {
    estimateConversationCost,
    estimateUsageCost,
    findRule,
    formatUsd,
    modelMatches,
    normalizeRules,
  };
  global.POFAiPricing = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
