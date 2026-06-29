const { expect } = require('chai');

const pricing = require('../shared/aiPricing');

describe('AI pricing estimates', () => {
  const rules = [
    {
      id: 'openai',
      model: 'openai@gpt-*',
      inputPerMillion: 2.5,
      outputPerMillion: 10,
      effectiveDate: '2026-01-01',
    },
    {
      id: 'exact',
      model: 'openai@gpt-4o',
      inputPerMillion: 5,
      outputPerMillion: 15,
      effectiveDate: '2026-02-01',
    },
  ];

  it('prefers the most specific matching model rule', () => {
    expect(pricing.findRule(rules, 'openai@gpt-4o').id).to.equal('exact');
    expect(pricing.findRule(rules, 'openai@gpt-5').id).to.equal('openai');
  });

  it('uses the latest tariff already effective at the message date', () => {
    const datedRules = [
      { id: 'old', model: 'openai@gpt-4o', inputPerMillion: 1, effectiveDate: '2025-01-01' },
      { id: 'new', model: 'openai@gpt-4o', inputPerMillion: 2, effectiveDate: '2026-01-01' },
    ];

    expect(pricing.findRule(datedRules, 'openai@gpt-4o', '2025-06-01').id).to.equal('old');
    expect(pricing.findRule(datedRules, 'openai@gpt-4o', '2026-06-01').id).to.equal('new');
  });

  it('estimates input and output costs per million tokens', () => {
    const estimate = pricing.estimateUsageCost({
      requestPromptTokens: 1000,
      requestCompletionTokens: 500,
    }, 'openai@gpt-4o', rules);

    expect(estimate.inputCost).to.equal(0.005);
    expect(estimate.outputCost).to.equal(0.0075);
    expect(estimate.totalCost).to.equal(0.0125);
  });

  it('reports priced and unpriced messages in a conversation', () => {
    const result = pricing.estimateConversationCost([
      { role: 'assistant', model: 'openai@gpt-4o', usage: { promptTokens: 10 } },
      { role: 'assistant', model: 'gemma4:e4b', usage: { promptTokens: 10 } },
    ], rules);

    expect(result.pricedMessages).to.equal(1);
    expect(result.unpricedMessages).to.equal(1);
  });

  it('normalizes invalid and empty rules away', () => {
    expect(pricing.normalizeRules([
      { model: '', inputPerMillion: 2 },
      { model: 'free-model', inputPerMillion: 0, outputPerMillion: 0 },
      { model: 'paid-model', inputPerMillion: '1.5', outputPerMillion: '2' },
    ])).to.have.length(1);
  });
});
