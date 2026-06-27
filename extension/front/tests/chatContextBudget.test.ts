const { expect } = require('chai');

const contextBudget = require('../webview/shared/chatContextBudget');

describe('chat context budget', () => {
  it('keeps the newest messages inside the configured limits', () => {
    const messages = Array.from({ length: 6 }, (_, index) => ({
      role: index % 2 ? 'assistant' : 'user',
      content: `message-${index}-${'x'.repeat(20)}`,
    }));
    const budget = contextBudget.buildContextWindow(messages, {
      maxMessages: 3,
      maxChars: 500,
      maxMessageChars: 100,
    });

    expect(budget.includedMessages).to.equal(3);
    expect(budget.omittedMessages).to.equal(3);
    expect(budget.lines.join('\n')).to.contain('message-5');
    expect(budget.lines.join('\n')).not.to.contain('message-0');
    expect(budget.significantTruncation).to.equal(true);
  });

  it('clips oversized messages and reports approximate tokens', () => {
    const budget = contextBudget.buildContextWindow(
      [{ role: 'assistant', content: 'x'.repeat(1000) }],
      { maxMessageChars: 100, maxChars: 500 },
    );

    expect(budget.clippedMessages).to.equal(1);
    expect(budget.truncated).to.equal(true);
    expect(budget.contextChars).to.be.at.most(120);
    expect(budget.estimatedTokens).to.equal(Math.ceil(budget.contextChars / 4));
  });

  it('formats visible budget and warning labels', () => {
    const budget = contextBudget.buildContextWindow(
      Array.from({ length: 5 }, (_, index) => ({ role: 'user', content: `m${index}` })),
      { maxMessages: 2 },
    );

    expect(contextBudget.formatBudgetLabel(budget)).to.contain('2/5 messages · tronqué');
    expect(contextBudget.formatTruncationWarning(budget)).to.contain('3 ancien(s) message(s)');
  });
});
