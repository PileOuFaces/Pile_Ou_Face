const { expect } = require('chai');

const chatExport = require('../webview/shared/chatExport');

describe('chat conversation export', () => {
  const snapshot = chatExport.buildConversationExport({
    id: 'conv-1',
    title: 'Analyse du point d’entrée',
    exportedAt: '2026-06-21T12:00:00.000Z',
    model: 'gemma4:e4b',
    binaryPath: '/workspace/demo.elf',
    messages: [
      {
        role: 'user',
        content: 'Explique ce code.',
        ts: Date.parse('2026-06-21T11:58:00.000Z'),
      },
      {
        role: 'assistant',
        content: '## Résultat\n\nLe code initialise la pile.',
        model: 'gemma4:e4b',
        ts: Date.parse('2026-06-21T11:59:00.000Z'),
        usage: {
          requestPromptTokens: 120,
          requestCompletionTokens: 30,
          requestTotalTokens: 150,
        },
      },
    ],
  });

  it('builds a versioned JSON snapshot with cumulative usage', () => {
    expect(snapshot).to.deep.include({
      schema: 'pile-ou-face.ai-conversation.v1',
      id: 'conv-1',
      title: 'Analyse du point d’entrée',
      model: 'gemma4:e4b',
      binaryPath: '/workspace/demo.elf',
    });
    expect(snapshot.usage).to.deep.equal({
      promptTokens: 120,
      completionTokens: 30,
      totalTokens: 150,
    });
    expect(snapshot.messages).to.have.length(2);
  });

  it('formats readable Markdown while preserving assistant Markdown', () => {
    const markdown = chatExport.formatConversationMarkdown(snapshot);

    expect(markdown).to.contain('# Analyse du point d’entrée');
    expect(markdown).to.contain('- Modèle actif : gemma4:e4b');
    expect(markdown).to.contain('120 entrée · 30 sortie · 150 total');
    expect(markdown).to.contain('## Assistant — gemma4:e4b');
    expect(markdown).to.contain('## Résultat\n\nLe code initialise la pile.');
  });

  it('creates a safe portable suggested filename', () => {
    expect(chatExport.buildSuggestedName('Analyse du point d’entrée !')).to.equal(
      'analyse-du-point-d-entree',
    );
  });
});
