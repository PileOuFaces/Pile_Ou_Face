const { expect } = require('chai');

const chatHistory = require('../webview/shared/chatHistory');

describe('chat conversation history helpers', () => {
  const history = [
    {
      id: 'recent',
      title: 'Analyse sécurité',
      model: 'gemma4:e4b',
      updatedAt: 30,
      messages: [{ content: 'Recherche de vulnérabilités' }],
    },
    {
      id: 'old',
      title: 'Désassemblage',
      model: 'openai@gpt-4o',
      updatedAt: 10,
      messages: [{ content: 'Explique le point entrée' }],
    },
    {
      id: 'middle',
      title: 'Imports',
      model: 'gemma4:e4b',
      updatedAt: 20,
      messages: [{ content: 'Liste libc et printf' }],
    },
  ];

  it('searches titles, models and message content without accents', () => {
    expect(chatHistory.filterAndSortConversations(history, 'securite').map((item) => item.id))
      .to.deep.equal(['recent']);
    expect(chatHistory.filterAndSortConversations(history, 'gpt-4o').map((item) => item.id))
      .to.deep.equal(['old']);
    expect(chatHistory.filterAndSortConversations(history, 'printf').map((item) => item.id))
      .to.deep.equal(['middle']);
  });

  it('sorts by date, title and model', () => {
    expect(chatHistory.filterAndSortConversations(history).map((item) => item.id))
      .to.deep.equal(['recent', 'middle', 'old']);
    expect(chatHistory.filterAndSortConversations(history, '', 'updated_asc').map((item) => item.id))
      .to.deep.equal(['old', 'middle', 'recent']);
    expect(chatHistory.filterAndSortConversations(history, '', 'title_asc').map((item) => item.id))
      .to.deep.equal(['recent', 'old', 'middle']);
    expect(chatHistory.filterAndSortConversations(history, '', 'model_asc').map((item) => item.id))
      .to.deep.equal(['recent', 'middle', 'old']);
  });

  it('normalizes renamed titles and limits their length', () => {
    const title = chatHistory.normalizeConversationTitle(`  Mon\n titre   ${'x'.repeat(100)}  `);
    expect(title).to.match(/^Mon titre /);
    expect(title.length).to.equal(80);
  });
});
