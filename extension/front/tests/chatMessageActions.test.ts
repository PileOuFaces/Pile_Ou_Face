const { expect } = require('chai');

const actions = require('../shared/chatMessageActions');

describe('chat message edit and regeneration plans', () => {
  const conversation = [
    { role: 'user', content: 'Premier prompt' },
    { role: 'assistant', content: 'Première réponse', model: 'llama3.2:3b' },
    { role: 'user', content: 'Question suivante' },
    { role: 'assistant', content: 'Seconde réponse', model: 'openai@gpt-4o' },
  ];

  it('regenerates from the user prompt associated with an assistant response', () => {
    const plan = actions.prepareRegeneration(conversation, 3);

    expect(plan.context).to.deep.equal(conversation.slice(0, 2));
    expect(plan.prompt).to.equal('Question suivante');
    expect(plan.model).to.equal('openai@gpt-4o');
    expect(plan.sourceIndex).to.equal(2);
  });

  it('branches before an edited user message and reuses its response model', () => {
    const plan = actions.prepareMessageEdit(conversation, 2, 'Question corrigée');

    expect(plan.context).to.deep.equal(conversation.slice(0, 2));
    expect(plan.prompt).to.equal('Question corrigée');
    expect(plan.model).to.equal('openai@gpt-4o');
  });

  it('rejects invalid targets and empty edits', () => {
    expect(actions.prepareRegeneration(conversation, 0)).to.equal(null);
    expect(actions.prepareMessageEdit(conversation, 1, 'texte')).to.equal(null);
    expect(actions.prepareMessageEdit(conversation, 2, '   ')).to.equal(null);
  });

  it('stops model lookup at the next user branch', () => {
    const messages = [
      { role: 'user', content: 'Un' },
      { role: 'system', content: 'Erreur' },
      { role: 'user', content: 'Deux' },
      { role: 'assistant', content: 'Réponse', model: 'gemma4:e4b' },
    ];

    expect(actions.findFollowingAssistantModel(messages, 0)).to.equal('');
  });
});
