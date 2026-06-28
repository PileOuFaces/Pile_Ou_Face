const { expect } = require('chai');

const aiContext = require('../shared/aiContextActions');

describe('AI analysis context actions', () => {
  it('builds a focused CFG prompt with binary and navigation context', () => {
    const prompt = aiContext.buildAnalysisPrompt({
      view: 'cfg',
      binaryPath: '/tmp/sample.elf',
      binaryMeta: { kind: 'ELF', arch: 'x86-64' },
      functionName: 'main',
      address: '0x401000',
      content: '0x401000 -> 0x401020\n0x401020 -> 0x401040',
    });

    expect(prompt).to.contain('vue CFG');
    expect(prompt).to.contain('Fichier : /tmp/sample.elf');
    expect(prompt).to.contain('Architecture : x86-64');
    expect(prompt).to.contain('Fonction : main');
    expect(prompt).to.contain('0x401020 -> 0x401040');
  });

  it('keeps the beginning and end when a large context is clipped', () => {
    const clipped = aiContext.clipText(`BEGIN-${'x'.repeat(1000)}-END`, 300);

    expect(clipped.truncated).to.equal(true);
    expect(clipped.text).to.contain('BEGIN');
    expect(clipped.text).to.contain('contexte tronqué');
    expect(clipped.text).to.contain('END');
    expect(clipped.text.length).to.be.at.most(300);
  });

  it('includes search terms and filters in a search prompt', () => {
    const prompt = aiContext.buildAnalysisPrompt({
      view: 'search',
      query: 'password',
      filters: 'mode text, sensible à la casse',
      content: '0x1234 password context',
    });

    expect(prompt).to.contain('Recherche : password');
    expect(prompt).to.contain('Filtres : mode text');
    expect(prompt).to.contain('0x1234 password context');
  });

  it('rejects unsupported views and empty analysis content', () => {
    expect(aiContext.buildAnalysisPrompt({ view: 'unknown', content: 'x' })).to.equal('');
    expect(aiContext.buildAnalysisPrompt({ view: 'imports', content: '   ' })).to.equal('');
  });
});
