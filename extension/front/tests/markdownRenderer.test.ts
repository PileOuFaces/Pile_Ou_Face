const { expect } = require('chai');

const markdown = require('../webview/shared/markdownRenderer');

describe('secure markdown renderer', () => {
  it('parses the supported block elements', () => {
    const blocks = markdown.parseMarkdown([
      '# Rapport',
      '',
      '- premier',
      '- second',
      '',
      '| Nom | Valeur |',
      '| --- | --- |',
      '| entry | `0x401000` |',
      '',
      '```asm',
      'mov rax, rbx',
      '```',
    ].join('\n'));

    expect(blocks.map((block: { type: string }) => block.type)).to.deep.equal([
      'heading',
      'list',
      'table',
      'codeBlock',
    ]);
    expect(blocks[3]).to.include({
      language: 'asm',
      text: 'mov rax, rbx',
    });
  });

  it('parses inline emphasis without interpreting raw HTML', () => {
    const blocks = markdown.parseMarkdown(
      'Texte **important**, *italique*, `code` et <img src=x onerror=alert(1)>.',
    );

    expect(blocks).to.have.length(1);
    expect(blocks[0].children.map((node: { type: string }) => node.type)).to.include.members([
      'strong',
      'em',
      'code',
    ]);
    expect(JSON.stringify(blocks)).to.contain('<img src=x onerror=alert(1)>');
    expect(JSON.stringify(blocks)).not.to.contain('"type":"html"');
  });

  it('allows only explicit safe link protocols', () => {
    expect(markdown.normalizeSafeLink('https://example.com/doc')).to.equal(
      'https://example.com/doc',
    );
    expect(markdown.normalizeSafeLink('mailto:security@example.com')).to.equal(
      'mailto:security@example.com',
    );
    expect(markdown.normalizeSafeLink('javascript:alert(1)')).to.equal('');
    expect(markdown.normalizeSafeLink('data:text/html,boom')).to.equal('');
    expect(markdown.normalizeSafeLink('//example.com/path')).to.equal('');
  });

  it('replaces unsafe markdown links with their visible label', () => {
    const nodes = markdown.parseInline(
      '[documentation](https://example.com) [attaque](javascript:alert(1))',
    );

    expect(nodes[0]).to.include({
      type: 'link',
      href: 'https://example.com/',
    });
    expect(nodes.some((node: { type: string; text?: string }) => (
      node.type === 'text' && node.text === 'attaque'
    ))).to.equal(true);
  });
});
