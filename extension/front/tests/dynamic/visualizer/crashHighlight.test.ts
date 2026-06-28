const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('dynamic/visualizer corruption and diagnostic badges', () => {
  let mod: {
    buildExpertRowItems: (items: unknown[]) => Record<string, any>[];
    buildExpertRiskSummary: (rows: Record<string, any>[]) => Record<string, any>;
  };

  before(async () => {
    const globals = globalThis as typeof globalThis & {
      __stackExpertDom: { stack: null };
      __buildSimplifiedStackViewModel: () => { items: unknown[] };
      __renderStackEmptyState: Function;
    };
    globals.__stackExpertDom = { stack: null };
    globals.__buildSimplifiedStackViewModel = () => ({ items: [] });
    globals.__renderStackEmptyState = () => null;
    const modulePath = path.resolve(__dirname, '../../../dynamic/app/stackExpertView.js');
    let source = fs.readFileSync(modulePath, 'utf8');
    source = source.replace(
      /^import \{ buildSimplifiedStackViewModel \}.*$/m,
      'const buildSimplifiedStackViewModel = (...args) => globalThis.__buildSimplifiedStackViewModel(...args);'
    );
    source = source.replace(
      /^import \{ dom \}.*$/m,
      'const dom = globalThis.__stackExpertDom;'
    );
    source = source.replace(
      /^import \{ renderStackEmptyState \}.*$/m,
      'const renderStackEmptyState = (...args) => globalThis.__renderStackEmptyState(...args);'
    );
    source += '\n// dynamic crashHighlight isolated import\n';
    mod = await import(`data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`);
  });

  function slot(overrides: Record<string, unknown> = {}) {
    return {
      key: 'slot',
      selectionKey: 'slot',
      kind: 'local',
      title: 'buffer',
      subtitle: 'rbp-0x40',
      size: 16,
      badges: [],
      flags: [],
      diagnostics: [],
      ...overrides
    };
  }

  it('corrupted-return-address-gets-corrupt-and-ret-signals', () => {
    const rows = mod.buildExpertRowItems([
      slot({ kind: 'return_address', title: 'return address', diagnosticCorrupted: true, diagnosticSeverity: 'error' })
    ]);

    expect(rows[0].isReturnAddress).to.equal(true);
    expect(rows[0].isCorrupted).to.equal(true);
    expect(rows[0].badges).to.include('CORRUPT');
    expect(rows[0].badges).to.include('RET');
    expect(mod.buildExpertRiskSummary(rows).severity).to.equal('DANGER');
  });

  it('saved-rbp-corruption-gets-rbp-signal', () => {
    const rows = mod.buildExpertRowItems([
      slot({ kind: 'saved_bp', title: 'saved rbp', diagnosticCorrupted: true })
    ]);

    expect(rows[0].isSavedBp).to.equal(true);
    expect(rows[0].badges).to.include('RBP');
    expect(mod.buildExpertRiskSummary(rows).severity).to.equal('WARNING');
  });

  it('changed-slots-are-marked-without-user-badge-unless-payload-evidence-exists', () => {
    const rows = mod.buildExpertRowItems([
      slot({ changed: true, valuePreview: '0x41414141', bytesHex: '41 41 41 41', ascii: 'AAAA' }),
      slot({ key: 'payload', selectionKey: 'payload', payloadRelated: true })
    ]);

    expect(rows[0].badges).to.include('CHANGED');
    expect(rows[0].badges).to.not.include('USER');
    expect(rows[1].badges).to.include('USER');
  });
});
