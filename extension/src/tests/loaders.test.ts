// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const sinon = require('sinon');
const { createLoaders } = require('../static/hub/loaders');

function makePanel() {
  const posted = [];
  return {
    posted,
    panel: {
      webview: {
        postMessage: (msg) => posted.push(msg),
      },
    },
  };
}

function makeLogChannel() {
  const lines = [];
  return {
    lines,
    logChannel: {
      appendLine: (l) => lines.push(l),
      append: (l) => lines.push(l),
    },
  };
}

/**
 * Build a minimal analysisCtx stub.
 * Override individual methods per test via `overrides`.
 */
function makeAnalysisCtx(overrides = {}) {
  return {
    resolveBinaryInputContext: (binaryPath, _meta) => ({
      binaryPath: binaryPath || '',
      absPath: binaryPath || '',
      exists: !!binaryPath && binaryPath !== '/nonexistent.bin',
      isDirectory: false,
      binaryMeta: _meta || {},
    }),
    buildPseudoRawInfo: sinon.stub().returns({ format: 'raw' }),
    loadBinaryHeaders: sinon.stub().resolves({ format: 'ELF', stripped: 'No', endianness: 'LSB', packers: 'none', packer_analysis: {} }),
    loadBinarySymbols: sinon.stub().resolves([{ name: 'main', addr: '0x400000' }]),
    collectSymbolNames: sinon.stub().callsFake((syms) => syms.map((s) => s.name)),
    resolveAnalysisArtifactsContext: sinon.stub().resolves({
      binaryPath: '/repo/demo.bin',
      absPath: '/repo/demo.bin',
      artifacts: null,
      baseName: 'demo',
      mappingPath: '/repo/.state/demo.mapping',
      discoveredPath: '/repo/.state/demo.discovered.json',
      hasAnalyzableBinary: true,
    }),
    ensureDiscoveredFunctionsArtifact: sinon.stub().resolves(null),
    ...overrides,
  };
}

// ── resolveCachedBinaryView ────────────────────────────────────────────────

describe('loaders — resolveCachedBinaryView', () => {
  it('returns cached value when cache hit and isCacheUsable returns true', async () => {
    const { panel, posted } = makePanel();
    const { logChannel, lines } = makeLogChannel();
    const readCache = sinon.stub().returns({ cached: true });
    const writeCache = sinon.stub();
    const compute = sinon.stub().resolves({ fresh: true });

    const loaders = createLoaders({
      panel,
      analysisCtx: makeAnalysisCtx(),
      root: '/root',
      storageDir: '/storage',
      runPythonJson: sinon.stub(),
      runPythonJsonViaFile: sinon.stub(),
      logChannel,
      fs: {},
      path: require('path'),
      readCache,
      writeCache,
      getStringsScript: () => '/scripts/strings.py',
      getSectionsScript: () => '/scripts/sections.py',
      getXrefsScript: () => '/scripts/xrefs.py',
    });

    // Directly test via hubLoadSymbols which uses resolveCachedBinaryView
    await loaders.hubLoadSymbols({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(readCache.calledOnce).to.equal(true);
    expect(compute.called).to.equal(false);
    expect(writeCache.called).to.equal(false);
    expect(posted[0]).to.deep.equal({ type: 'hubSymbols', symbols: { cached: true } });
    expect(lines).to.include('[cache] Symboles depuis cache');
  });

  it('calls compute and writes cache when cache miss', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const readCache = sinon.stub().returns(null);
    const writeCache = sinon.stub();
    const freshSymbols = [{ name: 'entry', addr: '0x401000' }];
    const analysisCtx = makeAnalysisCtx({
      loadBinarySymbols: sinon.stub().resolves(freshSymbols),
    });

    const loaders = createLoaders({
      panel,
      analysisCtx,
      root: '/root',
      storageDir: '/storage',
      runPythonJson: sinon.stub(),
      runPythonJsonViaFile: sinon.stub(),
      logChannel,
      fs: {},
      path: require('path'),
      readCache,
      writeCache,
      getStringsScript: () => '/scripts/strings.py',
      getSectionsScript: () => '/scripts/sections.py',
      getXrefsScript: () => '/scripts/xrefs.py',
    });

    await loaders.hubLoadSymbols({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(analysisCtx.loadBinarySymbols.calledOnce).to.equal(true);
    expect(writeCache.calledOnce).to.equal(true);
    expect(posted[0]).to.deep.equal({ type: 'hubSymbols', symbols: freshSymbols });
  });

  it('calls compute when isCacheUsable rejects the cached value', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const readCache = sinon.stub().returns([]); // empty array → isCacheUsable returns false
    const writeCache = sinon.stub();
    const freshStrings = [{ addr: '0x1000', value: 'hello', length: 5, encoding: 'utf-8' }];
    const runPythonJsonViaFile = sinon.stub().resolves(freshStrings);

    const loaders = createLoaders({
      panel,
      analysisCtx: makeAnalysisCtx(),
      root: '/root',
      storageDir: '/storage',
      runPythonJson: sinon.stub(),
      runPythonJsonViaFile,
      logChannel,
      fs: {},
      path: require('path'),
      readCache,
      writeCache,
      getStringsScript: () => '/scripts/strings.py',
      getSectionsScript: () => '/scripts/sections.py',
      getXrefsScript: () => '/scripts/xrefs.py',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', binaryMeta: null, minLen: '4', encoding: 'utf-8' });

    expect(runPythonJsonViaFile.calledOnce).to.equal(true);
    expect(writeCache.calledOnce).to.equal(true);
    expect(posted[0].strings).to.deep.equal(freshStrings);
  });
});

// ── hubLoadSymbols ─────────────────────────────────────────────────────────

describe('loaders — hubLoadSymbols', () => {
  it('posts empty symbols when binary does not exist', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({ binaryPath: '/nonexistent.bin', absPath: '/nonexistent.bin', exists: false, isDirectory: false, binaryMeta: {} }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadSymbols({ binaryPath: '/nonexistent.bin', binaryMeta: null });

    expect(posted).to.deep.equal([{ type: 'hubSymbols', symbols: [] }]);
  });

  it('posts empty symbols on compute error', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      loadBinarySymbols: sinon.stub().rejects(new Error('nm failed')),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadSymbols({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted).to.deep.equal([{ type: 'hubSymbols', symbols: [] }]);
  });
});

// ── hubLoadStrings ─────────────────────────────────────────────────────────

describe('loaders — hubLoadStrings', () => {
  it('posts empty strings when binary does not exist', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({ exists: false, isDirectory: false, absPath: '', binaryMeta: {} }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '', minLen: '4', encoding: 'utf-8' });

    expect(posted).to.deep.equal([{ type: 'hubStrings', strings: [] }]);
  });

  it('returns cache hit when cached array is non-empty', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const cachedStrings = [{ addr: '0x1000', value: 'ok', length: 2, encoding: 'utf-8' }];
    const readCache = sinon.stub().returns(cachedStrings);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8' });

    expect(posted[0].strings).to.deep.equal(cachedStrings);
  });

  it('never passes --section to Python regardless of requested section', async () => {
    const { panel } = makePanel();
    const { logChannel } = makeLogChannel();
    const runPythonJsonViaFile = sinon.stub().resolves([]);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile,
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '/scripts/strings.py', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8', section: '.rodata' });

    const args = runPythonJsonViaFile.firstCall.args[1];
    expect(args).to.not.include('--section');
  });

  it('filters strings by section using sections cache VA ranges', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const allStrings = [
      { addr: '0x401000', value: 'in-text', length: 7, encoding: 'utf-8' },
      { addr: '0x402000', value: 'in-data', length: 7, encoding: 'utf-8' },
      { addr: '0x403000', value: 'in-rodata', length: 9, encoding: 'utf-8' },
    ];
    const sections = [
      { name: '.text', virtual_address: '0x401000', size: 0x1000 },
      { name: '.data', virtual_address: '0x402000', size: 0x1000 },
      { name: '.rodata', virtual_address: '0x403000', size: 0x1000 },
    ];
    const readCache = sinon.stub();
    readCache.withArgs('/storage', '/repo/demo.bin', 'strings', sinon.match.any).returns(allStrings);
    readCache.withArgs('/storage', '/repo/demo.bin', 'sections').returns(sections);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8', section: '.text' });

    expect(posted[0].strings).to.deep.equal([
      { addr: '0x401000', value: 'in-text', length: 7, encoding: 'utf-8' },
    ]);
  });

  it('returns empty when requested section is not found in sections cache', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const allStrings = [{ addr: '0x401000', value: 'hello', length: 5, encoding: 'utf-8' }];
    const sections = [{ name: '.text', virtual_address: '0x401000', size: 0x1000 }];
    const readCache = sinon.stub();
    readCache.withArgs('/storage', '/repo/demo.bin', 'strings', sinon.match.any).returns(allStrings);
    readCache.withArgs('/storage', '/repo/demo.bin', 'sections').returns(sections);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8', section: '.nonexistent' });

    expect(posted[0].strings).to.deep.equal([]);
  });

  it('shows all strings when sections cache is unavailable for section filter', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const allStrings = [{ addr: '0x401000', value: 'hello', length: 5, encoding: 'utf-8' }];
    const readCache = sinon.stub();
    readCache.withArgs('/storage', '/repo/demo.bin', 'strings', sinon.match.any).returns(allStrings);
    readCache.withArgs('/storage', '/repo/demo.bin', 'sections').returns(null); // no sections cache

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8', section: '.text' });

    // Fallback: show all strings when sections cache is missing
    expect(posted[0].strings).to.deep.equal(allStrings);
  });

  it('excludes strings at addr 0x0 (PE import DLL names) when filtering by section', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const allStrings = [
      { addr: '0x0', value: 'kernel32.dll', length: 12, encoding: 'utf-8', source: 'pe_import' },
      { addr: '0x401000', value: 'in-text', length: 7, encoding: 'utf-8' },
    ];
    const sections = [{ name: '.text', virtual_address: '0x401000', size: 0x1000 }];
    const readCache = sinon.stub();
    readCache.withArgs('/storage', '/repo/demo.bin', 'strings', sinon.match.any).returns(allStrings);
    readCache.withArgs('/storage', '/repo/demo.bin', 'sections').returns(sections);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8', section: '.text' });

    expect(posted[0].strings).to.deep.equal([
      { addr: '0x401000', value: 'in-text', length: 7, encoding: 'utf-8' },
    ]);
  });

  it('always extracts with BASE_MIN_LEN=4 regardless of requested minLen', async () => {
    const { panel } = makePanel();
    const { logChannel } = makeLogChannel();
    const runPythonJsonViaFile = sinon.stub().resolves([]);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile,
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '/scripts/strings.py', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    // Request minLen=20 — Python should be called with 4 (BASE_MIN_LEN)
    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '20', encoding: 'utf-8' });

    const args = runPythonJsonViaFile.firstCall.args[1];
    const minLenIdx = args.indexOf('--min-len');
    expect(args[minLenIdx + 1]).to.equal('4');
  });

  it('filters in-process by requested minLen without re-extracting', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const cachedStrings = [
      { addr: '0x1000', value: 'hi', length: 2, encoding: 'utf-8' },
      { addr: '0x2000', value: 'hello', length: 5, encoding: 'utf-8' },
      { addr: '0x3000', value: 'helloworld', length: 10, encoding: 'utf-8' },
    ];
    const readCache = sinon.stub().returns(cachedStrings);
    const runPythonJsonViaFile = sinon.stub();

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile,
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '8', encoding: 'utf-8' });

    // Python must NOT be called — served from cache and filtered in-process
    expect(runPythonJsonViaFile.called).to.equal(false);
    // Only strings with length >= 8 are posted
    expect(posted[0].strings).to.deep.equal([
      { addr: '0x3000', value: 'helloworld', length: 10, encoding: 'utf-8' },
    ]);
  });

  it('clamps minLen to 64 max and still uses BASE_MIN_LEN=4 for extraction', async () => {
    const { panel } = makePanel();
    const { logChannel } = makeLogChannel();
    const runPythonJsonViaFile = sinon.stub().resolves([]);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile,
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '/scripts/strings.py', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '999', encoding: 'utf-8' });

    // 999 clamped to 64, extractMinLen = min(64, 4) = 4
    const args = runPythonJsonViaFile.firstCall.args[1];
    const minLenIdx = args.indexOf('--min-len');
    expect(args[minLenIdx + 1]).to.equal('4');
  });

  it('posts empty strings on compute error', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub().rejects(new Error('timeout')),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadStrings({ binaryPath: '/repo/demo.bin', minLen: '4', encoding: 'utf-8' });

    expect(posted).to.deep.equal([{ type: 'hubStrings', strings: [] }]);
  });
});

// ── hubLoadInfo ────────────────────────────────────────────────────────────

describe('loaders — hubLoadInfo', () => {
  it('posts error when binaryPath is empty', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({ binaryPath: '', absPath: '', exists: false, isDirectory: false, binaryMeta: {} }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadInfo({ binaryPath: '', binaryMeta: null });

    expect(posted[0]).to.deep.equal({ type: 'hubBinaryInfo', info: { error: 'Indiquez un chemin binaire.' } });
  });

  it('posts error when binary does not exist', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({ binaryPath: '/ghost.bin', absPath: '/ghost.bin', exists: false, isDirectory: false, binaryMeta: {} }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadInfo({ binaryPath: '/ghost.bin', binaryMeta: null });

    expect(posted[0].info.error).to.include('ghost.bin');
  });

  it('posts pseudo raw info when kind is raw', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const rawConfig = { baseAddr: '0x8000' };
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({
        binaryPath: '/raw.bin',
        absPath: '/raw.bin',
        exists: true,
        isDirectory: false,
        binaryMeta: { kind: 'raw', rawConfig },
      }),
      buildPseudoRawInfo: sinon.stub().returns({ format: 'raw', baseAddr: '0x8000' }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadInfo({ binaryPath: '/raw.bin', binaryMeta: { kind: 'raw', rawConfig } });

    expect(posted[0]).to.deep.equal({ type: 'hubBinaryInfo', info: { format: 'raw', baseAddr: '0x8000' } });
    expect(analysisCtx.buildPseudoRawInfo.calledOnce).to.equal(true);
  });

  it('returns cached info when isCacheUsable accepts the entry', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const cachedInfo = {
      format: 'ELF', stripped: 'No', endianness: 'LSB',
      packers: 'none', packer_analysis: { upx: false },
    };
    const readCache = sinon.stub().returns(cachedInfo);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadInfo({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0].info).to.deep.equal(cachedInfo);
  });

  it('recomputes when isCacheUsable rejects incomplete cached info', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    // Incomplete: missing endianness
    const incompleteCached = { format: 'ELF', stripped: 'No' };
    const freshInfo = {
      format: 'ELF', stripped: 'No', endianness: 'LSB',
      packers: 'none', packer_analysis: {},
    };
    const analysisCtx = makeAnalysisCtx({
      loadBinaryHeaders: sinon.stub().resolves(freshInfo),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(incompleteCached), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadInfo({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(analysisCtx.loadBinaryHeaders.calledOnce).to.equal(true);
    expect(posted[0].info).to.deep.equal(freshInfo);
  });

  it('posts error and logs when compute throws', async () => {
    const { panel, posted } = makePanel();
    const { logChannel, lines } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      loadBinaryHeaders: sinon.stub().rejects(new Error('read error')),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadInfo({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0].info.error).to.equal('read error');
    expect(lines.some((l) => l.includes('[headers]'))).to.equal(true);
  });
});

// ── hubLoadSections ────────────────────────────────────────────────────────

describe('loaders — hubLoadSections', () => {
  it('posts error when binaryPath is empty', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({ binaryPath: '', absPath: '', exists: false, isDirectory: false, binaryMeta: {} }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadSections({ binaryPath: '', binaryMeta: null });

    expect(posted[0]).to.deep.equal({ type: 'hubSections', sections: [], error: 'Indiquez un chemin binaire.' });
  });

  it('posts raw section when kind is raw', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({
        binaryPath: '/raw.bin',
        absPath: '/raw.bin',
        exists: true,
        isDirectory: false,
        binaryMeta: { kind: 'raw', rawConfig: { baseAddr: '0x1000' } },
      }),
    });
    const fs = { statSync: sinon.stub().returns({ size: 4096 }) };

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadSections({ binaryPath: '/raw.bin', binaryMeta: { kind: 'raw', rawConfig: { baseAddr: '0x1000' } } });

    expect(posted[0].sections).to.have.length(1);
    expect(posted[0].sections[0].name).to.equal('raw');
    expect(posted[0].sections[0].virtual_address).to.equal('0x1000');
    expect(posted[0].sections[0].size).to.equal(4096);
  });

  it('returns sections from cache', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const cachedSections = [{ name: '.text', offset: '0x1000', size: 512 }];
    const readCache = sinon.stub().returns(cachedSections);

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache, writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadSections({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0].sections).to.deep.equal(cachedSections);
  });

  it('handles object response with .sections property from compute', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const sectionList = [{ name: '.data', size: 256 }];
    const runPythonJson = sinon.stub().resolves({ sections: sectionList });

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson, runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '/scripts/sections.py', getXrefsScript: () => '',
    });

    await loaders.hubLoadSections({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0].sections).to.deep.equal(sectionList);
  });

  it('posts sections error and logs on compute throw', async () => {
    const { panel, posted } = makePanel();
    const { logChannel, lines } = makeLogChannel();
    const runPythonJson = sinon.stub().rejects(new Error('sections failed'));

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson, runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub().returns(null), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadSections({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0].sections).to.deep.equal([]);
    expect(posted[0].error).to.equal('sections failed');
    expect(lines.some((l) => l.includes('[sections]'))).to.equal(true);
  });
});

// ── hubLoadXrefs ───────────────────────────────────────────────────────────

describe('loaders — hubLoadXrefs', () => {
  it('returns immediately when addr is empty', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: { existsSync: sinon.stub().returns(true) }, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadXrefs({ addr: '', binaryPath: '/repo/demo.bin', mode: 'to' });

    expect(posted).to.have.length(0);
  });

  it('posts xrefs error when mapping does not exist and binary not analyzable', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveAnalysisArtifactsContext: sinon.stub().resolves({
        binaryPath: '/repo/demo.bin',
        absPath: '/repo/demo.bin',
        artifacts: null,
        baseName: 'demo',
        mappingPath: '/nonexistent/demo.mapping',
        discoveredPath: '',
        hasAnalyzableBinary: false,
      }),
    });
    const fs = { existsSync: sinon.stub().returns(false) };

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadXrefs({ addr: '0x401000', binaryPath: '/repo/demo.bin', mode: 'to' });

    const msg = posted[0];
    expect(msg.type).to.equal('hubXrefs');
    expect(msg.error).to.be.a('string');
    expect(msg.refs).to.deep.equal([]);
  });

  it('posts xrefs result on success', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const runPythonJson = sinon.stub().resolves({ refs: [{ addr: '0x402000' }], targets: [] });
    const fs = { existsSync: sinon.stub().returns(true) };

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson, runPythonJsonViaFile: sinon.stub(),
      logChannel, fs, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '/scripts/xrefs.py',
    });

    await loaders.hubLoadXrefs({ addr: '0x401000', binaryPath: '/repo/demo.bin', mode: 'to', requestKey: 'rk1' });

    expect(posted[0].refs).to.deep.equal([{ addr: '0x402000' }]);
    expect(posted[0].requestKey).to.equal('rk1');
    expect(posted[0].mode).to.equal('to');
  });

  it('posts empty xrefs and logs when compute throws', async () => {
    const { panel, posted } = makePanel();
    const { logChannel, lines } = makeLogChannel();
    const runPythonJson = sinon.stub().rejects(new Error('xrefs error'));
    const fs = { existsSync: sinon.stub().returns(true) };

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson, runPythonJsonViaFile: sinon.stub(),
      logChannel, fs, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.hubLoadXrefs({ addr: '0x401000', binaryPath: '/repo/demo.bin', mode: 'from' });

    expect(posted[0].refs).to.deep.equal([]);
    expect(lines.some((l) => l.includes('[Xrefs]'))).to.equal(true);
  });
});

// ── getSymbols ─────────────────────────────────────────────────────────────

describe('loaders — getSymbols', () => {
  it('returns symbol names when binary exists', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();

    const loaders = createLoaders({
      panel, analysisCtx: makeAnalysisCtx(), root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.getSymbols({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0]).to.deep.equal({ type: 'symbols', symbols: ['main'] });
  });

  it('returns empty symbols when binary does not exist', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      resolveBinaryInputContext: () => ({ exists: false, isDirectory: false, absPath: '', binaryMeta: {} }),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.getSymbols({ binaryPath: '/nonexistent.bin', binaryMeta: null });

    expect(posted[0]).to.deep.equal({ type: 'symbols', symbols: [] });
  });

  it('returns empty symbols when loadBinarySymbols throws', async () => {
    const { panel, posted } = makePanel();
    const { logChannel } = makeLogChannel();
    const analysisCtx = makeAnalysisCtx({
      loadBinarySymbols: sinon.stub().rejects(new Error('nm crash')),
    });

    const loaders = createLoaders({
      panel, analysisCtx, root: '/root', storageDir: '/storage',
      runPythonJson: sinon.stub(), runPythonJsonViaFile: sinon.stub(),
      logChannel, fs: {}, path: require('path'),
      readCache: sinon.stub(), writeCache: sinon.stub(),
      getStringsScript: () => '', getSectionsScript: () => '', getXrefsScript: () => '',
    });

    await loaders.getSymbols({ binaryPath: '/repo/demo.bin', binaryMeta: null });

    expect(posted[0]).to.deep.equal({ type: 'symbols', symbols: [] });
  });
});
