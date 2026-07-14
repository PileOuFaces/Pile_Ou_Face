// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const { createGraphRenderers } = require('../static/hub/graphRenderers');

function makePanel() {
  const posted = [];
  return {
    posted,
    panel: { webview: { postMessage: (msg) => posted.push(msg) } },
  };
}

function makeRenderer({ allowCache = false, mapping, discovered = null, runPythonJson = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-graph-renderers-'));
  const binaryPath = path.join(root, 'sample.elf');
  const mappingPath = path.join(root, 'sample.disasm.mapping.json');
  const symbolsPath = path.join(root, 'sample.symbols.json');
  const discoveredPath = path.join(root, 'sample.discovered.json');
  fs.writeFileSync(binaryPath, 'ELF');
  fs.writeFileSync(mappingPath, JSON.stringify(mapping || {
    binary: binaryPath,
    functions: [{ name: 'main', addr: '0x1000' }],
    lines: [{ addr: '0x1000', function_addr: '0x1000' }],
  }));
  fs.writeFileSync(symbolsPath, JSON.stringify([{ name: 'main', addr: '0x1000' }]));
  if (discovered) fs.writeFileSync(discoveredPath, JSON.stringify(discovered));

  const { panel, posted } = makePanel();
  const readAnalysisCacheEntry = sinon.stub().returns({ blocks: [{ addr: 'cached' }], edges: [], _cache_meta: {} });
  const writeAnalysisCacheEntry = sinon.stub();
  const resolveAnalysisArtifactsContext = sinon.stub().resolves({
    absPath: binaryPath,
    artifacts: { binaryMeta: { kind: 'native' } },
    baseName: 'sample',
    mappingPath,
    symbolsPath,
    discoveredPath,
    effectiveAbsPath: binaryPath,
    allowCache,
    hasAnalyzableBinary: true,
  });
  const runJson = runPythonJson || sinon.stub().callsFake(async (_script, args) => {
    if (args.includes('--symbols')) return { nodes: [{ id: 'computed' }], edges: [] };
    if (args.includes('--binary')) return [{ name: 'discovered_main', addr: '0x1000', confidence_score: 1 }];
    return { blocks: [{ addr: 'computed' }], edges: [] };
  });

  const renderer = createGraphRenderers({
    panel,
    analysisCtx: {
      resolveAnalysisArtifactsContext,
      resolveCachedAnalysisView: sinon.stub(),
      readAnalysisCacheEntry,
      writeAnalysisCacheEntry,
      ensureDiscoveredFunctionsArtifact: sinon.stub(),
      loadBinarySymbols: sinon.stub().resolves([{ name: 'main', addr: '0x1000' }]),
    },
    root,
    runPythonJson: runJson,
    storageDir: root,
    logChannel: { appendLine: sinon.spy(), append: sinon.spy() },
    vscode: {},
    fs,
    path,
    getCfgScript: () => path.join(root, 'cfg.py'),
    getCallGraphScript: () => path.join(root, 'call_graph.py'),
    getDiscoverFunctionsScript: () => path.join(root, 'discover.py'),
  });

  return {
    root,
    posted,
    renderer,
    readAnalysisCacheEntry,
    writeAnalysisCacheEntry,
    resolveAnalysisArtifactsContext,
    runPythonJson: runJson,
  };
}

describe('graph renderers cache behavior', () => {
  it('does not read CFG analysis cache but writes fresh CFG when useCache is false', async () => {
    const env = makeRenderer({ allowCache: false });

    await env.renderer.hubLoadCfg({ binaryPath: '/tmp/sample.elf', useCache: false });

    expect(env.resolveAnalysisArtifactsContext.firstCall.args[0].useCache).to.equal(false);
    expect(env.readAnalysisCacheEntry.called).to.equal(false);
    expect(env.writeAnalysisCacheEntry.calledOnce).to.equal(true);
    expect(env.posted[0].cfg.blocks[0].addr).to.equal('computed');
    fs.rmSync(env.root, { recursive: true, force: true });
  });

  it('does not read Call Graph analysis cache but writes fresh Call Graph when useCache is false', async () => {
    const env = makeRenderer({ allowCache: false });

    await env.renderer.hubLoadCallGraph({ binaryPath: '/tmp/sample.elf', useCache: false });

    expect(env.resolveAnalysisArtifactsContext.firstCall.args[0].useCache).to.equal(false);
    expect(env.readAnalysisCacheEntry.called).to.equal(false);
    expect(env.writeAnalysisCacheEntry.calledOnce).to.equal(true);
    expect(env.posted[0].callGraph.nodes[0].id).to.equal('computed');
    fs.rmSync(env.root, { recursive: true, force: true });
  });

  it('replaces a generic Mach-O header function with discovered functions', async () => {
    const env = makeRenderer({
      allowCache: false,
      mapping: {
        binary: '/tmp/sample.elf',
        functions: [{ name: '__mh_execute_header', addr: '0x0' }],
        lines: [{ addr: '0x0', function_addr: '0x0' }],
      },
    });

    await env.renderer.hubLoadCfg({ binaryPath: '/tmp/sample.elf', useCache: false });

    expect(env.posted[0].functions.map((fn) => fn.name)).to.deep.equal(['discovered_main']);
    fs.rmSync(env.root, { recursive: true, force: true });
  });
});
