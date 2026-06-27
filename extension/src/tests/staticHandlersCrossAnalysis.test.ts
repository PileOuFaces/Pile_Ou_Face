const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('hubLoadCrossAnalysis plugin disable', () => {
  afterEach(() => sinon.restore());

  function makeHandlers(execFile) {
    const staticHandlers = proxyquire('../src/static/staticHandlers', {
      child_process: { execFile },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({}),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (v) => v },
      './pluginState': {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (v) => v,
      },
    });
    const posted = [];
    const handlers = staticHandlers({
      root: '/workspace',
      panel: { webview: { postMessage: (m) => posted.push(m) } },
      context: { globalState: { get: () => ({}), update: async () => {} } },
    });
    return { handlers, posted };
  }

  it('forwards the plugin result directly for the investigation-oriented UI', async () => {
    const pluginResult = {
      ranked_functions: [{
        function: 'parse_input',
        addr: '0x401000',
        signal_count: 2,
        source_count: 2,
        dossier_count: 2,
        dominant_source: 'behavior',
        source_breakdown: [],
      }],
      coverage: { plugins_used: ['taint', 'behavior'], plugins_missing: [] },
      summary: {
        ranked_count: 1,
        total_dossiers: 2,
        total_signals: 2,
        high_or_above_count: 1,
      },
    };

    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      const cmdIndex = args.indexOf('invoke');
      const commandId = cmdIndex >= 0 ? args[cmdIndex + 1] : '';
      if (commandId === 'croisee.cross_analyze.run') {
        cb(null, JSON.stringify({ ok: true, result: pluginResult }), '');
      } else {
        cb(null, JSON.stringify({ ok: true, commands: [], command_sources: {} }), '');
      }
    });

    const { handlers, posted } = makeHandlers(execFile);

    await handlers.hubLoadCrossAnalysis({
      binaryPath: '/bin/foo',
      disabledFamilies: [],
    });

    const msg = posted.find((m) => m.type === 'hubCrossAnalysis');
    expect(msg).to.exist;
    expect(msg.result.summary).to.deep.include({
      ranked_count: 1,
      total_dossiers: 2,
      total_signals: 2,
      high_or_above_count: 1,
    });
    expect(msg.result.ranked_functions[0]).to.deep.include({
      signal_count: 2,
      source_count: 2,
      dossier_count: 2,
      function: 'parse_input',
      addr: '0x401000',
    });
    expect(msg.result.ranked_functions[0].dominant_source).to.equal('behavior');
  });

  it('passes disabled_families to the plugin and forwards its coverage result', async () => {
    const pluginResult = {
      ranked_functions: [],
      coverage: { plugins_used: ['taint', 'vulns', 'func_similarity'], plugins_missing: ['behavior', 'anti_analysis'] },
      insufficient: false,
    };

    let capturedPayload = null;
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      const cmdIndex = args.indexOf('invoke');
      const commandId = cmdIndex >= 0 ? args[cmdIndex + 1] : '';
      if (commandId === 'croisee.cross_analyze.run') {
        const payloadIndex = args.indexOf('--payload-json');
        if (payloadIndex >= 0) {
          capturedPayload = JSON.parse(args[payloadIndex + 1]);
        }
        cb(null, JSON.stringify({ ok: true, result: pluginResult }), '');
      } else {
        cb(null, JSON.stringify({ ok: true, commands: [], command_sources: {} }), '');
      }
    });

    const { handlers, posted } = makeHandlers(execFile);

    await handlers.hubLoadCrossAnalysis({
      binaryPath: '/bin/foo',
      disabledFamilies: ['malware'],
    });

    expect(capturedPayload).to.not.be.null;
    expect(capturedPayload.disabled_families).to.include('malware');

    const msg = posted.find((m) => m.type === 'hubCrossAnalysis');
    expect(msg).to.exist;
    const missing = msg.result?.coverage?.plugins_missing || [];
    expect(missing).to.include('behavior');
    expect(missing).to.include('anti_analysis');
  });

  it('does not add sources to plugins_missing when disabledFamilies is empty', async () => {
    const pluginResult = {
      ranked_functions: [],
      coverage: { plugins_used: ['taint', 'vulns', 'behavior', 'anti_analysis', 'func_similarity'], plugins_missing: [] },
    };

    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      const cmdIndex = args.indexOf('invoke');
      const commandId = cmdIndex >= 0 ? args[cmdIndex + 1] : '';
      if (commandId === 'croisee.cross_analyze.run') {
        cb(null, JSON.stringify({ ok: true, result: pluginResult }), '');
      } else {
        cb(null, JSON.stringify({ ok: true, commands: [], command_sources: {} }), '');
      }
    });

    const { handlers, posted } = makeHandlers(execFile);

    await handlers.hubLoadCrossAnalysis({
      binaryPath: '/bin/foo',
      disabledFamilies: [],
    });

    const msg = posted.find((m) => m.type === 'hubCrossAnalysis');
    expect(msg).to.exist;
    const missing = msg.result?.coverage?.plugins_missing || [];
    expect(missing).to.not.include('behavior');
    expect(missing).to.not.include('anti_analysis');
    expect(missing).to.not.include('taint');
    expect(missing).to.not.include('vulns');
    expect(missing).to.not.include('func_similarity');
  });

  it('marks all sources as missing when all families are disabled (forwarded from plugin)', async () => {
    const pluginResult = {
      ranked_functions: [],
      coverage: {
        plugins_used: [],
        plugins_missing: ['taint', 'vulns', 'behavior', 'anti_analysis', 'func_similarity'],
      },
      insufficient: true,
    };

    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      const cmdIndex = args.indexOf('invoke');
      const commandId = cmdIndex >= 0 ? args[cmdIndex + 1] : '';
      if (commandId === 'croisee.cross_analyze.run') {
        cb(null, JSON.stringify({ ok: true, result: pluginResult }), '');
      } else {
        cb(null, JSON.stringify({ ok: true, commands: [], command_sources: {} }), '');
      }
    });

    const { handlers, posted } = makeHandlers(execFile);

    await handlers.hubLoadCrossAnalysis({
      binaryPath: '/bin/foo',
      disabledFamilies: ['audit', 'malware', 'offensif'],
    });

    const msg = posted.find((m) => m.type === 'hubCrossAnalysis');
    expect(msg).to.exist;
    expect(msg.result.insufficient).to.equal(true);
    const missing = msg.result?.coverage?.plugins_missing || [];
    expect(missing).to.include.members(['taint', 'vulns', 'behavior', 'anti_analysis', 'func_similarity']);
  });
});
