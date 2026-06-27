// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const proxyquire = require('proxyquire').noCallThru();

describe('staticHandlers Ollama streaming', () => {
  it('forwards NDJSON stream events and the final response in order', async () => {
    const posted = [];
    const proc = new EventEmitter();
    proc.stdout = new PassThrough();
    proc.stderr = new PassThrough();
    let spawnedArgs = [];

    const staticHandlers = proxyquire('../src/static/staticHandlers', {
      vscode: { workspace: { getConfiguration: () => ({ inspect: () => ({}) }) } },
      child_process: { spawn: (_python, args) => {
        spawnedArgs = args;
        return proc;
      } },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || '' }),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (value) => value },
      './pluginState': {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
      '../shared/authService': { AuthService: class {} },
      '../shared/authConfig': { resolveAuthServerUrl: () => 'http://localhost' },
    });

    const handlers = staticHandlers({
      root: '/repo',
      panel: { webview: { postMessage: (message) => posted.push(message) } },
      context: { globalState: { get: () => ({}) } },
    });

    await handlers.hubOllamaPrompt({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen3:8b',
      prompt: 'Analyse',
      temperature: 0.2,
      top_p: 0.75,
      max_tokens: 1536,
    });

    expect(spawnedArgs).to.include.members([
      '--temperature', '0.2',
      '--top-p', '0.75',
      '--max-tokens', '1536',
    ]);

    proc.stdout.write('{"type":"token","content":"Bonjour\\n"}\n');
    proc.stdout.write('{"type":"token","content":"  monde"}\n');
    proc.stdout.write(
      '{"type":"done","ok":true,"response":"Bonjour\\n  monde","tool_calls":[],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16,"request_total_tokens":16}}\n',
    );
    proc.stdout.end();
    proc.emit('close', 0);
    await new Promise((resolve) => setTimeout(resolve, 140));

    expect(posted).to.deep.equal([
      {
        type: 'hubOllamaStream',
        event: { type: 'token', content: 'Bonjour\n  monde', fragments: 2 },
        model: 'qwen3:8b',
      },
      {
        type: 'hubOllamaResult',
        ok: true,
        model: 'qwen3:8b',
        output: 'Bonjour\n  monde',
        usage: {
          prompt_tokens: 12,
          completion_tokens: 4,
          total_tokens: 16,
          request_total_tokens: 16,
        },
        error: undefined,
      },
    ]);
  });

  it('persists the selected Ollama model in extension global state', async () => {
    const updates = [];
    const staticHandlers = proxyquire('../src/static/staticHandlers', {
      vscode: { workspace: { getConfiguration: () => ({ inspect: () => ({}) }) } },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || '' }),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (value) => value },
      './pluginState': {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
      '../shared/authService': { AuthService: class {} },
      '../shared/authConfig': { resolveAuthServerUrl: () => 'http://localhost' },
    });

    const handlers = staticHandlers({
      root: '/repo',
      panel: { webview: { postMessage: () => {} } },
      context: {
        globalState: {
          get: () => '',
          update: async (key, value) => updates.push([key, value]),
        },
      },
    });

    await handlers.hubOllamaModelSelected({ model: 'gemma4:e4b' });

    expect(updates).to.deep.equal([['pof.ollamaModel', 'gemma4:e4b']]);
  });

  it('cancels the active Ollama bridge without sending a second result', async () => {
    const posted = [];
    const proc = new EventEmitter();
    proc.stdout = new PassThrough();
    proc.stderr = new PassThrough();
    proc.kill = (signal) => {
      proc.killedWith = signal;
      proc.emit('close', null);
      return true;
    };

    const staticHandlers = proxyquire('../src/static/staticHandlers', {
      vscode: { workspace: { getConfiguration: () => ({ inspect: () => ({}) }) } },
      child_process: { spawn: () => proc },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || '' }),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (value) => value },
      './pluginState': {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
      '../shared/authService': { AuthService: class {} },
      '../shared/authConfig': { resolveAuthServerUrl: () => 'http://localhost' },
    });
    const sharedHandlers = require('../src/shared/sharedHandlers');
    const config = {
      root: '/repo',
      panel: { webview: { postMessage: (message) => posted.push(message) } },
      context: { globalState: { get: () => ({}) } },
    };
    const handlers = {
      ...sharedHandlers(config),
      ...staticHandlers(config),
    };

    await handlers.hubOllamaPrompt({
      model: 'qwen3:8b',
      prompt: 'Analyse',
      requestId: 'request-ollama',
    });
    handlers.hubAiCancel({ requestId: 'request-ollama' });

    expect(proc.killedWith).to.equal('SIGTERM');
    expect(posted).to.deep.equal([{
      type: 'hubOllamaResult',
      ok: false,
      cancelled: true,
      model: 'qwen3:8b',
      output: '',
      requestId: 'request-ollama',
    }]);
  });
});
