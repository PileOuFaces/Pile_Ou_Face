// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const proxyquire = require('proxyquire').noCallThru();

describe('sharedHandlers AI provider streaming', () => {
  it('forwards cloud provider chunks and final token usage', async () => {
    const posted = [];
    const proc = new EventEmitter();
    proc.stdout = new PassThrough();
    proc.stderr = new PassThrough();
    proc.stdin = new PassThrough();

    let spawnedArgs = [];
    const sharedHandlers = proxyquire('../shared/sharedHandlers', {
      vscode: {
        window: {},
        Uri: { file: (value) => ({ fsPath: value }) },
      },
      child_process: { spawn: (_python, args) => {
        spawnedArgs = args;
        return proc;
      } },
      './fileManager': {},
      './utils': { detectPythonExecutable: () => '/usr/bin/python3', getExtensionPath: () => '' },
      './recentBinaries': {
        getRecentBinaries: () => [],
        rememberRecentBinary: () => [],
        forgetRecentBinary: () => [],
        clearRecentBinaries: () => [],
      },
    });
    const handlers = sharedHandlers({
      root: '/repo',
      panel: { webview: { postMessage: (message) => posted.push(message) } },
      context: { globalState: { get: () => ({}) } },
    });

    handlers.hubAiProviderPrompt({
      provider: 'openai',
      model: 'gpt-4o',
      prompt: 'Analyse',
      temperature: 0.4,
      top_p: 0.8,
      max_tokens: 2048,
    });

    expect(spawnedArgs).to.include.members([
      '--temperature', '0.4',
      '--top-p', '0.8',
      '--max-tokens', '2048',
    ]);

    proc.stdout.write('{"type":"token","content":"Bonjour"}\n');
    proc.stdout.write('{"type":"token","content":" API"}\n');
    proc.stdout.write(
      '{"type":"done","ok":true,"text":"Bonjour API","usage":{"prompt_tokens":18,"completion_tokens":2,"total_tokens":20}}\n',
    );
    proc.stdout.end();
    proc.emit('close', 0);
    await new Promise((resolve) => setTimeout(resolve, 140));

    expect(posted).to.deep.equal([
      {
        type: 'hubOllamaStream',
        event: { type: 'token', content: 'Bonjour API', fragments: 2 },
        model: 'openai@gpt-4o',
      },
      {
        type: 'hubOllamaResult',
        ok: true,
        model: 'openai@gpt-4o',
        output: 'Bonjour API',
        usage: {
          prompt_tokens: 18,
          completion_tokens: 2,
          total_tokens: 20,
        },
        error: undefined,
      },
    ]);
  });

  it('cancels an active cloud provider process', () => {
    const posted = [];
    const proc = new EventEmitter();
    proc.stdout = new PassThrough();
    proc.stderr = new PassThrough();
    proc.stdin = new PassThrough();
    proc.kill = (signal) => {
      proc.killedWith = signal;
      proc.emit('close', null);
      return true;
    };

    const sharedHandlers = proxyquire('../shared/sharedHandlers', {
      vscode: {
        window: {},
        Uri: { file: (value) => ({ fsPath: value }) },
      },
      child_process: { spawn: () => proc },
      './fileManager': {},
      './utils': { detectPythonExecutable: () => '/usr/bin/python3', getExtensionPath: () => '' },
      './recentBinaries': {
        getRecentBinaries: () => [],
        rememberRecentBinary: () => [],
        forgetRecentBinary: () => [],
        clearRecentBinaries: () => [],
      },
    });
    const handlers = sharedHandlers({
      root: '/repo',
      panel: { webview: { postMessage: (message) => posted.push(message) } },
      context: { globalState: { get: () => ({}) } },
    });

    handlers.hubAiProviderPrompt({
      provider: 'openai',
      model: 'gpt-4o',
      prompt: 'Analyse',
      requestId: 'request-cloud',
    });
    handlers.hubAiCancel({ requestId: 'request-cloud' });

    expect(proc.killedWith).to.equal('SIGTERM');
    expect(posted).to.deep.equal([{
      type: 'hubOllamaResult',
      ok: false,
      cancelled: true,
      model: 'openai@gpt-4o',
      output: '',
      requestId: 'request-cloud',
    }]);
  });
});
