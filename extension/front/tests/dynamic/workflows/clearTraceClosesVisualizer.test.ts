const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

describe('dynamic/workflows clear trace history', () => {
  it('clear-history-emits-clear-request-without-reopening-stale-trace', () => {
    const posted: unknown[] = [];
    const opened: unknown[] = [];
    const status: string[] = [];
    const clearButton = createElement('button');
    const historyList = createElement('div');
    const documentRef = createDocument();

    const controller = loadPayloadHistoryController().initPayloadHistoryController({
      document: documentRef,
      dynamicTraceHistory: historyList,
      btnClearDynamicTraceHistory: clearButton,
      postMessage: (message: unknown) => posted.push(message),
      setDynamicTraceStatus: (message: string) => status.push(message),
      openVisualizer: (item: unknown) => opened.push(item),
      getDynamicTraceHistoryState: () => ({
        activeTracePath: '/tmp/pof/output.run-1-a.json',
        items: [
          { path: '/tmp/pof/output.run-1-a.json', runId: 1, active: true, steps: 4 }
        ]
      }),
      setDynamicTraceHistoryState: () => {},
      getBinaryPath: () => 'examples/pwncollege/latent-leakage-hard',
      runBtn: { disabled: false }
    });

    controller.clearHistory();

    expect(posted).to.deep.equal([{ type: 'clearDynamicTraceHistory' }]);
    expect(opened).to.deep.equal([]);
    expect(status[0]).to.equal('Nettoyage des anciennes traces...');
  });

  it('runtime-session-clear-removes-current-trace-and-calls-runtime-clear', () => {
    const runtimeNavSlot = createElement('div');
    const cleared: unknown[] = [];
    const shownPanels: string[] = [];
    const documentRef = createDocument({ runtimeNavSlot });
    const controller = loadRuntimeSessionController({
      POFHubRuntime: {
        loadTrace: () => {},
        clearTrace: () => cleared.push({ type: 'clearTrace' })
      }
    }).initRuntimeSessionController({
      document: documentRef,
      showPanel: (panel: string) => shownPanels.push(panel),
      fallbackRenderer: {
        clearPanel: () => cleared.push({ type: 'fallbackClear' })
      }
    });
    cleared.length = 0;

    controller.handleMessage({
      type: 'dynamicTraceReady',
      traceRunId: '9',
      tracePath: '/tmp/pof/output.run-9-a.json',
      snapshots: [{ step: 1, func: 'main' }],
      meta: { binary: '/repo/chal' }
    });
    expect(runtimeNavSlot.children).to.have.length(1);
    expect(shownPanels).to.deep.equal(['runtime']);

    controller.handleMessage({
      type: 'dynamicTraceCleared',
      tracePath: '/tmp/pof/output.run-9-a.json'
    });

    expect(runtimeNavSlot.children).to.have.length(0);
    expect(cleared).to.deep.equal([{ type: 'clearTrace' }]);
  });

  it('runtime-session-passes-analysisByStep-through-to-POFHubRuntime-loadTrace', () => {
    const runtimeNavSlot = createElement('div');
    const documentRef = createDocument({ runtimeNavSlot });
    const loadedTraces: unknown[] = [];
    const analysisByStepFixture = {
      '1': { frame: { slots: [], basePointer: '0x1000' }, control: { savedBpAddr: '0x1000' } }
    };
    const controller = loadRuntimeSessionController({
      POFHubRuntime: {
        loadTrace: (data: unknown) => loadedTraces.push(data),
        clearTrace: () => {}
      }
    }).initRuntimeSessionController({
      document: documentRef,
      showPanel: () => {},
      fallbackRenderer: { clearPanel: () => {} }
    });

    controller.handleMessage({
      type: 'dynamicTraceReady',
      traceRunId: '9',
      tracePath: '/tmp/pof/output.run-9-a.json',
      snapshots: [{ step: 1, func: 'main' }],
      meta: { binary: '/repo/chal' },
      analysisByStep: analysisByStepFixture
    });

    expect(loadedTraces).to.have.length(1);
    expect((loadedTraces[0] as any).analysisByStep).to.deep.equal(analysisByStepFixture);
  });

  it('deleting-active-history-trace-notifies-hub-and-standalone-visualizer-clear', async () => {
    const fsMod = require('fs');
    const sinon = require('sinon');
    const proxyquire = require('proxyquire');
    const vscode = require('vscode');
    const realExistsSync = fsMod.existsSync.bind(fsMod);
    const realReaddirSync = fsMod.readdirSync.bind(fsMod);
    const realStatSync = fsMod.statSync.bind(fsMod);
    const outputPaths = new Set([
      '/tmp/pof',
      '/tmp/pof/output.run-1-a.json',
      '/tmp/pof/output.run-1-a.disasm.asm'
    ]);
    const posted: unknown[] = [];
    const clearCurrentTrace = sinon.spy();
    let onMessage: Function | null = null;

    sinon.stub(fsMod, 'existsSync').callsFake((targetPath: string) => (
      String(targetPath).startsWith('/tmp/pof') ? outputPaths.has(String(targetPath)) : realExistsSync(targetPath)
    ));
    sinon.stub(fsMod, 'readdirSync').callsFake((targetPath: string, ...args: unknown[]) => (
      String(targetPath) === '/tmp/pof' ? ['output.run-1-a.json'] : realReaddirSync(targetPath, ...args as [])
    ));
    sinon.stub(fsMod, 'statSync').callsFake((targetPath: string, ...args: unknown[]) => (
      String(targetPath).startsWith('/tmp/pof')
        ? { mtimeMs: 100, isDirectory: () => String(targetPath) === '/tmp/pof' }
        : realStatSync(targetPath, ...args as [])
    ));
    sinon.stub(fsMod, 'unlinkSync').callsFake((targetPath: string) => {
      outputPaths.delete(String(targetPath));
    });

    vscode.workspace.workspaceFolders = [{ uri: { fsPath: '/repo' } }];
    vscode.Uri = { file: (fsPath: string) => ({ fsPath }) };
    vscode.ViewColumn = { Beside: 2 };
    vscode.window.onDidChangeTextEditorSelection = sinon.stub().returns({ dispose: () => {} });
    vscode.window.createWebviewPanel = sinon.stub().returns({
      disposed: false,
      onDidDispose: sinon.stub().returns({ dispose: () => {} }),
      webview: {
        html: '',
        postMessage: (message: unknown) => posted.push(message),
        onDidReceiveMessage: (handler: Function) => {
          onMessage = handler;
          return { dispose: () => {} };
        }
      }
    });

    try {
      const { createHub } = proxyquire('../../../../src/static/hub', {
        '../shared/webview': { getHubContent: () => '<!doctype html>' },
        './handlers': { createHandlers: () => ({}) }
      });
      const openVisualizerWebview = Object.assign(() => {}, { clearCurrentTrace });
      const openHub = createHub({
        context: {
          extensionUri: {},
          subscriptions: [],
          workspaceState: { get: () => ({}), update: async () => {} },
          globalState: { get: () => ({}), update: async () => {} }
        },
        logChannel: { appendLine: () => {}, append: () => {} },
        getTempDir: () => '/tmp/pof',
        ensureTempDir: () => '/tmp/pof',
        detectPythonExecutable: () => '/usr/bin/python3',
        readTraceJson: () => ({
          snapshots: [{ step: 1, func: 'main' }],
          meta: { trace_run_id: 1, binary: '/repo/chal' }
        }),
        writeTraceJson: () => {},
        setViewMode: () => {},
        openVisualizerWebview
      });
      openHub();
      await onMessage?.({ type: 'openDynamicTraceHistory', tracePath: '/tmp/pof/output.run-1-a.json' });
      await onMessage?.({ type: 'deleteDynamicTraceHistory', tracePath: '/tmp/pof/output.run-1-a.json' });
    } finally {
      sinon.restore();
    }

    expect(posted.some((message: any) => message?.type === 'dynamicTraceCleared')).to.equal(true);
    expect(clearCurrentTrace.calledOnce).to.equal(true);
    expect(clearCurrentTrace.firstCall.args[0]).to.include({
      tracePath: '/tmp/pof/output.run-1-a.json',
      reason: 'deleted'
    });
    const historyMessages = posted.filter((message: any) => message?.type === 'dynamicTraceHistory') as any[];
    expect(historyMessages[historyMessages.length - 1].activeTracePath).to.equal('');
  });

  function loadPayloadHistoryController() {
    const source = fs.readFileSync(
      path.resolve(__dirname, '../../../dynamic/payloadHistoryController.js'),
      'utf8'
    );
    const context: any = { window: {}, console };
    context.window.POFHub = {};
    vm.runInNewContext(source, context, { filename: 'payloadHistoryController.js' });
    return context.window.POFHubPayloadHistoryController;
  }

  function loadRuntimeSessionController(extraWindow: Record<string, unknown> = {}) {
    const source = fs.readFileSync(
      path.resolve(__dirname, '../../../dynamic/runtimeSessionController.js'),
      'utf8'
    );
    const context: any = {
      window: { ...extraWindow },
      console
    };
    context.window.POFHub = {};
    vm.runInNewContext(source, context, { filename: 'runtimeSessionController.js' });
    return context.window.POFHubRuntimeSessionController;
  }

  function createElement(tagName: string) {
    return {
      tagName,
      className: '',
      textContent: '',
      disabled: false,
      dataset: {} as Record<string, string>,
      children: [] as unknown[],
      classList: {
        add() {},
        toggle() {}
      },
      setAttribute() {},
      appendChild(child: unknown) {
        this.children.push(child);
        return child;
      },
      replaceChildren() {
        this.children = [];
      },
      addEventListener() {}
    };
  }

  function createDocument(elements: Record<string, any> = {}) {
    return {
      createElement,
      getElementById: (id: string) => elements[id] || null,
      querySelectorAll: () => []
    };
  }
});
