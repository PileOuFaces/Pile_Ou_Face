const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/visualizer debug trace JSON inspector', () => {
  let inspector: {
    buildTraceDebugSnapshot: Function;
    getTraceDebugCopyJson: Function;
    renderTraceDebugInspector: Function;
    clearTraceDebugInspector: Function;
    isTraceDebugInspectorEnabled: Function;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../webview/dynamic/app/debugTraceInspector.js');
    inspector = await import(pathToFileURL(modulePath).href);
  });

  function buildDebugSnapshot(renderedId = 'challenge:rbp:buffer:-448:440:frame', selectedStep = 2) {
    return inspector.buildTraceDebugSnapshot({
      state: {
        traceRunId: '7',
        currentStep: selectedStep,
        selectedFunction: 'challenge',
        snapshots: [
          { step: 1, func: 'main', rip: '0x401000' },
          { step: 2, func: 'challenge', rip: '0x401ec8' }
        ],
        risks: [],
        diagnostics: [{ step: 2, kind: 'buffer_overflow', severity: 'warning' }],
        crash: null,
        analysisByStep: {},
        enrichment: { byStep: {} },
        meta: {
          trace_run_id: 7,
          binary: 'latent-leakage-hard',
          binary_metadata: {
            binary: {
              path: '/tmp/latent-leakage-hard',
              format: 'ELF',
              arch: 'x86_64',
              bits: 64,
              entry: '0x401050',
              base: '0x400000',
              pie: false,
              stripped: false
            },
            sections: [{ name: '.text', vaddr: '0x401000', size: 512, offset: '0x1000', kind: 'TEXT', flags: ['READ', 'EXEC'], source: 'LIEF' }],
            symbols: [{ name: 'challenge', addr: '0x401ec8', size: 120, kind: 'FUNC', binding: 'GLOBAL', section: '.text', source: 'LIEF/symtab' }],
            functions: [{ name: 'challenge', start: '0x401ec8', end: '0x401f40', source: 'LIEF/symtab' }],
            plt: [{ name: 'printf', plt_addr: '0x401040', got_addr: '0x404000', source: 'LIEF/PLT' }],
            runtime: { base: '0x400000', entry: '0x401050', pie: false },
            diagnostics: []
          }
        }
      },
      snap: { step: 2, func: 'challenge', rip: '0x401ec8', instr: 'call gets' },
      analysis: { function: { name: 'challenge' } },
      mcp: { model: { name: 'challenge', locals: [] } },
      currentStep: selectedStep,
      stackWorkspace: {
        frameModel: {
          functionName: 'challenge',
          debug: {
            requestedFunction: 'challenge',
            resolvedFunction: 'challenge',
            rejectedReason: ''
          },
          entries: [
            { key: renderedId, name: 'buffer', kind: 'buffer', offset: -448, size: 440 }
          ]
        }
      }
    });
  }

  function buildMismatchDebugSnapshot() {
    return inspector.buildTraceDebugSnapshot({
      state: {
        traceRunId: '7',
        currentStep: 1,
        selectedFunction: 'challenge',
        snapshots: [
          { step: 1, func: 'main', rip: '0x401000' },
          { step: 2, func: 'challenge', rip: '0x401ec8' }
        ],
        diagnostics: [],
        meta: { trace_run_id: 7, binary: 'latent-leakage-hard' }
      },
      snap: { step: 1, func: 'main', rip: '0x401000' },
      analysis: { function: { name: 'main' } },
      mcp: { model: { name: 'main', locals: [] } },
      currentStep: 1,
      stackWorkspace: {
        frameModel: {
          functionName: 'challenge',
          emptyText: 'challenge() is selected, but the current trace step is still in main().',
          debug: {
            requestedFunction: 'challenge',
            rejectedFunction: 'main',
            rejectedReason: 'function_mismatch',
            firstStepForActiveFunction: 2,
            mismatchExplanation: 'challenge() is selected, but the current trace step is still in main().'
          },
          entries: []
        }
      }
    });
  }

  class FakeClassList {
    values = new Set<string>();

    add(value: string) {
      this.values.add(value);
    }

    toggle(value: string, force?: boolean) {
      if (force === true) {
        this.values.add(value);
        return true;
      }
      if (force === false) {
        this.values.delete(value);
        return false;
      }
      if (this.values.has(value)) {
        this.values.delete(value);
        return false;
      }
      this.values.add(value);
      return true;
    }
  }

  class FakeElement {
    tagName: string;
    id = '';
    className = '';
    hidden = false;
    textContent = '';
    innerHTML = '';
    type = '';
    open = false;
    children: FakeElement[] = [];
    parentNode: FakeElement | null = null;
    classList = new FakeClassList();
    onclick: Function | null = null;
    private attrs = new Map<string, string>();
    private listeners = new Map<string, Function[]>();

    constructor(tagName: string) {
      this.tagName = tagName.toLowerCase();
    }

    appendChild(child: FakeElement) {
      child.parentNode = this;
      this.children.push(child);
      return child;
    }

    replaceChildren(...children: FakeElement[]) {
      this.children = [];
      this.textContent = '';
      children.forEach((child) => this.appendChild(child));
    }

    addEventListener(name: string, listener: Function) {
      const listeners = this.listeners.get(name) || [];
      listeners.push(listener);
      this.listeners.set(name, listeners);
    }

    dispatchEventName(name: string) {
      (this.listeners.get(name) || []).forEach((listener) => listener());
    }

    click() {
      this.dispatchEventName('click');
      if (this.onclick) this.onclick();
    }

    setAttribute(name: string, value: string) {
      this.attrs.set(name, String(value));
    }

    getAttribute(name: string) {
      return this.attrs.get(name);
    }

    querySelector(selector: string): FakeElement | null {
      if (selector.startsWith('#')) {
        return this.findById(selector.slice(1));
      }
      if (selector.startsWith('.')) {
        return this.findByClass(selector.slice(1));
      }
      return this.findByTag(selector.toLowerCase());
    }

    private findById(id: string): FakeElement | null {
      if (this.id === id) return this;
      for (const child of this.children) {
        const found = child.findById(id);
        if (found) return found;
      }
      return null;
    }

    private findByClass(className: string): FakeElement | null {
      if (this.className.split(/\s+/).includes(className)) return this;
      for (const child of this.children) {
        const found = child.findByClass(className);
        if (found) return found;
      }
      return null;
    }

    private findByTag(tagName: string): FakeElement | null {
      if (this.tagName === tagName) return this;
      for (const child of this.children) {
        const found = child.findByTag(tagName);
        if (found) return found;
      }
      return null;
    }
  }

  class FakeDocument {
    body = new FakeElement('body');

    createElement(tagName: string) {
      return new FakeElement(tagName);
    }

    getElementById(id: string) {
      return this.body.querySelector(`#${id}`);
    }

    querySelector(selector: string) {
      return this.body.querySelector(selector);
    }
  }

  function buildFakeInspectorDocument() {
    const doc = new FakeDocument();
    const controls = doc.createElement('section');
    controls.className = 'controls';
    const toggle = doc.createElement('button');
    toggle.id = 'traceDebugToggle';
    toggle.hidden = false;
    toggle.textContent = 'Debug JSON';
    const copy = doc.createElement('button');
    copy.id = 'traceDebugCopy';
    copy.hidden = true;
    copy.textContent = 'Copy JSON';
    controls.appendChild(toggle);
    controls.appendChild(copy);

    const root = doc.createElement('section');
    root.id = 'traceDebugInspector';
    root.hidden = true;
    const body = doc.createElement('div');
    body.id = 'traceDebugBody';
    body.hidden = true;
    root.appendChild(body);

    doc.body.appendChild(controls);
    doc.body.appendChild(root);
    return { doc, toggle, copy, root, body };
  }

  function readWebviewHtml(relativePath: string) {
    return fs.readFileSync(path.resolve(__dirname, '../../..', relativePath), 'utf8');
  }

  function expectHiddenDebugControl(html: string) {
    expect(html).to.match(/<button[^>]+id=["']traceDebugToggle["'][^>]*>\s*(?:Debug JSON|Trace JSON)\s*<\/button>/);
    const controlLine = html.split('\n').find((line: string) => line.includes('id="traceDebugToggle"')) || '';
    expect(controlLine).to.match(/\bhidden\b/);
    expect(html).to.contain('id="traceDebugInspector"');
    expect(html).to.contain('id="traceDebugBody"');
  }

  function withTraceDebugUiEnabled(callback: Function) {
    const previous = (globalThis as any).__POF_TRACE_DEBUG_INSPECTOR;
    (globalThis as any).__POF_TRACE_DEBUG_INSPECTOR = true;
    try {
      return callback();
    } finally {
      if (previous === undefined) {
        delete (globalThis as any).__POF_TRACE_DEBUG_INSPECTOR;
      } else {
        (globalThis as any).__POF_TRACE_DEBUG_INSPECTOR = previous;
      }
    }
  }

  it('shows-active-and-current-function-plus-rendered-item-ids', () => {
    const debug = buildDebugSnapshot();

    expect(debug.summary).to.include({
      traceRunId: '7',
      activeFunction: 'challenge',
      currentFunction: 'challenge',
      selectedStep: 2,
      instructionAddress: '0x401ec8',
      rawStackModelFunction: 'challenge',
      selectedFrameFunction: 'challenge'
    });
    expect(debug.summary.renderedItemIds).to.deep.equal(['challenge:rbp:buffer:-448:440:frame']);
    expect(debug.summary.binaryMetadataAvailable).to.equal(true);
    expect(debug.snapshot.func).to.equal('challenge');
  });

  it('exposes-stale-main-rendered-ids-when-challenge-is-selected', () => {
    const debug = buildDebugSnapshot('main:rbp:buffer:-64:64:frame');

    expect(debug.summary.activeFunction).to.equal('challenge');
    expect(debug.summary.renderedItemIds).to.deep.equal(['main:rbp:buffer:-64:64:frame']);
  });

  it('copy-json-is-valid-json-with-debug-summary', () => {
    const debug = buildDebugSnapshot();
    const parsed = JSON.parse(inspector.getTraceDebugCopyJson(debug));

    expect(parsed.summary.traceRunId).to.equal('7');
    expect(parsed.summary.renderedItemIds).to.deep.equal(['challenge:rbp:buffer:-448:440:frame']);
  });

  it('standalone-graphical-stack-html-mounts-a-hidden-debug-json-control', () => {
    const html = readWebviewHtml('webview/dynamic/graphical-stack.html');

    expectHiddenDebugControl(html);
  });

  it('hub-runtime-html-mounts-the-same-hidden-debug-json-control', () => {
    const html = readWebviewHtml('webview/hub.html');

    expectHiddenDebugControl(html);
  });

  it('main-runtime-initializes-debug-inspector-with-current-trace-state', () => {
    const source = readWebviewHtml('webview/dynamic/app/main.js');

    expect(source).to.contain("from './debugTraceInspector.js'");
    expect(source).to.contain('renderTraceDebugInspector({');
    expect(source).to.contain('buildTraceDebugSnapshot({');
    expect(source).to.contain('state,');
    expect(source).to.contain('snap,');
    expect(source).to.contain('analysis,');
    expect(source).to.contain('mcp,');
    expect(source).to.contain('stackWorkspace,');
    expect(source).to.contain('currentStep');
    expect(source).to.contain('clearTraceDebugInspector({');
  });

  it('debug-json-button-opens-summary-and-lazy-loads-full-trace-when-enabled', () => {
    const debug = buildDebugSnapshot();
    const { doc, toggle, copy, root, body } = buildFakeInspectorDocument();

    withTraceDebugUiEnabled(() => {
      inspector.renderTraceDebugInspector({ documentRef: doc, debugSnapshot: debug });

      expect(root.hidden).to.equal(false);
      expect(toggle.hidden).to.equal(false);
      expect(copy.hidden).to.equal(false);
      expect(body.hidden).to.equal(true);

      toggle.click();

      expect(body.hidden).to.equal(false);
      expect(toggle.getAttribute('aria-expanded')).to.equal('true');
      expect(body.children[0].textContent).to.contain('"traceRunId": "7"');
      expect(body.children[0].textContent).to.contain('"activeFunction": "challenge"');
      expect(body.children[0].textContent).to.contain('"rawStackModelFunction": "challenge"');
      expect(body.children[0].textContent).to.contain('challenge:rbp:buffer:-448:440:frame');

      const snapshotDetails = body.children[1];
      expect(snapshotDetails.children[0].textContent).to.contain('"func": "challenge"');

      const fullTraceDetails = body.children[3];
      const fullTracePre = fullTraceDetails.children[0];
      expect(fullTracePre.textContent).to.equal('');
      fullTraceDetails.open = true;
      fullTraceDetails.dispatchEventName('toggle');
      expect(fullTracePre.textContent).to.contain('"snapshots"');
    });
  });

  it('renders-binary-metadata-debug-panel-when-trace-meta-has-normalized-model', () => {
    const debug = buildDebugSnapshot();
    const { doc, toggle, body } = buildFakeInspectorDocument();

    withTraceDebugUiEnabled(() => {
      inspector.renderTraceDebugInspector({ documentRef: doc, debugSnapshot: debug });
      toggle.click();

      const metadataDetails = body.children.find((child: any) => child.innerHTML.includes('Binary Metadata'));
      expect(metadataDetails).to.exist;
      expect(metadataDetails.children[0].textContent).to.equal('');
      metadataDetails.open = true;
      metadataDetails.dispatchEventName('toggle');
      expect(metadataDetails.children[0].textContent).to.contain('"Binary"');
      expect(metadataDetails.children[0].textContent).to.contain('"Sections"');
      expect(metadataDetails.children[0].textContent).to.contain('"Functions"');
      expect(metadataDetails.children[0].textContent).to.contain('"PLT/GOT"');
      expect(metadataDetails.children[0].textContent).to.contain('"challenge"');
    });
  });

  it('debug-json-panel-updates-when-selected-step-changes', () => {
    const { doc, toggle, body } = buildFakeInspectorDocument();

    withTraceDebugUiEnabled(() => {
      inspector.renderTraceDebugInspector({
        documentRef: doc,
        debugSnapshot: buildDebugSnapshot('challenge:rbp:buffer:-448:440:frame', 2)
      });
      toggle.click();
      expect(body.children[0].textContent).to.contain('"selectedStep": 2');

      inspector.renderTraceDebugInspector({
        documentRef: doc,
        debugSnapshot: buildDebugSnapshot('challenge:rbp:canary:-8:8:frame', 3)
      });

      expect(body.hidden).to.equal(false);
      expect(body.children[0].textContent).to.contain('"selectedStep": 3');
      expect(body.children[0].textContent).to.contain('challenge:rbp:canary:-8:8:frame');
    });
  });

  it('debug-json-summary-exposes-active-function-mismatch-for-rendered-main-ids', () => {
    const debug = buildDebugSnapshot('main:rbp:buffer:-64:64:frame');
    const { doc, toggle, body } = buildFakeInspectorDocument();

    withTraceDebugUiEnabled(() => {
      inspector.renderTraceDebugInspector({ documentRef: doc, debugSnapshot: debug });
      toggle.click();

      expect(body.children[0].textContent).to.contain('"activeFunction": "challenge"');
      expect(body.children[0].textContent).to.contain('main:rbp:buffer:-64:64:frame');
    });
  });

  it('debug-json-exposes-first-step-and-mismatch-explanation', () => {
    const debug = buildMismatchDebugSnapshot();

    expect(debug.summary).to.include({
      activeFunction: 'challenge',
      currentFunction: 'main',
      selectedStep: 1,
      firstStepForActiveFunction: 2,
      mismatchExplanation: 'challenge() is selected, but the current trace step is still in main().'
    });
    expect(debug.summary.renderedItemIds).to.deep.equal([]);
  });
});
