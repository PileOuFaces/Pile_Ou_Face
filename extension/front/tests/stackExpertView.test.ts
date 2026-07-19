/* global describe, it, before, __dirname */
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

describe('stackExpertView — buildExpertRowItems', () => {
  let mod: {
    buildExpertRowItems: (items: unknown[]) => Record<string, unknown>[];
    buildExpertRiskSummary: (rows: Record<string, unknown>[]) => Record<string, unknown>;
    renderExpertFrameWorkspace: (frameModel: unknown, options?: Record<string, unknown>) => void;
  };
  let expertDom: { stack: ReturnType<typeof createDomHarness>['stack'] | null };
  let viewModelStub: (input?: unknown) => { items: unknown[] };

  before(async () => {
    expertDom = { stack: null };
    viewModelStub = () => ({ items: [] });
    const globals = globalThis as typeof globalThis & {
      __stackExpertDom: typeof expertDom;
      __buildSimplifiedStackViewModel: typeof viewModelStub;
      __renderStackEmptyState: Function;
    };
    globals.__stackExpertDom = expertDom;
    globals.__buildSimplifiedStackViewModel = (...args: unknown[]) => viewModelStub(args[0]);
    globals.__renderStackEmptyState = (container: any, frameModel: any) => {
      const empty = global.document.createElement('div');
      empty.className = 'stack-empty';
      empty.textContent = frameModel?.emptyText || 'Choisissez une fonction pour afficher sa frame.';
      container.appendChild(empty);
      return empty;
    };

    // Load stackExpertView.js — strip the dom/stackSimpleModel imports since
    // most tests use pure helpers while render tests provide stubs.
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackExpertView.js');
    let source = fs.readFileSync(modulePath, 'utf8');
    // Replace ES imports with stubs so the data-URL import works without a bundler.
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
    const dataUrl = `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;
    mod = await import(dataUrl);
  });

  function makeSlot(overrides: Record<string, unknown> = {}) {
    return {
      key: 'slot-0',
      selectionKey: 'slot-0',
      kind: 'local',
      title: 'buffer',
      name: 'buffer',
      subtitle: 'rbp-0x40',
      offsetLabel: 'rbp-0x40',
      size: 16,
      offsetBand: 'negative',
      badges: [],
      valuePreview: '',
      diagnosticCorrupted: false,
      diagnosticSeverity: null,
      diagnostics: [],
      isChanged: false,
      changed: false,
      recentWrite: false,
      flags: [],
      payloadRelated: false,
      pointerKind: '',
      isSensitive: false,
      detailPayload: null,
      ...overrides
    };
  }

  it('returns empty array for non-array input', () => {
    expect(mod.buildExpertRowItems(null as unknown as [])).to.deep.equal([]);
    expect(mod.buildExpertRowItems(undefined as unknown as [])).to.deep.equal([]);
    expect(mod.buildExpertRowItems([])).to.deep.equal([]);
  });

  it('expert mode renders compact row with expected shape', () => {
    const rows = mod.buildExpertRowItems([makeSlot()]);
    expect(rows).to.have.length(1);
    const row = rows[0];
    expect(row).to.include.keys(
      'key', 'selectionKey', 'kind', 'name', 'offset',
      'size', 'offsetBand', 'badges', 'value',
      'isReturnAddress', 'isSavedBp', 'isCorrupted',
      'isChanged', 'isSensitive', 'diagnosticSeverity',
      'hasDiagnostic', 'detailPayload'
    );
    expect(row.name).to.equal('buffer');
    expect(row.offset).to.equal('rbp-0x40');
    expect(row.size).to.equal('16B');
    expect(row.offsetBand).to.equal('negative');
  });

  it('simple mode uses existing renderer — expert row is NOT a frame-slot', () => {
    // simple mode does not call buildExpertRowItems at all.
    // We verify the expert items have distinct shape from frame-slot items.
    const rows = mod.buildExpertRowItems([makeSlot()]);
    expect(rows[0]).to.not.have.property('detailPayload', undefined);
    // Expert rows have explicit isReturnAddress, isSavedBp flags
    expect(rows[0].isReturnAddress).to.equal(false);
    expect(rows[0].isSavedBp).to.equal(false);
  });

  it('corrupted return address is still marked (isCorrupted + isReturnAddress)', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({
        kind: 'return_address',
        diagnosticCorrupted: true,
        diagnosticSeverity: 'error',
        diagnostics: [{ message: 'overflow into ret' }]
      })
    ]);
    expect(rows[0].isReturnAddress).to.equal(true);
    expect(rows[0].isCorrupted).to.equal(true);
    expect(rows[0].diagnosticSeverity).to.equal('error');
    expect(rows[0].hasDiagnostic).to.equal(true);
    expect(rows[0].badges).to.include('CORRUPT');
    expect(rows[0].badges).to.include('RET');
  });

  it('saved rbp slot is marked isSavedBp', () => {
    const rows = mod.buildExpertRowItems([makeSlot({ kind: 'saved_bp' })]);
    expect(rows[0].isSavedBp).to.equal(true);
    expect(rows[0].isReturnAddress).to.equal(false);
    expect(rows[0].badges).to.include('RBP');
  });

  it('changed item gets CHANGED badge from current-step change signals', () => {
    const rows = mod.buildExpertRowItems([makeSlot({ changed: true })]);
    expect(rows[0].isChanged).to.equal(true);
    expect(rows[0].badges).to.include('CHANGED');
  });

  it('does not add USER badge without explicit payload signal', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({
        valuePreview: '0x41414141',
        bytesHex: '41 41 41 41',
        ascii: 'AAAA'
      })
    ]);
    expect(rows[0].badges).to.not.include('USER');
  });

  it('adds USER badge when existing data explicitly marks payload relation', () => {
    const rows = mod.buildExpertRowItems([makeSlot({ payloadRelated: true })]);
    expect(rows[0].badges).to.include('USER');
  });

  it('adds pointer type badge only when pointerKind classifies an address', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ valuePreview: '0x7fffffffe000', pointerKind: 'stack' }),
      makeSlot({ valuePreview: '0x401176' })
    ]);
    expect(rows[0].badges).to.include('PTR:STACK');
    expect(rows[1].badges.some((badge: string) => String(badge).startsWith('PTR:'))).to.equal(false);
  });

  it('resolves expert rendering explicitly — resolveStackPanelRenderMode', async () => {
    const vmPath = path.resolve(__dirname, '../dynamic/app/stackViewMode.js');
    const vmSource = fs.readFileSync(vmPath, 'utf8');
    const vmUrl = `data:text/javascript;base64,${Buffer.from(vmSource, 'utf8').toString('base64')}`;
    const vm = await import(vmUrl);
    expect(vm.resolveStackPanelRenderMode('expert')).to.equal('expert');
    expect(vm.resolveStackPanelRenderMode('simple')).to.equal('simple');
    expect(vm.resolveStackPanelRenderMode('garbage')).to.equal('simple');
  });

  it('clicking expert row reuses existing inline detail expansion shape', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({
        detailPayload: {
          subtitle: 'local var',
          rows: [
            { label: 'taille', value: '64 octets' },
            { label: 'valeur', value: '0x41414141' }
          ]
        }
      })
    ]);
    expect(rows[0].detailPayload).to.not.equal(null);
    expect(rows[0].detailPayload.rows).to.have.length(2);
    expect(rows[0].detailPayload.rows[0].label).to.equal('taille');
  });

  it('normalizes and preserves existing expert badges', () => {
    const rows = mod.buildExpertRowItems([makeSlot({ badges: ['ABI', 'overflow'] })]);
    expect(rows[0].badges).to.deep.equal(['OVERFLOW', 'ABI']);
  });

  it('does not infer overflow from a negated diagnostic message', () => {
    const rows = mod.buildExpertRowItems([makeSlot({
      diagnostics: [{
        kind: 'benign_termination',
        message: 'Aucun overflow et aucune ecriture suspecte.'
      }]
    })]);

    expect(rows[0].badges).to.not.include('OVERFLOW');
  });

  it('value preview is carried through', () => {
    const rows = mod.buildExpertRowItems([makeSlot({ valuePreview: '0xdeadbeef' })]);
    expect(rows[0].value).to.equal('0xdeadbeef');
  });

  it('builds OK summary when no dangerous changes exist', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ kind: 'saved_bp', title: 'saved rbp' }),
      makeSlot({ kind: 'return_address', title: 'return address' }),
      makeSlot()
    ]);
    const summary = mod.buildExpertRiskSummary(rows);
    expect(summary.severity).to.equal('OK');
    expect(summary.changedCount).to.equal(0);
    expect(summary.details).to.deep.equal([]);
  });

  it('builds CHANGED summary for a modified buffer', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ kind: 'return_address', title: 'return address' }),
      makeSlot({ kind: 'saved_bp', title: 'saved rbp' }),
      makeSlot({ changed: true, title: 'buffer' })
    ]);
    const summary = mod.buildExpertRiskSummary(rows);
    expect(summary.severity).to.equal('CHANGED');
    expect(summary.changedCount).to.equal(1);
    expect(summary.details).to.include('1 modified slot');
  });

  it('builds DANGER summary for corrupted return address', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ kind: 'return_address', title: 'return address', diagnosticCorrupted: true })
    ]);
    const summary = mod.buildExpertRiskSummary(rows);
    expect(summary.severity).to.equal('DANGER');
    expect(summary.returnAddressCorrupted).to.equal(true);
    expect(summary.details).to.include('RET corrupted');
  });

  it('builds WARNING summary for corrupted saved rbp', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ kind: 'saved_bp', title: 'saved rbp', diagnosticCorrupted: true })
    ]);
    const summary = mod.buildExpertRiskSummary(rows);
    expect(summary.severity).to.equal('WARNING');
    expect(summary.savedBpCorrupted).to.equal(true);
    expect(summary.details).to.include('RBP corrupted');
  });

  it('builds DANGER summary for overflow', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ diagnostics: [{ kind: 'buffer_overflow', message: 'overflow detected' }] })
    ]);
    const summary = mod.buildExpertRiskSummary(rows);
    expect(summary.severity).to.equal('DANGER');
    expect(summary.overflowDetected).to.equal(true);
    expect(summary.details).to.include('overflow detected');
  });

  it('does not report USER-controlled slot without explicit payload data', () => {
    const rows = mod.buildExpertRowItems([
      makeSlot({ valuePreview: '0x41414141', bytesHex: '41 41 41 41', ascii: 'AAAA' })
    ]);
    const summary = mod.buildExpertRiskSummary(rows);
    expect(summary.userControlled).to.equal(false);
    expect(summary.details).to.not.include('USER-controlled slot');
  });

  it('does not render OK summary', () => {
    const stack = renderExpertRows([
      makeSlot({ kind: 'return_address', title: 'return address' }),
      makeSlot({ kind: 'saved_bp', title: 'saved rbp' }),
      makeSlot()
    ]);
    expect(stack.querySelectorAll('.expert-risk-summary')).to.have.length(0);
  });

  it('renders CHANGED summary', () => {
    const stack = renderExpertRows([makeSlot({ changed: true })]);
    expect(stack.querySelectorAll('.expert-risk-summary')).to.have.length(1);
    expect(stack.querySelector('.expert-risk-summary-severity')?.textContent).to.equal('CHANGED');
  });

  it('renders WARNING summary', () => {
    const stack = renderExpertRows([makeSlot({ kind: 'saved_bp', diagnosticCorrupted: true })]);
    expect(stack.querySelectorAll('.expert-risk-summary')).to.have.length(1);
    expect(stack.querySelector('.expert-risk-summary-severity')?.textContent).to.equal('WARNING');
  });

  it('renders DANGER summary', () => {
    const stack = renderExpertRows([makeSlot({ kind: 'return_address', diagnosticCorrupted: true })]);
    expect(stack.querySelectorAll('.expert-risk-summary')).to.have.length(1);
    expect(stack.querySelector('.expert-risk-summary-severity')?.textContent).to.equal('DANGER');
  });

  function renderExpertRows(items: unknown[]) {
    const harness = createDomHarness();
    const originalDocument = global.document;
    expertDom.stack = harness.stack;
    viewModelStub = () => ({ items });
    global.document = harness.document as unknown as Document;
    try {
      mod.renderExpertFrameWorkspace({});
    } finally {
      global.document = originalDocument;
    }
    return harness.stack;
  }
});

describe('stack render dispatch — simple/expert panel modes', () => {
  let originalDocument: Document | undefined;
  let originalWindow: Window | undefined;
  let originalRequestAnimationFrame: ((callback: FrameRequestCallback) => number) | undefined;
  let originalConsoleDebug: typeof console.debug;
  let renderStack: (stackItems: unknown[], regMap: Record<string, string>, meta: Record<string, unknown>, options: Record<string, unknown>) => unknown;
  let harness: ReturnType<typeof createDomHarness>;

  before(async () => {
    originalDocument = global.document;
    originalWindow = global.window;
    originalRequestAnimationFrame = global.requestAnimationFrame;
    originalConsoleDebug = console.debug;
    console.debug = () => {};
    harness = createDomHarness();
    global.document = harness.document as unknown as Document;
    global.window = {
      setTimeout,
      clearTimeout
    } as unknown as Window;
    global.requestAnimationFrame = ((callback: FrameRequestCallback) => {
      callback(0);
      return 0;
    });

    const modulePath = path.resolve(__dirname, '../dynamic/app/stack.js');
    const moduleUrl = `${pathToFileURL(modulePath).href}?dispatch-test=${Date.now()}`;
    ({ renderStack } = await import(moduleUrl));
  });

  after(() => {
    global.document = originalDocument;
    global.window = originalWindow;
    global.requestAnimationFrame = originalRequestAnimationFrame;
    console.debug = originalConsoleDebug;
  });

  beforeEach(() => {
    harness.reset();
  });

  it('simple mode uses the existing frame workspace path after expert rendered', () => {
    renderSelectedFrame('expert');
    expect(harness.stack.classList.contains('stack-expert-list')).to.equal(true);
    expect(harness.stack.querySelectorAll('.expert-row')).to.have.length.greaterThan(0);
    expect(harness.stack.querySelectorAll('.expert-row-size')).to.have.length.greaterThan(0);
    expect(harness.stack.querySelectorAll('.frame-slot')).to.have.length(0);

    harness.stack.replaceChildren();
    renderSelectedFrame('simple');

    expect(harness.stack.classList.contains('stack-expert-list')).to.equal(false);
    expect(harness.stack.querySelectorAll('.frame-slot')).to.have.length.greaterThan(0);
    expect(harness.stack.querySelectorAll('.expert-row')).to.have.length(0);
    expect(harness.stack.querySelectorAll('.frame-slot-summary')).to.have.length.greaterThan(0);
    expect(harness.stack.querySelectorAll('.expert-risk-summary')).to.have.length(0);
  });

  it('expert and simple render classes remain mutually exclusive', () => {
    renderSelectedFrame('simple');
    expect(harness.stack.querySelectorAll('.frame-slot')).to.have.length.greaterThan(0);
    expect(harness.stack.querySelectorAll('.expert-row')).to.have.length(0);
    expect(harness.stack.querySelectorAll('.expert-risk-summary')).to.have.length(0);

    harness.stack.replaceChildren();
    renderSelectedFrame('expert');
    expect(harness.stack.querySelectorAll('.expert-row')).to.have.length.greaterThan(0);
    expect(harness.stack.querySelectorAll('.expert-risk-summary')).to.have.length(1);
    expect(harness.stack.querySelectorAll('.frame-slot')).to.have.length(0);
  });

  it('simple mode keeps selected slot details inline without the bottom detail drawer', () => {
    const initialWorkspace = renderSelectedFrame('simple') as any;
    const selectedEntry = initialWorkspace.frameModel.entries.find((entry: any) => (
      entry.kind !== 'return_address' && entry.kind !== 'saved_bp'
    ));

    renderSelectedFrame('simple', selectedEntry.key);

    expect(harness.stack.querySelectorAll('.is-expanded')).to.have.length(1);
    expect(harness.stack.querySelectorAll('.frame-slot-inline-details')).to.have.length.greaterThan(0);
    expect(harness.document.getElementById('stackDetail')?.hidden).to.equal(true);
    expect(harness.document.getElementById('stackDetail')?.querySelectorAll('.stack-detail-card')).to.have.length(0);
  });

  function renderSelectedFrame(stackPanelMode: 'simple' | 'expert', selectedSlotKey = '') {
    return renderStack(
      [
        {
          key: 'runtime-buffer',
          addressLabel: '0x0fc0',
          offsetFromBp: -64,
          size: 16,
          rawRole: 'local',
          source: 'runtime',
          technicalLabel: 'buffer',
          displayValue: '0x41414141'
        }
      ],
      { rbp: '0x1000', rsp: '0x0fc0' },
      { arch_bits: 64, start_symbol: 'main' },
      {
        displayMode: 'frame',
        stackPanelMode,
        selectedSlotKey,
        snapshots: [{ step: 1, func: 'main' }],
        currentStep: 1,
        selectedFunction: 'main',
        snapshot: { step: 1, func: 'main' },
        analysis: {
          function: { name: 'main' },
          frame: {
            basePointer: '0x1000',
            stackPointer: '0x0fc0',
            frameSize: 96
          },
          control: {
            savedBpAddr: '0x1000',
            retAddrAddr: '0x1008'
          }
        },
        diagnostics: [],
        mcp: null
      }
    );
  }
});

function createDomHarness() {
  class FakeElement {
    id = '';
    tagName: string;
    type = '';
    textContent = '';
    className = '';
    hidden = false;
    title = '';
    onclick: Function | null = null;
    dataset: Record<string, string> = {};
    children: FakeElement[] = [];
    parentNode: FakeElement | null = null;
    attributes: Record<string, string> = {};
    listeners: Record<string, Function[]> = {};

    constructor(tagName: string, id = '') {
      this.tagName = tagName.toUpperCase();
      this.id = id;
    }

    get classList() {
      const element = this;
      return {
        add(...classes: string[]) {
          const set = new Set(element.className.split(/\s+/).filter(Boolean));
          classes.forEach((name) => set.add(name));
          element.className = Array.from(set).join(' ');
        },
        remove(...classes: string[]) {
          const removeSet = new Set(classes);
          element.className = element.className
            .split(/\s+/)
            .filter((name) => name && !removeSet.has(name))
            .join(' ');
        },
        toggle(name: string, force?: boolean) {
          const has = element.className.split(/\s+/).includes(name);
          const shouldAdd = force === undefined ? !has : Boolean(force);
          if (shouldAdd) this.add(name);
          else this.remove(name);
          return shouldAdd;
        },
        contains(name: string) {
          return element.className.split(/\s+/).includes(name);
        }
      };
    }

    matches(selector: string) {
      if (selector.startsWith('#')) return this.id === selector.slice(1);
      if (selector.startsWith('.')) return this.className.split(/\s+/).includes(selector.slice(1));
      return false;
    }

    querySelector(selector: string) {
      return this.querySelectorAll(selector)[0] || null;
    }

    querySelectorAll(selector: string) {
      const results: FakeElement[] = [];
      const visit = (node: FakeElement) => {
        node.children.forEach((child) => {
          if (child.matches(selector)) results.push(child);
          visit(child);
        });
      };
      visit(this);
      return results;
    }

    appendChild(child: FakeElement) {
      child.parentNode = this;
      this.children.push(child);
      return child;
    }

    replaceChildren(...children: FakeElement[]) {
      this.children = [];
      children.forEach((child) => this.appendChild(child));
    }

    setAttribute(name: string, value: string) {
      this.attributes[name] = String(value);
    }

    getAttribute(name: string) {
      return this.attributes[name] ?? null;
    }

    addEventListener(name: string, callback: Function) {
      if (!this.listeners[name]) this.listeners[name] = [];
      this.listeners[name].push(callback);
    }

    scrollIntoView() {}
  }

  const ids = [
    'panel-runtime',
    'status',
    'stack',
    'registers',
    'risks',
    'memoryDump',
    'explainBody',
    'disasmList',
    'frameContext',
    'explainPanel',
    'explainSubtitle',
    'disasmPanel',
    'disasmSubtitle',
    'stepLabel',
    'stepRange',
    'showAllTrace',
    'focusLabel',
    'btnPrev',
    'btnNext',
    'stackLegend',
    'stackSummary',
    'stackModeFrame',
    'stackModeExpert',
    'stackModeAdvanced',
    'stackWorkspace',
    'stackWorkspaceTitle',
    'stackWorkspaceSubtitle',
    'stackWorkspaceBack',
    'stackFunctions',
    'stackDetail'
  ];
  const elements = new Map<string, FakeElement>();
  ids.forEach((id) => elements.set(id, new FakeElement('div', id)));
  const root = elements.get('panel-runtime') as FakeElement;
  ids.filter((id) => id !== 'panel-runtime').forEach((id) => root.appendChild(elements.get(id) as FakeElement));

  const document = {
    getElementById: (id: string) => elements.get(id) || null,
    querySelector: (selector: string) => root.querySelector(selector),
    createElement: (tagName: string) => new FakeElement(tagName),
    createTextNode: (text: string) => {
      const node = new FakeElement('#text');
      node.textContent = text;
      return node;
    }
  };

  return {
    document,
    stack: elements.get('stack') as FakeElement,
    reset() {
      elements.forEach((element, id) => {
        if (id !== 'panel-runtime') element.replaceChildren();
        element.className = '';
        element.hidden = false;
        element.textContent = '';
        element.dataset = {};
        element.attributes = {};
      });
    }
  };
}
