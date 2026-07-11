/**
 * Executes PLUGIN_BRIDGE_PREAMBLE (the script injected into every plugin's
 * sandboxed srcdoc iframe) inside a real jsdom window, and asserts on its
 * actual runtime behavior — not just string presence in the generated HTML.
 *
 * This is the single most regression-prone piece of the P3 iframe-isolation
 * work: any stub silently removed here breaks a plugin with no compile error,
 * only a runtime ReferenceError inside the iframe (as happened repeatedly
 * during manual testing this session — tabDataCache, GROUP_LABELS,
 * setStaticLoading, functionsUiState, the code-navigation helpers, etc.).
 *
 * The bridge script is embedded as a real <script> tag in the jsdom document
 * (exactly like the real srcdoc iframe) rather than eval()'d, so jsdom's own
 * script engine executes it — the same code path as production.
 */
const { expect } = require('chai');
const sinon = require('sinon');
const { JSDOM } = require('jsdom');
const { PLUGIN_BRIDGE_PREAMBLE } = require('../shared/webview');

/** Build a fresh jsdom window with the bridge script already executed. */
function makeBridgeWindow(bodyHtml = ''): { dom: any; win: any } {
  const dom = new JSDOM(`<!doctype html><html><body>${bodyHtml}${PLUGIN_BRIDGE_PREAMBLE}</body></html>`, {
    runScripts: 'dangerously',
    url: 'https://example.org/',
  });
  const win = dom.window;
  // In a real srcdoc iframe, window.parent is the host document. Here there is
  // no real parent, so give it a spy-able stand-in.
  win.parent = { postMessage: sinon.spy() };
  return { dom, win };
}

/** Simulate the host delivering a wrapped __pof_host message to the iframe. */
function deliverHostMessage(win: any, payload: unknown) {
  win.dispatchEvent(new win.MessageEvent('message', { data: { __pof_host: true, payload } }));
}

describe('PLUGIN_BRIDGE_PREAMBLE', () => {
  describe('state stubs', () => {
    it('defines tabDataCache as an empty object', () => {
      const { win } = makeBridgeWindow();
      expect(win.tabDataCache).to.deep.equal({});
    });

    it('defines symbolsCache/sectionsCache/functionListCache as empty arrays', () => {
      const { win } = makeBridgeWindow();
      expect(win.symbolsCache).to.deep.equal([]);
      expect(win.sectionsCache).to.deep.equal([]);
      expect(win.functionListCache).to.deep.equal([]);
    });

    it('defines functionsUiState with a selectedAddr field', () => {
      const { win } = makeBridgeWindow();
      expect(win.functionsUiState).to.deep.equal({ selectedAddr: '' });
    });

    it('defines GROUP_LABELS and PREMIUM_TAB_FAMILY as empty objects before any hubPluginState', () => {
      const { win } = makeBridgeWindow();
      expect(win.GROUP_LABELS).to.deep.equal({});
      expect(win.PREMIUM_TAB_FAMILY).to.deep.equal({});
    });
  });

  describe('hubPluginState -> GROUP_LABELS/PREMIUM_TAB_FAMILY sync', () => {
    it('populates labels and families from tabRegistrations', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, {
        type: 'hubPluginState',
        state: {
          tabRegistrations: [
            { tabId: 'vulns', label: 'Vulnérabilités', family: 'audit' },
            { tabId: 'taint', label: 'Taint', family: 'audit' },
          ],
        },
      });
      expect(win.GROUP_LABELS.vulns).to.equal('Vulnérabilités');
      expect(win.GROUP_LABELS.taint).to.equal('Taint');
      expect(win.PREMIUM_TAB_FAMILY.vulns).to.equal('audit');
    });

    it('ignores registrations with no tabId', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, { type: 'hubPluginState', state: { tabRegistrations: [{ label: 'X' }] } });
      expect(Object.keys(win.GROUP_LABELS)).to.have.length(0);
    });
  });

  describe('setStaticLoading', () => {
    it('replaces container content with a loading message', () => {
      const { win } = makeBridgeWindow('<div id="behaviorContent">stale</div>');
      win.setStaticLoading('behaviorContent', 'Chargement…');
      const el = win.document.getElementById('behaviorContent');
      expect(el.textContent.trim()).to.equal('Chargement…');
      expect(el.querySelector('p.loading')).to.exist;
    });

    it('clears the container when no message is given', () => {
      const { win } = makeBridgeWindow('<div id="behaviorContent">stale</div>');
      win.setStaticLoading('behaviorContent', '');
      expect(win.document.getElementById('behaviorContent').textContent).to.equal('');
    });

    it('does nothing (no throw) when the container does not exist', () => {
      const { win } = makeBridgeWindow();
      expect(() => win.setStaticLoading('doesNotExist', 'x')).not.to.throw();
    });
  });

  describe('registerTabLoader retry (host-not-ready race)', () => {
    let clock: any;
    afterEach(() => { if (clock) clock.restore(); });

    it('resends the registerTabLoader call until a reply arrives', () => {
      const { win } = makeBridgeWindow();
      clock = sinon.useFakeTimers();
      win.registerTabLoader('behavior', () => {});

      expect(win.parent.postMessage.callCount).to.equal(1);
      const firstMsg = win.parent.postMessage.firstCall.args[0];
      expect(firstMsg).to.include({ __pof_plugin: true, __pof_call: true, method: 'registerTabLoader' });
      expect(firstMsg.args).to.deep.equal(['behavior']);

      clock.tick(250);
      expect(win.parent.postMessage.callCount).to.equal(2);
      // Same seq resent, not a new call
      expect(win.parent.postMessage.secondCall.args[0].__seq).to.equal(firstMsg.__seq);

      // Router "comes online" and replies — further ticks must not resend.
      deliverHostMessage(win, { __pof_reply: true, __seq: firstMsg.__seq, result: undefined });
      const callsAfterReply = win.parent.postMessage.callCount;
      clock.tick(2000);
      expect(win.parent.postMessage.callCount).to.equal(callsAfterReply);
    });

    it('gives up after 8 attempts', () => {
      const { win } = makeBridgeWindow();
      clock = sinon.useFakeTimers();
      win.registerTabLoader('behavior', () => {});
      clock.tick(250 * 10);
      expect(win.parent.postMessage.callCount).to.equal(8);
    });

    it('invokes the callback when the host delivers a matching __pof_tabload', () => {
      const { win } = makeBridgeWindow();
      const fn = sinon.spy();
      win.registerTabLoader('behavior', fn);
      deliverHostMessage(win, { __pof_tabload: true, tabId: 'behavior', binaryPath: '/tmp/x.bin' });
      expect(fn.calledOnceWith('/tmp/x.bin')).to.equal(true);
      expect(win._pofCurrentBinaryPath).to.equal('/tmp/x.bin');
    });

    it('ignores __pof_tabload for a different tabId', () => {
      const { win } = makeBridgeWindow();
      const fn = sinon.spy();
      win.registerTabLoader('behavior', fn);
      deliverHostMessage(win, { __pof_tabload: true, tabId: 'other', binaryPath: '/tmp/x.bin' });
      expect(fn.called).to.equal(false);
    });
  });

  describe('__binaryPath / __cssVars broadcasts', () => {
    it('updates _pofCurrentBinaryPath and getStaticBinaryPath()', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, { type: '__binaryPath', binaryPath: '/tmp/sample.exe' });
      expect(win.getStaticBinaryPath()).to.equal('/tmp/sample.exe');
    });

    it('applies CSS vars into a __pof_css_vars style element', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, { type: '__cssVars', vars: { '--vscode-foreground': '#eee' } });
      const styleEl = win.document.getElementById('__pof_css_vars');
      expect(styleEl).to.exist;
      expect(styleEl.textContent).to.include('--vscode-foreground:#eee');
    });
  });

  describe('showTab re-dispatch (unwraps __pof_host for the plugin\'s own listeners)', () => {
    it('activates the matching .static-panel and deactivates the others', () => {
      const { win } = makeBridgeWindow(
        '<div id="staticBehavior" class="static-panel"></div>' +
        '<div id="staticPacker" class="static-panel active"></div>',
      );
      deliverHostMessage(win, { type: 'showTab', tabId: 'behavior' });
      expect(win.document.getElementById('staticBehavior').classList.contains('active')).to.equal(true);
      expect(win.document.getElementById('staticPacker').classList.contains('active')).to.equal(false);
    });

    it('re-dispatches the unwrapped message as a plain "message" event for plugin listeners', () => {
      const { win } = makeBridgeWindow();
      const received: any[] = [];
      win.addEventListener('message', (e: any) => { if (e.data && e.data.type === 'hubPluginResult') received.push(e.data); });
      deliverHostMessage(win, { type: 'hubPluginResult', feature: 'malware.packer.run', result: { ok: true } });
      expect(received).to.have.length(1);
      expect(received[0].feature).to.equal('malware.packer.run');
    });
  });

  describe('vscode.postMessage', () => {
    it('forwards plugin messages to window.parent wrapped in __pof_plugin', () => {
      const { win } = makeBridgeWindow();
      win.vscode.postMessage({ type: 'hubPluginInvoke', feature: 'x' });
      expect(win.parent.postMessage.calledOnce).to.equal(true);
      expect(win.parent.postMessage.firstCall.args[0]).to.deep.equal({
        __pof_plugin: true,
        payload: { type: 'hubPluginInvoke', feature: 'x' },
      });
    });
  });

  describe('shared rendering helpers', () => {
    it('normalizePluginPanelPayload wraps a raw array as items', () => {
      const { win } = makeBridgeWindow();
      const payload = win.normalizePluginPanelPayload([{ a: 1 }], ['items']);
      expect(payload.items).to.deep.equal([{ a: 1 }]);
      expect(payload.error).to.equal(null);
    });

    it('normalizePluginPanelPayload picks the first matching array key on an object result', () => {
      const { win } = makeBridgeWindow();
      const payload = win.normalizePluginPanelPayload({ matches: [1, 2], error: 'boom' }, ['matches', 'results']);
      expect(payload.items).to.deep.equal([1, 2]);
      expect(payload.error).to.equal('boom');
    });

    it('formatPremiumEvidence joins summaries and falls back cleanly', () => {
      const { win } = makeBridgeWindow();
      expect(win.formatPremiumEvidence([{ summary: 'a' }, { evidence: 'b' }])).to.equal('a ; b');
      expect(win.formatPremiumEvidence(null, '—')).to.equal('—');
    });

    it('buildNavigableAddrNode renders a clickable code node for hex addresses', () => {
      const { win } = makeBridgeWindow();
      const node = win.buildNavigableAddrNode('0x401000');
      expect(node.tagName).to.equal('CODE');
      expect(node.dataset.addr).to.equal('0x401000');
    });

    it('buildNavigableAddrNode renders plain text for non-hex values', () => {
      const { win } = makeBridgeWindow();
      const node = win.buildNavigableAddrNode('n/a');
      expect(node.nodeType).to.equal(win.Node.TEXT_NODE);
    });

    it('getDisabledFamilies reads from local storage', () => {
      const { win } = makeBridgeWindow();
      win._saveStorage({ disabledFamilies: ['offensif'] });
      expect([...win.getDisabledFamilies()]).to.deep.equal(['offensif']);
    });
  });

  describe('code-navigation helpers (ported from vulnerability-audit-pro, shared across plugins)', () => {
    it('isCodeNavigationAddress is false with empty caches and no address', () => {
      const { win } = makeBridgeWindow();
      expect(win.isCodeNavigationAddress('')).to.equal(false);
      expect(win.isCodeNavigationAddress('0x1000')).to.equal(false);
    });

    it('getPrimaryCodeNavigationAddr resolves a direct function_addr', () => {
      const { win } = makeBridgeWindow();
      expect(win.getPrimaryCodeNavigationAddr({ function_addr: '0x401000' })).to.equal('0x401000');
    });

    it('getPrimaryCodeNavigationAddr returns "" when nothing resolves', () => {
      const { win } = makeBridgeWindow();
      expect(win.getPrimaryCodeNavigationAddr({})).to.equal('');
    });

    it('getPrimaryNavigationOffset picks the first present offset-like field', () => {
      const { win } = makeBridgeWindow();
      expect(win.getPrimaryNavigationOffset({ offset_hex: '0x20' })).to.equal('0x20');
    });

    it('getPrimaryNavigationLocation prefers a callsite address', () => {
      const { win } = makeBridgeWindow();
      const loc = win.getPrimaryNavigationLocation({ addr: '0x1', related: { callsites: [{ addr: '0x2' }] } });
      expect(loc.addr).to.equal('0x2');
    });

    it('pickCodeAddressFromXrefs returns "" when no ref resolves to code', () => {
      const { win } = makeBridgeWindow();
      expect(win.pickCodeAddressFromXrefs({ refs: [] })).to.equal('');
    });

    it('requestAddressXrefs resolves via timeout fallback when no binary is loaded', async () => {
      const { win } = makeBridgeWindow();
      const result: any = await win.requestAddressXrefs('0x1000', 'to');
      expect(result).to.deep.equal({ refs: [], targets: [], addr: '0x1000', mode: 'to' });
    });

    it('withTemporaryButtonState disables the button during the task and restores it after', async () => {
      const { win } = makeBridgeWindow('<button id="btn">Run</button>');
      const button = win.document.getElementById('btn');
      let sawDisabled = false;
      await win.withTemporaryButtonState(button, 'Chargement…', () => {
        sawDisabled = button.disabled && button.textContent === 'Chargement…';
        return Promise.resolve();
      });
      expect(sawDisabled).to.equal(true);
      expect(button.disabled).to.equal(false);
      expect(button.textContent).to.equal('Run');
    });

    it('withTemporaryButtonState is a no-op on an already-disabled button', async () => {
      const { win } = makeBridgeWindow('<button id="btn" disabled>Run</button>');
      const button = win.document.getElementById('btn');
      const task = sinon.spy(() => Promise.resolve());
      await win.withTemporaryButtonState(button, 'x', task);
      expect(task.called).to.equal(false);
    });
  });

  describe('navigation via PoF.navigateTo (host-scope actions routed through the bridge)', () => {
    it('navigateTo sends a __pof_call with the action and params', () => {
      const { win } = makeBridgeWindow();
      win.PoF.navigateTo('showGroup', { group: 'code', tab: 'disasm' });
      const call = win.parent.postMessage.getCalls().find((c: any) => c.args[0].method === 'navigateTo');
      expect(call).to.exist;
      expect(call.args[0].args).to.deep.equal(['showGroup', { group: 'code', tab: 'disasm' }]);
    });

    it('navigateTo defaults params to an empty object', () => {
      const { win } = makeBridgeWindow();
      win.PoF.navigateTo('showPanel');
      const call = win.parent.postMessage.getCalls().find((c: any) => c.args[0].method === 'navigateTo');
      expect(call.args[0].args).to.deep.equal(['showPanel', {}]);
    });

    it('openVulnDataXrefs/openVulnStrings delegate to PoF.navigateTo once a binary and address are known', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, { type: '__binaryPath', binaryPath: '/tmp/x.bin' });
      win.openVulnDataXrefs('0x1000');
      let call = win.parent.postMessage.getCalls().find((c: any) => c.args[0].method === 'navigateTo' && c.args[0].args[0] === 'openXrefs');
      expect(call).to.exist;
      expect(call.args[0].args[1].addr).to.equal('0x1000');

      win.openVulnStrings('0x2000');
      call = win.parent.postMessage.getCalls().find((c: any) => c.args[0].method === 'navigateTo' && c.args[0].args[0] === 'openStringAt');
      expect(call).to.exist;
      expect(call.args[0].args[1].addr).to.equal('0x2000');
    });

    it('openVulnDataXrefs/openVulnStrings no-op without a loaded binary', () => {
      const { win } = makeBridgeWindow();
      win.openVulnDataXrefs('0x1000');
      win.openVulnStrings('0x1000');
      const navCalls = win.parent.postMessage.getCalls().filter((c: any) => c.args[0].method === 'navigateTo');
      expect(navCalls.length).to.equal(0);
    });
  });

  describe('isStaticTabAvailable', () => {
    it('defaults to permissive (true) since availability depends on host-side binary metadata', () => {
      const { win } = makeBridgeWindow();
      expect(win.isStaticTabAvailable('disasm')).to.equal(true);
    });
  });

  describe('group/family/disabled-family accessors', () => {
    it('getGroupLabels/getTabFamilies reflect the hubPluginState sync', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, { type: 'hubPluginState', state: { tabRegistrations: [{ tabId: 'taint', label: 'Taint', family: 'audit' }] } });
      expect(win.PoF.getGroupLabels()).to.deep.equal({ taint: 'Taint' });
      expect(win.PoF.getTabFamilies()).to.deep.equal({ taint: 'audit' });
    });

    it('getDisabledFamilies reads the persisted disabledFamilies as a Set', () => {
      const { win } = makeBridgeWindow();
      win._saveStorage({ disabledFamilies: ['malware', 'audit'] });
      expect(win.PoF.getDisabledFamilies()).to.deep.equal(new Set(['malware', 'audit']));
    });
  });

  describe('function-review helpers', () => {
    it('findAnnotationForAddress always returns null in the iframe', () => {
      const { win } = makeBridgeWindow();
      expect(win.findAnnotationForAddress('0x1')).to.equal(null);
    });

    it('getFunctionReviewLabel maps known statuses to French labels', () => {
      const { win } = makeBridgeWindow();
      expect(win.getFunctionReviewLabel('important')).to.equal('Prioritaire');
      expect(win.getFunctionReviewLabel('unknown-status')).to.equal('Sans revue');
    });

    it('persistFunctionReview posts hubSaveFunctionReview with a normalized address', () => {
      const { win } = makeBridgeWindow();
      deliverHostMessage(win, { type: '__binaryPath', binaryPath: '/tmp/x.bin' });
      win.persistFunctionReview({ addr: '0x1000' }, 'reviewed', 'looks fine');
      const sent = win.parent.postMessage.getCalls().map((c: any) => c.args[0].payload).find((p: any) => p && p.type === 'hubSaveFunctionReview');
      expect(sent).to.include({ addr: '0x1000', reviewStatus: 'reviewed', reviewNotes: 'looks fine', binaryPath: '/tmp/x.bin' });
    });

    it('persistFunctionReview is a no-op without a binary path', () => {
      const { win } = makeBridgeWindow();
      win.persistFunctionReview({ addr: '0x1000' }, 'reviewed', '');
      const sent = win.parent.postMessage.getCalls().map((c: any) => c.args[0].payload).find((p: any) => p && p.type === 'hubSaveFunctionReview');
      expect(sent).to.equal(undefined);
    });
  });

  describe('window.PoF proxy calls', () => {
    it('getBinaryPath is synchronous and reflects the last __binaryPath broadcast', () => {
      const { win } = makeBridgeWindow();
      expect(win.PoF.getBinaryPath()).to.equal('');
      deliverHostMessage(win, { type: '__binaryPath', binaryPath: '/tmp/x.bin' });
      expect(win.PoF.getBinaryPath()).to.equal('/tmp/x.bin');
    });

    it('setLoading replaces the target container with a loading message', () => {
      const { win } = makeBridgeWindow('<div id="yaraContent">stale content</div>');
      const container = win.document.getElementById('yaraContent');
      win.PoF.setLoading('yaraContent', 'Scan en cours…');
      expect(container.textContent).to.equal('Scan en cours…');
      expect(container.querySelector('.loading-state')).to.exist;
    });

    it('renders a host-managed indeterminate plugin progress banner', () => {
      const { win } = makeBridgeWindow('<main id="pluginRoot"></main>');
      deliverHostMessage(win, {
        type: 'hubPluginProgress',
        feature: 'packer',
        percent: null,
        message: 'Démarrage…',
      });
      const banner = win.document.getElementById('__pof_plugin_progress');
      expect(banner).to.exist;
      expect(banner.hidden).to.equal(false);
      expect(banner.classList.contains('is-indeterminate')).to.equal(true);
      expect(banner.textContent).to.include('Démarrage…');
      expect(banner.querySelector('.pof-plugin-progress-percent').textContent).to.equal('');
    });

    it('renders plugin progress percent when the host provides one', () => {
      const { win } = makeBridgeWindow('<main id="pluginRoot"></main>');
      deliverHostMessage(win, {
        type: 'hubPluginProgress',
        feature: 'packer',
        percent: 42,
        message: 'Signatures packer…',
      });
      const banner = win.document.getElementById('__pof_plugin_progress');
      expect(banner).to.exist;
      expect(banner.hidden).to.equal(false);
      expect(banner.classList.contains('is-indeterminate')).to.equal(false);
      expect(banner.textContent).to.include('Signatures packer…');
      expect(banner.querySelector('.pof-plugin-progress-percent').textContent).to.equal('42%');
      expect(banner.querySelector('.pof-plugin-progress-bar').style.width).to.equal('42%');
    });
  });
});
