// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { JSDOM } = require('jsdom');

function mount() {
  const dom = new JSDOM(`
    <section id="panel-static" class="panel active">
      <div id="staticDisasm" class="static-panel active"></div>
      <div id="staticDecompile" class="static-panel"></div>
      <span id="annotationAddrBadge" data-addr="0x401000"></span>
      <input id="annotationName"><input id="annotationComment"><input id="goToAddrInput">
      <select id="decompileAddrSelect"><option value="0x402000" selected>fn</option></select>
    </section>
    <section id="panel-dashboard" class="panel"></section>
  `, { runScripts: 'outside-only' });
  const navigations = [];
  const focused = [];
  Object.assign(dom.window, {
    normalizeHexAddress: (value) => String(value || '').trim(),
    focusAnnotationEditor: (addr, _annotation, options) => focused.push({ addr, options }),
    PileOuFaceHostApi: { navigateTo: (action, params) => navigations.push({ action, params }) },
  });
  const sourcePath = path.resolve(__dirname, '../shared/idaKeymap.js');
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), dom.getInternalVMContext(), { filename: sourcePath });
  return { window: dom.window, document: dom.window.document, navigations, focused };
}

function enable(app) {
  app.window.dispatchEvent(new app.window.MessageEvent('message', {
    data: { type: 'hubKeymapConfig', keymap: 'ida' },
  }));
}

function press(app, key, target = app.document.body) {
  const event = new app.window.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}

describe('IDA keymap bridge', () => {
  it('keeps the default keymap inert', () => {
    const app = mount();
    expect(press(app, 'n').defaultPrevented).to.equal(false);
    expect(app.focused).to.deep.equal([]);
  });

  it('maps rename, comment, xrefs and goto in analysis views', () => {
    const app = mount();
    enable(app);
    expect(press(app, 'n').defaultPrevented).to.equal(true);
    expect(app.document.activeElement.id).to.equal('annotationName');
    press(app, ';');
    expect(app.document.activeElement.id).to.equal('annotationComment');
    press(app, 'x');
    expect(app.navigations).to.deep.equal([{ action: 'openXrefs', params: { addr: '0x401000', mode: 'to' } }]);
    press(app, 'g');
    expect(app.document.activeElement.id).to.equal('goToAddrInput');
  });

  it('does not steal keys from inputs or outside the two analysis views', () => {
    const app = mount();
    enable(app);
    const input = app.document.getElementById('annotationName');
    expect(press(app, 'x', input).defaultPrevented).to.equal(false);
    expect(app.navigations).to.deep.equal([]);

    app.document.getElementById('panel-static').classList.remove('active');
    expect(press(app, 'g').defaultPrevented).to.equal(false);
    expect(app.document.activeElement?.id).to.not.equal('goToAddrInput');
  });
});
