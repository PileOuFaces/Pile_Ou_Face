/* global describe, it, before, after, __dirname */
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

function makeFakeElement(): any {
  const el: any = {
    className: '',
    textContent: '',
    children: [] as any[],
    _classes: [] as string[],
  };
  el.classList = { add: (cls: string) => { el._classes.push(cls); } };
  el.appendChild = (child: any) => { el.children.push(child); return child; };
  el.append = (...nodes: any[]) => { el.children.push(...nodes); };
  return el;
}

describe('dynamic/explain — crash classification must match the backend, never invent one', () => {
  let mod: { renderExplain: (...args: any[]) => void };
  let explainBody: any;
  let originalDocument: any;
  let tmpModulePath: string | null = null;

  before(async () => {
    originalDocument = (global as any).document;
    // render.js (imported by explain.js) also imports the real dom.js,
    // which calls document.getElementById('panel-runtime') at module load.
    (global as any).document = { createElement: () => makeFakeElement(), getElementById: () => null, querySelector: () => null };

    explainBody = {
      children: [] as any[],
      replaceChildren() { this.children = []; },
      appendChild(child: any) { this.children.push(child); return child; }
    };
    (globalThis as any).__explainDom = { explainBody };

    // A data: URL has no base path, so explain.js's own relative imports
    // (./diagnostics.js, ./render.js) can't resolve from one -- write the
    // patched source next to the originals instead, so those imports
    // resolve normally, and clean it up afterwards.
    const modulePath = path.resolve(__dirname, '../dynamic/app/explain.js');
    let source = fs.readFileSync(modulePath, 'utf8');
    source = source.replace(
      /^import \{ dom \}.*$/m,
      'const dom = globalThis.__explainDom;'
    );
    tmpModulePath = path.resolve(__dirname, '../dynamic/app/__test_explain_tmp.mjs');
    fs.writeFileSync(tmpModulePath, source);
    mod = await import(pathToFileURL(tmpModulePath).href);
  });

  after(() => {
    (global as any).document = originalDocument;
    if (tmpModulePath && fs.existsSync(tmpModulePath)) fs.unlinkSync(tmpModulePath);
  });

  function crashOf(classification: string) {
    return { classification, reason: 'test reason', step: 1, instructionText: 'ret' };
  }

  function renderAndGetCard(crash: unknown) {
    explainBody.replaceChildren();
    mod.renderExplain({ step: 1, instr: 'ret', func: 'main' }, null, {}, {}, {}, null, null, [], crash);
    return explainBody.children[0];
  }

  it('benign_termination (hello-world/printf-only) renders as info, never CRASH DETECTE', () => {
    const card = renderAndGetCard(crashOf('benign_termination'));
    expect(card._classes).to.include('explain-section-info');
    expect(card._classes).to.not.include('explain-section-error');
    expect(card.children[0].textContent).to.not.equal('CRASH DETECTE');
  });

  it('emulator_stop renders as info, never CRASH DETECTE', () => {
    const card = renderAndGetCard(crashOf('emulator_stop'));
    expect(card._classes).to.include('explain-section-info');
    expect(card._classes).to.not.include('explain-section-error');
  });

  it('a real fatal_crash (real overflow) still renders as CRASH DETECTE / error', () => {
    const card = renderAndGetCard(crashOf('fatal_crash'));
    expect(card._classes).to.include('explain-section-error');
    expect(card.children[0].textContent).to.equal('CRASH DETECTE');
  });

  it('control_hijack is unaffected by the new classifications', () => {
    const card = renderAndGetCard(crashOf('control_hijack'));
    expect(card._classes).to.include('explain-section-warning');
  });
});
