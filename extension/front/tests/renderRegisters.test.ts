/* global describe, it, before, after, __dirname */
// Registres d'une trace : affichés en texte, jamais en HTML (CSP du visualiseur : scripts inline
// autorisés). Une trace peut venir d'un output.json de l'espace de travail.
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { JSDOM } = require('jsdom');

const PAYLOAD = '<img src="x" onerror="globalThis.__pwned = true">';

describe('dynamic/render — register names and values are text (CodeQL js/xss #6)', () => {
  let renderRegisters;
  let registers;
  let dom;
  let tmpRenderModulePath = null;
  let originalDocument;

  before(async () => {
    dom = new JSDOM('<div id="registers"></div>');
    originalDocument = global.document;
    global.document = dom.window.document;
    registers = dom.window.document.getElementById('registers');
    globalThis.__renderRegistersDom = { registers };
    // Same isolation as explain.test.ts: never load the real dom.js singleton.
    const renderModulePath = path.resolve(__dirname, '../dynamic/app/render.js');
    const source = fs.readFileSync(renderModulePath, 'utf8')
      .replace(/^import \{ dom \}.*$/m, 'const dom = globalThis.__renderRegistersDom;');
    tmpRenderModulePath = path.resolve(__dirname, '../dynamic/app/__test_render_registers_tmp.mjs');
    fs.writeFileSync(tmpRenderModulePath, source);
    ({ renderRegisters } = await import(pathToFileURL(tmpRenderModulePath).href));
  });

  after(() => {
    global.document = originalDocument;
    if (tmpRenderModulePath && fs.existsSync(tmpRenderModulePath)) fs.unlinkSync(tmpRenderModulePath);
    dom.window.close();
  });

  it('renders a hostile register name and value as text', () => {
    renderRegisters([{ name: PAYLOAD, value: PAYLOAD, pos: 0 }]);
    expect(registers.querySelector('img')).to.equal(null);
    expect(registers.querySelector('.register-name').textContent).to.equal(PAYLOAD);
    expect(registers.querySelector('.register-value').textContent).to.equal(PAYLOAD);
    expect(globalThis.__pwned).to.equal(undefined);
  });

  it('keeps the regular rendering of a register', () => {
    renderRegisters([{ name: 'rax', value: '0x2a', pos: 0 }]);
    expect(registers.querySelector('.register-name').textContent).to.equal('rax');
    expect(registers.querySelector('.register-value').textContent).to.equal('0x2a');
  });
});
