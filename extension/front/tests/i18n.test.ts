// SPDX-License-Identifier: AGPL-3.0-only
import { expect } from 'chai';
import fs from 'fs';
import { JSDOM } from 'jsdom';
import path from 'path';

const i18n = require('../shared/i18n.js');

describe('webview i18n', () => {
  it('resolves French variants and falls back to English', () => {
    expect(i18n.resolveLocale('fr-FR')).to.equal('fr');
    expect(i18n.resolveLocale('FR-ca')).to.equal('fr');
    expect(i18n.resolveLocale('en-US')).to.equal('en');
    expect(i18n.resolveLocale('de')).to.equal('en');
    expect(i18n.resolveLocale('')).to.equal('en');
  });

  it('keeps French and translates known English catalog entries', () => {
    expect(i18n.translate('Analyse statique', 'fr')).to.equal('Analyse statique');
    expect(i18n.translate('Analyse statique', 'en')).to.equal('Static analysis');
    expect(i18n.translate('0x401000', 'en')).to.equal('0x401000');
  });

  it('localizes text and accessible attributes without changing ids or values', () => {
    const dom = new JSDOM(`<!doctype html><html lang="en"><body>
      <button id="run" value="technical" title="Rafraîchir les modèles">Analyse statique</button>
      <input id="query" value="user data" placeholder="Rechercher…" aria-label="Rechercher une conversation">
    </body></html>`);
    i18n.localizeDocument(dom.window.document, 'en');
    const button = dom.window.document.getElementById('run') as HTMLButtonElement;
    const input = dom.window.document.getElementById('query') as HTMLInputElement;
    expect(button.textContent).to.equal('Static analysis');
    expect(button.title).to.equal('Refresh models');
    expect(button.id).to.equal('run');
    expect(button.value).to.equal('technical');
    expect(input.placeholder).to.equal('Search…');
    expect(input.getAttribute('aria-label')).to.equal('Search conversations');
    expect(input.value).to.equal('user data');
  });

  it('switches the same document between English and French', () => {
    const dom = new JSDOM(`<!doctype html><html lang="fr"><body>
      <section><h2>Confort de lecture</h2><label title="Rafraîchir">Langue</label></section>
    </body></html>`);
    const document = dom.window.document;

    i18n.setLocale('en', document);
    expect(document.querySelector('h2')?.textContent).to.equal('Reading comfort');
    expect(document.querySelector('label')?.textContent).to.equal('Language');
    expect(document.querySelector('label')?.title).to.equal('Refresh');

    i18n.setLocale('fr', document);
    expect(document.querySelector('h2')?.textContent).to.equal('Confort de lecture');
    expect(document.querySelector('label')?.textContent).to.equal('Langue');
    expect(document.querySelector('label')?.title).to.equal('Rafraîchir');
  });

  it('localizes the Options and Account panels', () => {
    const extensionRoot = path.resolve(__dirname, '../..');
    const panelSources = ['panel-options.html', 'panel-account.html']
      .map((name) => fs.readFileSync(path.join(extensionRoot, 'front/shared', name), 'utf8'))
      .join('\n');
    const dom = new JSDOM(`<!doctype html><html lang="fr"><body>${panelSources}</body></html>`);

    i18n.setLocale('en', dom.window.document);
    const content = dom.window.document.body.textContent || '';
    expect(content).to.include('Account');
    expect(content).to.include('Available decompilers');
    expect(content).to.include('Global generation settings');
    expect(content).to.include('Reading comfort');
    expect(content).to.include('Reset settings');
    expect(content).not.to.match(/Compte|Décompilateurs disponibles|Paramètres de génération globaux|Confort de lecture|Remettre les réglages à zéro/);
  });

  it('keeps the default and French VS Code manifest catalogs in sync', () => {
    const extensionRoot = path.resolve(__dirname, '../..');
    const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'package.json'), 'utf8'));
    const english = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'package.nls.json'), 'utf8'));
    const french = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'package.nls.fr.json'), 'utf8'));
    const referenced = new Set(JSON.stringify(manifest).match(/%([^%]+)%/g)?.map((item) => item.slice(1, -1)) || []);
    expect([...referenced].sort()).to.deep.equal(Object.keys(english).sort());
    expect(Object.keys(french).sort()).to.deep.equal(Object.keys(english).sort());
  });
});
