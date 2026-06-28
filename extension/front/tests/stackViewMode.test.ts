/* global describe, it, before, __dirname */
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('stackViewMode helpers', () => {
  let helpers: {
    STACK_PANEL_MODE_KEY: string;
    normalizeStackPanelMode: (mode: unknown) => string;
    restoreStackPanelMode: (storage: Storage) => string;
    persistStackPanelMode: (mode: string, storage: Storage) => void;
    resolveStackPanelRenderMode: (mode: string) => string;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackViewMode.js');
    const source = fs.readFileSync(modulePath, 'utf8');
    const dataUrl = `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;
    helpers = await import(dataUrl);
  });

  function createStorage(initial: Record<string, string> = {}): Storage {
    const values = new Map(Object.entries(initial));
    return {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, String(value)),
    } as unknown as Storage;
  }

  it('default mode is simple for null / undefined / invalid input', () => {
    expect(helpers.normalizeStackPanelMode(null)).to.equal('simple');
    expect(helpers.normalizeStackPanelMode(undefined)).to.equal('simple');
    expect(helpers.normalizeStackPanelMode('')).to.equal('simple');
    expect(helpers.normalizeStackPanelMode('unknown')).to.equal('simple');
    expect(helpers.normalizeStackPanelMode('advanced')).to.equal('simple');
  });

  it('switching to expert updates state', () => {
    expect(helpers.normalizeStackPanelMode('expert')).to.equal('expert');
  });

  it('switching back to simple updates state', () => {
    expect(helpers.normalizeStackPanelMode('simple')).to.equal('simple');
  });

  it('simple active => expert must be inactive (mutually exclusive)', () => {
    const mode = helpers.normalizeStackPanelMode('simple');
    expect(mode).to.equal('simple');
    expect(mode).to.not.equal('expert');
  });

  it('expert active => simple must be inactive (mutually exclusive)', () => {
    const mode = helpers.normalizeStackPanelMode('expert');
    expect(mode).to.equal('expert');
    expect(mode).to.not.equal('simple');
  });

  it('normalizeStackPanelMode only produces simple or expert, never both', () => {
    const validModes = new Set(['simple', 'expert']);
    ['simple', 'expert', null, undefined, '', 'advanced', 'garbage'].forEach((input) => {
      const result = helpers.normalizeStackPanelMode(input);
      expect(validModes).to.include(result);
    });
  });

  it('mode persists and is restored from localStorage', () => {
    const storage = createStorage();

    helpers.persistStackPanelMode('expert', storage);
    expect(helpers.restoreStackPanelMode(storage)).to.equal('expert');

    helpers.persistStackPanelMode('simple', storage);
    expect(helpers.restoreStackPanelMode(storage)).to.equal('simple');
  });

  it('invalid stored mode falls back to simple', () => {
    const storage = createStorage({ [helpers.STACK_PANEL_MODE_KEY]: 'garbage' });
    expect(helpers.restoreStackPanelMode(storage)).to.equal('simple');
  });

  it('empty storage returns simple default', () => {
    const storage = createStorage();
    expect(helpers.restoreStackPanelMode(storage)).to.equal('simple');
  });

  it('resolves the requested render mode, defaulting invalid input to simple', () => {
    expect(helpers.resolveStackPanelRenderMode('expert')).to.equal('expert');
    expect(helpers.resolveStackPanelRenderMode('simple')).to.equal('simple');
    expect(helpers.resolveStackPanelRenderMode('garbage')).to.equal('simple');
  });
});
