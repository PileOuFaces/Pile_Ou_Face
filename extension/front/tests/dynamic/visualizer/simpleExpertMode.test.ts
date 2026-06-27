const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('dynamic/visualizer simple and expert mode invariants', () => {
  let helpers: {
    STACK_PANEL_MODE_KEY: string;
    normalizeStackPanelMode: (mode: unknown) => string;
    persistStackPanelMode: (mode: string, storage: Storage) => void;
    restoreStackPanelMode: (storage: Storage) => string;
    resolveStackPanelRenderMode: (mode: string) => string;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../webview/dynamic/app/stackViewMode.js');
    const source = fs.readFileSync(modulePath, 'utf8');
    helpers = await import(`data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`);
  });

  function storage(initial: Record<string, string> = {}) {
    const values = new Map(Object.entries(initial));
    return {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, String(value)),
    } as unknown as Storage;
  }

  it('simple-mode-remains-the-default-renderer', () => {
    expect(helpers.normalizeStackPanelMode(undefined)).to.equal('simple');
    expect(helpers.resolveStackPanelRenderMode('garbage')).to.equal('simple');
  });

  it('expert-mode-is-explicit-and-does-not-coerce-simple', () => {
    expect(helpers.normalizeStackPanelMode('expert')).to.equal('expert');
    expect(helpers.normalizeStackPanelMode('simple')).to.equal('simple');
    expect(helpers.normalizeStackPanelMode('advanced')).to.equal('simple');
  });

  it('mode-persists-through-local-storage', () => {
    const localStorage = storage();

    helpers.persistStackPanelMode('expert', localStorage);
    expect(helpers.restoreStackPanelMode(localStorage)).to.equal('expert');

    helpers.persistStackPanelMode('simple', localStorage);
    expect(helpers.restoreStackPanelMode(localStorage)).to.equal('simple');
  });
});
