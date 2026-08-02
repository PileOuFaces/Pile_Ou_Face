const { expect } = require('chai');
const { JSDOM } = require('jsdom');
const path = require('path');

const controllerModule = require(path.resolve(__dirname, '../static/decompileAugmentationController.js'));

function fixture() {
  const dom = new JSDOM(`
    <button id="btnAugmentDecompile"></button>
    <p id="decompileAugmentStatus"></p>
    <section id="decompileAugmentReview" hidden>
      <strong id="decompileAugmentSummary"></strong>
      <div id="decompileAugmentSuggestions"></div>
      <pre id="decompileAugmentCode"></pre>
      <button id="btnAcceptDecompileAugment"></button>
      <button data-augment-view="raw"></button>
      <button data-augment-view="augmented"></button>
    </section>`);
  const posted: any[] = [];
  const applied: any[] = [];
  const controller = controllerModule.createController({
    document: dom.window.document,
    postMessage: (message: any) => posted.push(message),
    applyAccepted: (result: any) => applied.push(result),
  });
  controller.bind();
  return { applied, controller, document: dom.window.document, posted };
}

describe('decompileAugmentationController', () => {
  it('mounts with the real hub message bus instead of requiring window.vscode', () => {
    const dom = new JSDOM('<button id="btnAugmentDecompile" disabled></button>');
    const posted: any[] = [];
    const target: any = {
      document: dom.window.document,
      POFHubMessageBus: { vscode: { postMessage: (message: any) => posted.push(message) } },
    };
    const mounted = controllerModule.mountController(target);
    expect(mounted).to.exist;
    expect(target.decompileAugmentationController).to.equal(mounted);
    mounted.setSource({ binaryPath: '/tmp/a', addr: '0x1', code: 'int f(){}' });
    mounted.request();
    expect(posted.at(-1).type).to.equal('hubAugmentDecompile');
    expect(controllerModule.mountController({ document: dom.window.document })).to.equal(null);
  });

  it('flattens every supported metadata kind with readable labels', () => {
    const items = controllerModule.flattenItems({
      summary: 'Parses input',
      renames: [{ id: 'r', from: 'a', to: 'count' }],
      comments: [{ id: 'c', text: 'Checks input' }],
      types: [{ id: 't', name: 'count', type: 'size_t' }],
      prototype: { id: 'p', value: 'int parse(void);' },
    });
    expect(items.map(controllerModule.itemLabel)).to.deep.equal([
      'Résumé : Parses input', 'a → count', 'Commentaire : Checks input', 'count : size_t', 'Prototype : int parse(void);',
    ]);
    expect(controllerModule.flattenItems(null)).to.deep.equal([]);
  });

  it('enables augmentation when code exists and explains when a function is still required', () => {
    const { controller, document } = fixture();
    controller.setSource({ binaryPath: '/tmp/a', addr: '', code: 'int main(){}' });
    expect(document.getElementById('btnAugmentDecompile').disabled).to.equal(false);
    expect(controller.request()).to.equal(false);
    expect(document.getElementById('decompileAugmentStatus').textContent).to.contain('Choisissez une fonction');
    controller.setSource({ binaryPath: '/tmp/a', addr: '0x1', code: 'int main(){}' });
    expect(document.getElementById('btnAugmentDecompile').disabled).to.equal(false);
  });

  it('uses the only function returned by a global decompilation', () => {
    const { controller, posted } = fixture();
    controller.setSource({
      binaryPath: '/tmp/a', addr: '', code: '// 0x10\nint only(){}',
      functions: [{ addr: '0x10', name: 'only', code: 'int only(){}' }],
    });
    expect(controller.request()).to.equal(true);
    expect(posted.at(-1)).to.include({ addr: '0x10', functionName: 'only', code: 'int only(){}' });
  });

  it('posts only the current function when requesting suggestions', () => {
    const { controller, document, posted } = fixture();
    controller.setSource({ binaryPath: '/tmp/a', addr: '0x1', code: 'int v1;', functionName: 'sub_1' });
    (document.getElementById('btnAugmentDecompile') as HTMLElement).click();
    expect(posted.at(-1)).to.include({ type: 'hubAugmentDecompile', addr: '0x1', code: 'int v1;' });
    expect(controller.request()).to.equal(false);
  });

  it('renders suggestions safely and switches raw/augmented previews', () => {
    const { controller, document } = fixture();
    controller.setSource({ binaryPath: '/tmp/a', addr: '0x1', code: 'int v1;' });
    controller.receive({ type: 'hubDecompileAugmented', ok: true, result: {
      cache_key: 'a'.repeat(64), raw_code: 'int v1;', augmented_code: 'int count;',
      proposal: { summary: '<b>Résumé</b>', renames: [{ id: 'rename:v1', from: 'v1', to: 'count', reason: '<img>' }] },
      accepted_ids: [], cached: false,
    }});
    expect(document.getElementById('decompileAugmentReview').hidden).to.equal(false);
    expect(document.getElementById('decompileAugmentSummary').textContent).to.equal('<b>Résumé</b>');
    expect(document.getElementById('decompileAugmentCode').textContent).to.equal('int count;');
    (document.querySelector('[data-augment-view="raw"]') as HTMLElement).click();
    expect(document.getElementById('decompileAugmentCode').textContent).to.equal('int v1;');
  });

  it('requires a selection and posts accepted ids', () => {
    const { controller, document, posted } = fixture();
    controller.setSource({ binaryPath: '/tmp/a', addr: '0x1', code: 'int v1;' });
    controller.receive({ type: 'hubDecompileAugmented', ok: true, result: {
      cache_key: 'a'.repeat(64), raw_code: 'int v1;', augmented_code: 'int count;',
      proposal: { renames: [{ id: 'rename:v1', from: 'v1', to: 'count' }] }, accepted_ids: [],
    }});
    const checkbox = document.querySelector('[data-suggestion-id]') as HTMLInputElement;
    checkbox.checked = false;
    expect(controller.accept()).to.equal(false);
    checkbox.checked = true;
    expect(controller.accept()).to.equal(true);
    expect(posted.at(-1)).to.deep.include({ type: 'hubAcceptDecompileAugmentation', selectedIds: ['rename:v1'] });
  });

  it('surfaces backend errors without opening the review', () => {
    const { controller, document } = fixture();
    expect(controller.receive({ type: 'other' })).to.equal(false);
    expect(controller.receive({ type: 'hubDecompileAugmented', ok: false, error: 'Provider indisponible' })).to.equal(true);
    expect(document.getElementById('decompileAugmentStatus').textContent).to.equal('Provider indisponible');
  });

  it('restores an accepted cached selection and handles the accept button binding', () => {
    const { applied, controller, document, posted } = fixture();
    const source = { binaryPath: '/tmp/a', addr: '0x1', code: 'int v1;' };
    controller.setSource(source);
    controller.setSource(source);
    controller.receive({ type: 'hubDecompileAugmented', ok: true, accepted: true, result: {
      cache_key: 'b'.repeat(64), raw_code: 'int v1;', augmented_code: 'int count;', cached: true,
      proposal: { renames: [{ id: 'rename:v1', from: 'v1', to: 'count' }] },
      accepted_ids: ['rename:v1'],
    }});
    expect((document.querySelector('[data-suggestion-id]') as HTMLInputElement).checked).to.equal(true);
    (document.getElementById('btnAcceptDecompileAugment') as HTMLElement).click();
    expect(posted.at(-1).cacheKey).to.equal('b'.repeat(64));
    controller.receive({ type: 'hubDecompileAugmented', ok: true, accepted: true, ...source, result: {
      cache_key: 'b'.repeat(64), raw_code: 'int v1;', augmented_code: 'int count;',
      proposal: {}, accepted_ids: ['rename:v1'],
    }});
    expect(applied.at(-1).augmented_code).to.equal('int count;');
    expect(document.getElementById('decompileAugmentReview').hidden).to.equal(true);
  });

  it('loads an accepted cache entry locally and ignores stale responses', () => {
    const { applied, controller, posted } = fixture();
    controller.setSource({ binaryPath: '/tmp/a', addr: '0x1', code: 'int v1;' });
    expect(posted[0]).to.include({ type: 'hubLoadDecompileAugmentationCache', addr: '0x1' });
    controller.receive({ type: 'hubDecompileAugmentationCache', ok: true, binaryPath: '/tmp/old', addr: '0x1', result: { found: true, augmented_code: 'stale' } });
    expect(applied).to.have.length(0);
    controller.receive({ type: 'hubDecompileAugmentationCache', ok: true, binaryPath: '/tmp/a', addr: '0x1', result: { found: true, augmented_code: 'int count;' } });
    expect(applied).to.deep.equal([{ found: true, augmented_code: 'int count;' }]);
  });

  it('retains an accepted cache result when the same decompile source is rendered again', () => {
    const app = fixture();
    const source = {
      binaryPath: '/tmp/a.bin', addr: '0x1000', functionName: 'main', code: 'int main(){}',
    };
    app.controller.setSource(source);
    app.controller.receive({
      type: 'hubDecompileAugmentationCache', binaryPath: '/tmp/a.bin', addr: '0x1000', ok: true,
      result: { found: true, accepted_ids: ['summary'], augmented_code: 'int renamed_main(){}' },
    });

    app.controller.setSource(source);

    expect(app.controller.state.result).to.deep.include({
      found: true,
      accepted_ids: ['summary'],
      augmented_code: 'int renamed_main(){}',
    });
  });
});
