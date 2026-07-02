const { expect } = require('chai');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { loadPluginWebviews } = require('../shared/webview');

describe('loadPluginWebviews', () => {
  let tmpDir;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-test-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  const storageDir = () => path.join(tmpDir, 'workspaceStorage', 'PileOuFaces.stack-visualizer');
  const loadFromStorage = () => loadPluginWebviews(tmpDir, { storageDir: storageDir() });
  const pluginDir = (name) => path.join(storageDir(), 'plugins', name);

  it('returns empty strings when plugins dir is absent', () => {
    const result = loadPluginWebviews(tmpDir);
    expect(result.styles).to.equal('');
    expect(result.panels).to.equal('');
    expect(result.scripts).to.equal('');
  });

  it('generates inline CSS from ui.tab_color', () => {
    const dir = pluginDir('my-plugin');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: {
        family: 'myfamily',
        tab_label: 'MY TAB',
        tab_color: { bg: '#111', fg: '#eee', border: '#555' },
      },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir);
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), '<div id="myPanel"></div>');
    fs.writeFileSync(path.join(webviewDir, 'tab.js'), 'console.log("loaded");');

    const result = loadFromStorage();
    expect(result.styles).to.include('.group-tab.active[data-group="myfamily"]');
    expect(result.styles).to.include('#111');
    expect(result.styles).to.include('#eee');
    expect(result.styles).to.include('#555');
  });

  it('inlines tab HTML and JS content', () => {
    const dir = pluginDir('my-plugin');
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: { family: 'myfamily' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), '<div id="myPanel">content</div>');
    fs.writeFileSync(path.join(webviewDir, 'tab.js'), 'var x = 1;');

    const result = loadFromStorage();
    expect(result.panels).to.include('<div id="myPanel">content</div>');
    expect(result.scripts).to.include('<script>');
    expect(result.scripts).to.include('var x = 1;');
  });

  it('builds external plugin script tags when a webview resolver is provided', () => {
    const dir = pluginDir('my-plugin');
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: { family: 'myfamily' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), '<div id="myPanel">content</div>');
    fs.writeFileSync(path.join(webviewDir, 'tab.js'), 'window.pluginLoaded = true;');

    const result = loadPluginWebviews(tmpDir, {
      storageDir: storageDir(),
      webviewResourceResolver: (filePath) => `vscode-resource:${path.basename(filePath)}`,
    });

    expect(result.scripts).to.include('<script src="vscode-resource:tab.js"></script>');
    expect(result.scripts).not.to.include('window.pluginLoaded = true;');
  });

  it('skips plugins with no entrypoints.webview declared', () => {
    const dir = pluginDir('backend-only');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.backend-only',
      entrypoints: { python: { module: 'plugin_main', register: 'register_plugin' } },
    }));

    const result = loadFromStorage();
    expect(result.panels).to.equal('');
    expect(result.scripts).to.equal('');
    expect(result.styles).to.equal('');
  });

  it('loads installed plugin webviews from manifest.json and metadata extras', () => {
    const dir = pluginDir('pof.cross-analysis-pro');
    const extrasDir = path.join(dir, 'metadata', 'extras', 'plugins', 'cross-analysis-pro', 'webview');
    fs.mkdirSync(extrasDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
      id: 'pof.cross-analysis-pro',
      ui: {
        family: 'croisee',
        tab_color: { bg: '#0d3a32', fg: '#63e6c6', border: '#248f77' },
      },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    fs.writeFileSync(path.join(dir, 'metadata', 'build.json'), JSON.stringify({
      slug: 'cross-analysis-pro',
    }));
    fs.writeFileSync(path.join(extrasDir, 'tab.html'), '<section id="panel-cross-analysis"></section>');
    fs.writeFileSync(path.join(extrasDir, 'tab.js'), 'window.crossLoaded = true;');

    const result = loadFromStorage();
    expect(result.styles).to.include('.group-tab.active[data-group="croisee"]');
    expect(result.panels).to.include('panel-cross-analysis');
    expect(result.scripts).to.include('window.crossLoaded = true;');
  });

  it('skips missing webview files gracefully', () => {
    const dir = pluginDir('broken-plugin');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.broken-plugin',
      ui: { family: 'broken' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    // webview/ dir intentionally absent

    expect(() => loadPluginWebviews(tmpDir)).not.to.throw();
    const result = loadFromStorage();
    expect(result.panels).to.equal('');
  });
});
