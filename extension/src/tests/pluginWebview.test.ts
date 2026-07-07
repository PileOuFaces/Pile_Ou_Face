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

  it('returns empty strings when no plugins', () => {
    const result = loadPluginWebviews(tmpDir);
    expect(result.groupStyles).to.equal('');
    expect(result.frames).to.deep.equal([]);
    expect(result.framesHtml).to.equal('');
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
    expect(result.groupStyles).to.include('.group-tab.active[data-group="myfamily"]');
    expect(result.groupStyles).to.include('#111');
    expect(result.groupStyles).to.include('#eee');
    expect(result.groupStyles).to.include('#555');
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
    expect(result.frames).to.have.length(1);
    expect(result.frames[0].pluginSlug).to.equal('my-plugin');
    expect(result.framesHtml).to.include('id="pof-plugin-frame-my-plugin"');
    expect(result.framesHtml).to.include('sandbox="allow-scripts allow-same-origin"');
    expect(result.framesHtml).to.include('__pof_plugin');   // bridge preamble present
    expect(result.framesHtml).to.include('myPanel');         // plugin HTML present
    expect(result.framesHtml).to.include('var x = 1');       // plugin script present
  });

  it('scopes plugin inline styles to plugin panels', () => {
    const dir = pluginDir('my-plugin');
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: { family: 'myfamily' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: [] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), `
      <style>
        .btn { color: red; }
        #myPanel .item { color: blue; }
        @media (max-width: 520px) { .item { display: block; } }
        @keyframes plugin-spin { to { transform: rotate(360deg); } }
      </style>
      <div id="myPanel" class="static-panel"><button class="btn item">Run</button></div>
    `);

    const result = loadFromStorage();
    // Scoped styles are inside the srcdoc, which is stored as an HTML attribute value.
    // Double-quotes inside the attribute are escaped to &quot;, so the assertion must match that.
    expect(result.framesHtml).to.include(':where([data-plugin-scope=&quot;my-plugin&quot;]');
    expect(result.framesHtml).to.include('@keyframes plugin-spin');
    // The outer groupStyles should NOT contain per-plugin scoped CSS
    expect(result.groupStyles).not.to.include(':where([data-plugin-scope');
  });

  it('inlines script content even when a resolver is provided', () => {
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
    // srcdoc always inlines
    expect(result.framesHtml).to.include('window.pluginLoaded = true;');
    expect(result.framesHtml).not.to.include('src=');
  });

  it('skips plugins with no entrypoints.webview declared', () => {
    const dir = pluginDir('backend-only');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.backend-only',
      entrypoints: { python: { module: 'plugin_main', register: 'register_plugin' } },
    }));

    const result = loadFromStorage();
    expect(result.frames).to.deep.equal([]);
    expect(result.framesHtml).to.equal('');
    expect(result.groupStyles).to.equal('');
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
    expect(result.groupStyles).to.include('.group-tab.active[data-group="croisee"]');
    expect(result.framesHtml).to.include('panel-cross-analysis');
    expect(result.framesHtml).to.include('window.crossLoaded = true;');
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
    expect(result.frames).to.deep.equal([]);
    expect(result.framesHtml).to.equal('');
  });

  it('srcdoc hides .static-panel by default so only the active tab is shown inside the iframe', () => {
    const dir = pluginDir('my-plugin');
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: { family: 'myfamily' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: [] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'),
      '<div id="staticTab1" class="static-panel"></div><div id="staticTab2" class="static-panel"></div>');

    const result = loadFromStorage();
    // The srcdoc (HTML-attribute-encoded) must contain the panel visibility CSS
    expect(result.framesHtml).to.include('.static-panel{display:none');
    expect(result.framesHtml).to.include('.static-panel.active{display:flex');
  });

  it('srcdoc contains the showTab message handler to switch panels inside the iframe', () => {
    const dir = pluginDir('my-plugin');
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: { family: 'myfamily' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: [] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), '<div id="staticMyTab" class="static-panel"></div>');

    const result = loadFromStorage();
    // The srcdoc must contain the showTab handler (HTML-attribute-encoded)
    expect(result.framesHtml).to.include('showTab');
    expect(result.framesHtml).to.include('classList.remove');
  });

  it('iframe has no inline display:none — visibility is controlled by CSS class', () => {
    const dir = pluginDir('my-plugin');
    const webviewDir = path.join(dir, 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      ui: { family: 'myfamily' },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), '<div id="staticMyTab" class="static-panel">content</div>');
    fs.writeFileSync(path.join(webviewDir, 'tab.js'), 'var x = 1;');

    const result = loadFromStorage();
    // Extract the iframe attributes that appear BEFORE srcdoc (style, class, id, etc.)
    const beforeSrcdoc = result.framesHtml.split('srcdoc=')[0] || '';
    expect(beforeSrcdoc).not.to.include('display:none');
    expect(beforeSrcdoc).not.to.include('display: none');
    // Visibility is exclusively managed via the .active CSS class
    expect(beforeSrcdoc).to.include('class="plugin-iframe static-panel"');
  });
});
