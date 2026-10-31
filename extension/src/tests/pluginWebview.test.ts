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
  const pluginDir = (name) => path.join(storageDir(), 'plugins', name);
  const installedPlugins = () => {
    const pluginsRoot = path.join(storageDir(), 'plugins');
    if (!fs.existsSync(pluginsRoot)) return [];
    return fs.readdirSync(pluginsRoot).flatMap((entry) => {
      const root = path.join(pluginsRoot, entry);
      const file = ['plugin.json', 'manifest.json'].map((name) => path.join(root, name)).find((f) => fs.existsSync(f));
      if (!file) return [];
      try {
        const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
        return [{ plugin_id: manifest.id, version: manifest.version, root_path: root }];
      } catch (_) {
        return [];
      }
    });
  };
  const loadFromStorage = (authorized = installedPlugins()) => loadPluginWebviews({ storageDir: storageDir(), authorized });
  const framesText = (result) => result.frames.map((frame) => frame.srcdoc).join('\n');

  it('returns empty strings when no plugins', () => {
    const result = loadPluginWebviews();
    expect(result.groupStyles).to.equal('');
    expect(result.frames).to.deep.equal([]);
    expect(framesText(result)).to.equal('');
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
    expect(result.frames[0].frameId).to.equal('pof-plugin-frame-my-plugin');
    expect(framesText(result)).to.include('__pof_plugin');   // bridge preamble present
    expect(framesText(result)).to.include('myPanel');         // plugin HTML present
    expect(framesText(result)).to.include('var x = 1');       // plugin script present
  });

  it('inlines plugin styles into the iframe srcdoc unscoped', () => {
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
    // The iframe already isolates each plugin, so its CSS is inlined as-is (no
    // per-plugin selector scoping — that would break the plugin's own :root{--var}
    // declarations). Scoped styles are inside the srcdoc, stored as an HTML
    // attribute value, so double-quotes inside are escaped to &quot;.
    expect(framesText(result)).to.include('.btn { color: red; }');
    expect(framesText(result)).to.include('#myPanel .item { color: blue; }');
    expect(framesText(result)).to.include('@keyframes plugin-spin');
    // The outer groupStyles (host page, not the iframe) never receives plugin CSS.
    expect(result.groupStyles).to.equal('');
  });

  it('inlines script content into the iframe srcdoc', () => {
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

    const result = loadPluginWebviews({
      authorized: installedPlugins(),
      storageDir: storageDir(),
    });
    // srcdoc always inlines
    expect(framesText(result)).to.include('window.pluginLoaded = true;');
    expect(framesText(result)).not.to.include('src=');
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
    expect(framesText(result)).to.equal('');
    expect(result.groupStyles).to.equal('');
  });

  it('loads installed plugin webviews from manifest.json and metadata extras', () => {
    const dir = pluginDir('vendor.analysis-demo');
    const extrasDir = path.join(dir, 'metadata', 'extras', 'plugins', 'analysis-demo', 'webview');
    fs.mkdirSync(extrasDir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
      id: 'vendor.analysis-demo',
      ui: {
        family: 'analysis',
        tab_color: { bg: '#0d3a32', fg: '#63e6c6', border: '#248f77' },
      },
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    fs.writeFileSync(path.join(dir, 'metadata', 'build.json'), JSON.stringify({
      slug: 'analysis-demo',
    }));
    fs.writeFileSync(path.join(extrasDir, 'tab.html'), '<section id="panel-analysis"></section>');
    fs.writeFileSync(path.join(extrasDir, 'tab.js'), 'window.analysisLoaded = true;');

    const result = loadFromStorage();
    expect(result.groupStyles).to.include('.group-tab.active[data-group="analysis"]');
    expect(framesText(result)).to.include('panel-analysis');
    expect(framesText(result)).to.include('window.analysisLoaded = true;');
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

    expect(() => loadPluginWebviews()).not.to.throw();
    const result = loadFromStorage();
    expect(result.frames).to.deep.equal([]);
    expect(framesText(result)).to.equal('');
  });

  it('rejects plugin assets that escape the plugin directory', () => {
    const dir = pluginDir('traversal-plugin');
    fs.mkdirSync(dir, { recursive: true });
    const outsideHtml = path.join(storageDir(), 'outside.html');
    const outsideJs = path.join(storageDir(), 'outside.js');
    fs.writeFileSync(outsideHtml, '<div>outside secret</div>');
    fs.writeFileSync(outsideJs, 'window.outsideSecret = true;');
    fs.writeFileSync(path.join(dir, 'plugin.json'), JSON.stringify({
      id: 'pof.traversal-plugin',
      ui: { family: 'malicious' },
      entrypoints: {
        webview: {
          tab_html: path.relative(dir, outsideHtml),
          scripts: [path.relative(dir, outsideJs)],
        },
      },
    }));

    const result = loadFromStorage();
    expect(result.frames).to.deep.equal([]);
    expect(framesText(result)).not.to.include('outside secret');
    expect(framesText(result)).not.to.include('outsideSecret');
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
    expect(framesText(result)).to.include('.static-panel{display:none');
    expect(framesText(result)).to.include('.static-panel.active{display:flex');
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
    expect(framesText(result)).to.include('showTab');
    expect(framesText(result)).to.include('classList.remove');
  });

  it('matches a symlinked plugin against the resolved path reported by the runtime', () => {
    const realDir = path.join(tmpDir, 'real-plugin');
    fs.mkdirSync(path.join(realDir, 'webview'), { recursive: true });
    fs.mkdirSync(path.join(storageDir(), 'plugins'), { recursive: true });
    fs.writeFileSync(path.join(realDir, 'plugin.json'), JSON.stringify({
      id: 'pof.linked',
      version: '1.0.0',
      entrypoints: { webview: { tab_html: 'webview/tab.html' } },
    }));
    fs.writeFileSync(path.join(realDir, 'webview', 'tab.html'), '<div>linked</div>');
    fs.symlinkSync(realDir, pluginDir('linked'));

    const authorized = [{ plugin_id: 'pof.linked', version: '1.0.0', root_path: fs.realpathSync(realDir) }];
    expect(loadFromStorage(authorized).frames).to.have.length(1);
  });

  it('loads no plugin script unless the plugin is authorized', () => {
    const webviewDir = path.join(pluginDir('my-plugin'), 'webview');
    fs.mkdirSync(webviewDir, { recursive: true });
    fs.writeFileSync(path.join(pluginDir('my-plugin'), 'plugin.json'), JSON.stringify({
      id: 'pof.my-plugin',
      version: '1.0.0',
      entrypoints: { webview: { tab_html: 'webview/tab.html', scripts: ['webview/tab.js'] } },
    }));
    fs.writeFileSync(path.join(webviewDir, 'tab.html'), '<div>content</div>');
    fs.writeFileSync(path.join(webviewDir, 'tab.js'), 'window.pluginRan = true;');
    const entry = { plugin_id: 'pof.my-plugin', version: '1.0.0', root_path: pluginDir('my-plugin') };

    expect(loadFromStorage([]).frames).to.deep.equal([]);
    expect(loadPluginWebviews({ storageDir: storageDir() }).frames).to.deep.equal([]);
    expect(loadFromStorage([{ ...entry, version: '0.9.0' }]).frames).to.deep.equal([]);
    expect(loadFromStorage([{ ...entry, root_path: path.join(tmpDir, 'elsewhere') }]).frames).to.deep.equal([]);
    expect(framesText(loadFromStorage([entry]))).to.include('window.pluginRan = true;');
  });
});
