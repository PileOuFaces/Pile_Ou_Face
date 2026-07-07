const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('hub template placeholders', () => {
  const frontDir = path.join(__dirname, '../../front');

  it('hub.html uses {{pluginGroupStyles}} not {{pluginStyles}}', () => {
    const html = fs.readFileSync(path.join(frontDir, 'hub.html'), 'utf8');
    expect(html).to.include('{{pluginGroupStyles}}');
    expect(html).not.to.include('{{pluginStyles}}');
  });

  it('hub.html uses {{pluginIframeRouterUri}} not {{pluginScripts}}', () => {
    const html = fs.readFileSync(path.join(frontDir, 'hub.html'), 'utf8');
    expect(html).to.include('{{pluginIframeRouterUri}}');
    expect(html).not.to.include('{{pluginScripts}}');
  });

  it('panel-static.html uses {{pluginFrames}} not {{pluginPanels}}', () => {
    const html = fs.readFileSync(path.join(frontDir, 'static', 'panel-static.html'), 'utf8');
    expect(html).to.include('{{pluginFrames}}');
    expect(html).not.to.include('{{pluginPanels}}');
  });
});
