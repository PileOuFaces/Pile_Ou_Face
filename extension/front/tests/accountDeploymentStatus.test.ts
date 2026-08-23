// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { JSDOM } = require('jsdom');

function mountAccount() {
  const html = `
    <div data-pof-account-root>
      <div data-pof-account-logged-out></div>
      <div data-pof-account-logged-in style="display:none">
        <span data-pof-account-email></span>
        <ul data-pof-plugin-list></ul>
      </div>
      <p data-pof-login-error></p>
      <span data-pof-deployment-profile></span>
      <span data-pof-deployment-origin></span>
      <span data-pof-deployment-id></span>
    </div>`;
  const dom = new JSDOM(html, { runScripts: 'outside-only' });
  const messages = [];
  dom.window.POFHubMessageBus = { postMessage: (message) => messages.push(message) };
  const sourcePath = path.resolve(__dirname, '../shared/account.js');
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), dom.getInternalVMContext(), {
    filename: sourcePath,
  });
  return { dom, messages };
}

function sendAccountState(dom, payload) {
  dom.window.dispatchEvent(new dom.window.MessageEvent('message', {
    data: { type: 'accountState', ...payload },
  }));
}

describe('account deployment status', () => {
  it('renders deployment identity while logged out', () => {
    const { dom } = mountAccount();
    sendAccountState(dom, {
      loggedIn: false,
      deployment: {
        profile: 'OFFICIAL_SAAS',
        origin: 'https://auth.pileouface.dev',
        deploymentId: 'official-saas',
        verified: false,
      },
    });

    expect(dom.window.document.querySelector('[data-pof-deployment-profile]').textContent)
      .to.equal('OFFICIAL_SAAS');
    expect(dom.window.document.querySelector('[data-pof-deployment-origin]').textContent)
      .to.equal('https://auth.pileouface.dev');
    expect(dom.window.document.querySelector('[data-pof-deployment-id]').textContent)
      .to.equal('official-saas');
  });

  it('shows explicit offline fallbacks when no auth authority exists', () => {
    const { dom } = mountAccount();
    sendAccountState(dom, {
      loggedIn: false,
      deployment: { profile: 'AIRGAP_ENTERPRISE', origin: '', deploymentId: 'airgap-a' },
    });

    expect(dom.window.document.querySelector('[data-pof-deployment-origin]').textContent)
      .to.equal('Hors ligne');
    expect(dom.window.document.querySelector('[data-pof-deployment-id]').textContent)
      .to.equal('airgap-a');
  });
});
