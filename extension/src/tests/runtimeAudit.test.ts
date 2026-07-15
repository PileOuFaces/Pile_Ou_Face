const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  AUDIT_FILE,
  configureRuntimeAudit,
  getRuntimeAuditState,
  recordRuntimeEvent,
  resetRuntimeAudit,
} = require('../shared/runtimeAudit');

describe('runtimeAudit', () => {
  let tempRoot;
  let previousEnv;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-runtime-audit-'));
    previousEnv = process.env.POF_AUDIT_TRACE;
    delete process.env.POF_AUDIT_TRACE;
    resetRuntimeAudit();
  });

  afterEach(() => {
    resetRuntimeAudit();
    if (previousEnv === undefined) delete process.env.POF_AUDIT_TRACE;
    else process.env.POF_AUDIT_TRACE = previousEnv;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('is disabled by default', () => {
    const state = configureRuntimeAudit({ storageDir: tempRoot });
    recordRuntimeEvent('command', 'pileOuFace.open');

    expect(state.enabled).to.equal(false);
    expect(getRuntimeAuditState().enabled).to.equal(false);
    expect(fs.existsSync(path.join(tempRoot, AUDIT_FILE))).to.equal(false);
  });

  it('writes JSONL events when POF_AUDIT_TRACE is enabled', () => {
    process.env.POF_AUDIT_TRACE = '1';
    const state = configureRuntimeAudit({ storageDir: tempRoot });

    recordRuntimeEvent('webview_message', 'hubLoadAnnotations', {
      source: 'test',
      payload: { should: 'not be serialized deeply' },
    });

    expect(state.enabled).to.equal(true);
    const lines = fs.readFileSync(path.join(tempRoot, AUDIT_FILE), 'utf8').trim().split('\n');
    expect(lines).to.have.length(1);
    const event = JSON.parse(lines[0]);
    expect(event.kind).to.equal('webview_message');
    expect(event.name).to.equal('hubLoadAnnotations');
    expect(event.source).to.equal('test');
    expect(event.payload).to.equal('[object Object]');
    expect(event.ts).to.be.a('string');
  });

  it('can be enabled through configuration without POF_AUDIT_TRACE', () => {
    const state = configureRuntimeAudit({ storageDir: tempRoot, enabled: true });
    recordRuntimeEvent('command', 'pileOuFace.open');

    expect(state.enabled).to.equal(true);
    const event = JSON.parse(fs.readFileSync(path.join(tempRoot, AUDIT_FILE), 'utf8').trim());
    expect(event.kind).to.equal('command');
    expect(event.name).to.equal('pileOuFace.open');
  });

  it('wraps pileOuFace command registrations', async () => {
    process.env.POF_AUDIT_TRACE = '1';
    let registeredHandler = null;
    const fakeVscode = {
      commands: {
        registerCommand: (_id, handler) => {
          registeredHandler = handler;
          return { dispose: () => {} };
        },
      },
    };

    configureRuntimeAudit({ storageDir: tempRoot, vscode: fakeVscode });
    fakeVscode.commands.registerCommand('pileOuFace.testCommand', async () => 'ok');

    expect(await registeredHandler('arg1')).to.equal('ok');

    const event = JSON.parse(fs.readFileSync(path.join(tempRoot, AUDIT_FILE), 'utf8').trim());
    expect(event.kind).to.equal('command');
    expect(event.name).to.equal('pileOuFace.testCommand');
    expect(event.argc).to.equal(1);
  });
});
