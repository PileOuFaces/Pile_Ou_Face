const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

describe('dynamic/workflows run trace submit dispatch', () => {
  it('panel.js no longer attaches a legacy submit listener to #traceForm', () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, '../../../dynamic/panel.js'),
      'utf8'
    );
    // Regression guard for the "one click = two runTrace posts" bug: the
    // form submit is owned exclusively by runTraceController.js now.
    expect(source).to.not.match(/form\?\.addEventListener\(\s*['"]submit['"]/);
  });

  it('a single submit dispatch on the trace form posts exactly one runTrace message', () => {
    const controller = loadRunTraceController();
    const posted: unknown[] = [];
    const form = createMockElement();

    controller.initRunTraceController({
      document: { getElementById: () => null },
      form,
      postMessage: (message: unknown) => posted.push(message),
      runBtn: createMockElement(),
      binaryPathInput: createMockElement({ value: '/tmp/pof/challenge' }),
      dynamicSourcePathInput: createMockElement(),
      dynamicPayloadTargetMode: createMockElement(),
      btnDynamicSelectBinary: createMockElement(),
      btnDynamicSelectSource: createMockElement(),
      payloadBuilderInput: createMockElement()
    });

    // Exactly one listener should have been registered for 'submit'.
    expect(form.listenerCountFor('submit')).to.equal(1);

    form.dispatchEvent({ type: 'submit', preventDefault: () => {} });

    const runTraceMessages = posted.filter((message: any) => message?.type === 'runTrace');
    expect(runTraceMessages).to.have.length(1);
  });

  it('ignores stale initRunTrace responses for a previous binary', () => {
    const controller = loadRunTraceController();
    const posted: unknown[] = [];
    const statuses: string[] = [];
    const initStates: unknown[] = [];
    const binaryPathInput = createMockElement({ value: '/tmp/current.bin' });
    const dynamicArchBits = createMockElement({ textContent: '64-bit' });
    const dynamicPie = createMockElement({ textContent: 'No' });

    const instance = controller.initRunTraceController({
      document: { getElementById: () => null },
      form: createMockElement(),
      postMessage: (message: unknown) => posted.push(message),
      runBtn: createMockElement(),
      binaryPathInput,
      dynamicArchBits,
      dynamicPie,
      dynamicSourcePathInput: createMockElement(),
      dynamicPayloadTargetMode: createMockElement(),
      btnDynamicSelectBinary: createMockElement(),
      btnDynamicSelectSource: createMockElement(),
      payloadBuilderInput: createMockElement(),
      setDynamicTraceInitState: (state: unknown) => initStates.push(state),
      setDynamicTraceStatus: (status: string) => statuses.push(status),
      setTraceField: (field: string, value: string) => initStates.push({ field, value }),
    });

    expect(instance.handleMessage({
      type: 'initRunTrace',
      binaryPath: '/tmp/old.bin',
      archBits: 32,
      pie: true,
    })).to.equal(true);

    expect(initStates).to.deep.equal([]);
    expect(statuses).to.deep.equal([]);
    expect(dynamicArchBits.textContent).to.equal('64-bit');
    expect(dynamicPie.textContent).to.equal('No');
    expect(posted).to.deep.equal([{
      type: 'hubDebugLog',
      scope: 'dynamic-init',
      event: 'ignored-stale-response',
      details: {
        currentBinaryPath: '/tmp/current.bin',
        responseBinaryPath: '/tmp/old.bin',
      },
    }]);
  });

  it('re-enables the run button but does not mark stale runTraceDone as completed', () => {
    const controller = loadRunTraceController();
    const posted: unknown[] = [];
    const statuses: string[] = [];
    const historyRefreshes: string[] = [];
    const runBtn = createMockElement({ disabled: true });

    const instance = controller.initRunTraceController({
      document: { getElementById: () => null },
      form: createMockElement(),
      postMessage: (message: unknown) => posted.push(message),
      runBtn,
      binaryPathInput: createMockElement({ value: '/tmp/current.bin' }),
      dynamicSourcePathInput: createMockElement(),
      dynamicPayloadTargetMode: createMockElement(),
      btnDynamicSelectBinary: createMockElement(),
      btnDynamicSelectSource: createMockElement(),
      payloadBuilderInput: createMockElement(),
      setDynamicTraceStatus: (status: string) => statuses.push(status),
      refreshDynamicTraceHistory: () => historyRefreshes.push('refresh'),
    });

    expect(instance.handleMessage({
      type: 'runTraceDone',
      binaryPath: '/tmp/old.bin',
    })).to.equal(true);

    expect(runBtn.disabled).to.equal(false);
    expect(statuses).to.deep.equal([]);
    expect(historyRefreshes).to.deep.equal([]);
    expect(posted).to.deep.equal([{
      type: 'hubDebugLog',
      scope: 'dynamic-run-trace-done',
      event: 'ignored-stale-response',
      details: {
        currentBinaryPath: '/tmp/current.bin',
        responseBinaryPath: '/tmp/old.bin',
      },
    }]);
  });

  function loadRunTraceController() {
    const source = fs.readFileSync(
      path.resolve(__dirname, '../../../dynamic/runTraceController.js'),
      'utf8'
    );
    const context: any = { window: {}, console };
    context.window.POFHub = {};
    vm.runInNewContext(source, context, { filename: 'runTraceController.js' });
    return context.window.POFHubRunTraceController;
  }

  function createMockElement(initial: Record<string, any> = {}) {
    const listeners: Record<string, Function[]> = {};
    const classNames = new Set<string>();

    return {
      value: initial.value ?? '',
      checked: initial.checked ?? false,
      disabled: initial.disabled ?? false,
      textContent: initial.textContent ?? '',
      classList: {
        add(...names: string[]) {
          names.forEach((name) => classNames.add(name));
        },
        remove(...names: string[]) {
          names.forEach((name) => classNames.delete(name));
        },
        contains(name: string) {
          return classNames.has(name);
        },
        toggle(name: string, force?: boolean) {
          const shouldAdd = force ?? !classNames.has(name);
          shouldAdd ? classNames.add(name) : classNames.delete(name);
          return shouldAdd;
        }
      },
      addEventListener(type: string, handler: Function) {
        (listeners[type] = listeners[type] || []).push(handler);
      },
      removeEventListener(type: string, handler: Function) {
        listeners[type] = (listeners[type] || []).filter((entry) => entry !== handler);
      },
      dispatchEvent(event: any) {
        event.target = event.target || this;
        event.currentTarget = this;
        (listeners[event.type] || []).forEach((handler) => handler(event));
        return event.defaultPrevented !== true;
      },
      listenerCountFor(type: string) {
        return (listeners[type] || []).length;
      }
    };
  }
});
