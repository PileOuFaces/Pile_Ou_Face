const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/visualizer function mismatch empty stack state', () => {
  let renderStackEmptyState: Function;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../webview/dynamic/app/stackEmptyState.js');
    ({ renderStackEmptyState } = await import(pathToFileURL(modulePath).href));
  });

  it('renders-function-mismatch-explanation-and-jump-action', () => {
    const documentRef = createDocument();
    const container = documentRef.createElement('div');
    const jumped: number[] = [];

    renderStackEmptyState(container, {
      emptyState: {
        message: 'challenge() is selected, but the current trace step is still in main().',
        guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
        actionLabel: 'Jump to first challenge() step',
        actionStep: 2
      }
    }, {
      documentRef,
      onJumpToStep: (step: number) => jumped.push(step)
    });

    const empty = container.querySelector('.stack-empty');
    const action = container.querySelector('.stack-empty-action');

    expect(empty?.textContent).to.contain('challenge() is selected, but the current trace step is still in main().');
    expect(empty?.textContent).to.contain('Go to a step inside challenge() to view its runtime stack frame.');
    expect(action?.textContent).to.equal('Jump to first challenge() step');

    action?.click();

    expect(jumped).to.deep.equal([2]);
  });

  it('renders-no-executed-step-message-without-jump-action', () => {
    const documentRef = createDocument();
    const container = documentRef.createElement('div');

    renderStackEmptyState(container, {
      emptyState: {
        message: 'challenge() is selected, but the current trace step is still in main().',
        guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
        noExecutedStepText: 'No executed step for challenge() in this trace.',
        actionLabel: '',
        actionStep: null
      }
    }, {
      documentRef,
      onJumpToStep: () => {
        throw new Error('jump should not be rendered');
      }
    });

    const empty = container.querySelector('.stack-empty');
    const action = container.querySelector('.stack-empty-action');

    expect(empty?.textContent).to.contain('No executed step for challenge() in this trace.');
    expect(action).to.equal(null);
  });
});

function createDocument() {
  class FakeElement {
    tagName: string;
    type = '';
    className = '';
    textContent = '';
    children: FakeElement[] = [];
    listeners: Record<string, Function[]> = {};

    constructor(tagName: string) {
      this.tagName = tagName.toUpperCase();
    }

    matches(selector: string) {
      if (selector.startsWith('.')) return this.className.split(/\s+/).includes(selector.slice(1));
      return this.tagName.toLowerCase() === selector.toLowerCase();
    }

    querySelector(selector: string): FakeElement | null {
      return this.querySelectorAll(selector)[0] || null;
    }

    querySelectorAll(selector: string) {
      const results: FakeElement[] = [];
      const visit = (node: FakeElement) => {
        node.children.forEach((child) => {
          if (child.matches(selector)) results.push(child);
          visit(child);
        });
      };
      visit(this);
      return results;
    }

    appendChild(child: FakeElement) {
      this.children.push(child);
      this.textContent = this.children.map((entry) => entry.textContent).join('');
      return child;
    }

    addEventListener(name: string, callback: Function) {
      if (!this.listeners[name]) this.listeners[name] = [];
      this.listeners[name].push(callback);
    }

    click() {
      (this.listeners.click || []).forEach((callback) => callback());
    }
  }

  return {
    createElement: (tagName: string) => new FakeElement(tagName)
  };
}
