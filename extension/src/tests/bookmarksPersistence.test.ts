const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

function makeInMemoryBridge() {
  const store = new Map(); // binaryPath -> { addr -> entry }
  function bucket(binaryPath) {
    if (!store.has(binaryPath)) store.set(binaryPath, {});
    return store.get(binaryPath);
  }
  return {
    loadAnnotations: async (binaryPath) => ({ ...bucket(binaryPath) }),
    saveAnnotation: async (binaryPath, addr, { comment, name } = {}) => {
      const b = bucket(binaryPath);
      const existing = b[addr] || {};
      b[addr] = {
        ...existing,
        ...(comment !== undefined ? { comment } : {}),
        ...(name !== undefined ? { name } : {}),
        updated: new Date().toISOString(),
      };
      return { ...b };
    },
    saveFunctionReview: async (binaryPath, addr, { reviewStatus, reviewNotes } = {}) => {
      const b = bucket(binaryPath);
      b[addr] = { ...b[addr], reviewStatus, reviewNotes, reviewUpdated: new Date().toISOString() };
      return { ...b };
    },
    saveBookmark: async (binaryPath, addr, { label, color } = {}) => {
      const b = bucket(binaryPath);
      b[addr] = { ...b[addr], bookmark: true, bookmarkLabel: label, bookmarkColor: color, bookmarkUpdated: new Date().toISOString() };
      return { ...b };
    },
    deleteBookmark: async (binaryPath, addr) => {
      const b = bucket(binaryPath);
      if (b[addr]) {
        delete b[addr].bookmark; delete b[addr].bookmarkLabel; delete b[addr].bookmarkColor; delete b[addr].bookmarkUpdated;
      }
      return { ...b };
    },
    clearBookmarks: async (binaryPath) => {
      const b = bucket(binaryPath);
      Object.values(b).forEach((entry) => {
        delete entry.bookmark; delete entry.bookmarkLabel; delete entry.bookmarkColor; delete entry.bookmarkUpdated;
      });
      return { ...b };
    },
    deleteAnnotation: async (binaryPath, addr) => {
      const b = bucket(binaryPath);
      if (b[addr]) { delete b[addr].comment; delete b[addr].name; delete b[addr].updated; }
      return { ...b };
    },
  };
}

function makePanelSink() {
  const messages = [];
  return { messages, panel: { webview: { postMessage: (m) => messages.push(m) } } };
}

describe("bookmark persistence", () => {
  it("stores bookmarks scoped to the selected binary", async () => {
    const sharedHandlers = require("../shared/sharedHandlers");
    const bridge = makeInMemoryBridge();
    const sinkA = makePanelSink();
    const handlersA = sharedHandlers({ root: "/r", panel: sinkA.panel, annotationsBridge: bridge });
    await handlersA.hubSaveBookmark({ binaryPath: "/bin/a", addr: "0x1000" });

    const annA = sinkA.messages.find((m) => m.type === "hubAnnotations").annotations;
    expect(annA["0x1000"]).to.include({ bookmark: true });

    const sinkB = makePanelSink();
    const handlersB = sharedHandlers({ root: "/r", panel: sinkB.panel, annotationsBridge: bridge });
    await handlersB.hubLoadAnnotations({ binaryPath: "/bin/b" });
    const loadedForB = sinkB.messages.find((m) => m.type === "hubAnnotations");
    expect(loadedForB.annotations).to.deep.equal({});
  });

  it("stores manual function review metadata", async () => {
    const sharedHandlers = require("../shared/sharedHandlers");
    const bridge = makeInMemoryBridge();
    const sink = makePanelSink();
    const handlers = sharedHandlers({ root: "/r", panel: sink.panel, annotationsBridge: bridge });
    await handlers.hubSaveFunctionReview({ binaryPath: "/bin/a", addr: "0x2000", reviewStatus: "reviewed", reviewNotes: "ok" });
    const ann = sink.messages.find((m) => m.type === "hubAnnotations").annotations;
    expect(ann["0x2000"]).to.include({ reviewStatus: "reviewed", reviewNotes: "ok" });
  });

  it("preserves existing bookmark label when only the color is updated", async () => {
    const sharedHandlers = require("../shared/sharedHandlers");
    const bridge = makeInMemoryBridge();
    const sink = makePanelSink();
    const handlers = sharedHandlers({ root: "/r", panel: sink.panel, annotationsBridge: bridge });
    await handlers.hubSaveBookmark({ binaryPath: "/bin/a", addr: "0x1000", label: "my label", color: "#111111" });
    await handlers.hubSaveBookmark({ binaryPath: "/bin/a", addr: "0x1000", color: "#222222" });
    const ann = sink.messages[sink.messages.length - 2].annotations; // last hubAnnotations message
    expect(ann["0x1000"]).to.include({ bookmarkLabel: "my label", bookmarkColor: "#222222" });
  });

  describe("bridge failure handling", () => {
    afterEach(() => {
      sinon.restore();
    });

    it("surfaces an error toast when saveBookmark rejects instead of failing silently", async () => {
      const showErrorMessage = sinon.stub();
      const sharedHandlers = proxyquire("../shared/sharedHandlers", {
        vscode: {
          window: {
            showErrorMessage,
            showInformationMessage: sinon.stub(),
            showWarningMessage: sinon.stub(),
          },
        },
      });
      const bridge = makeInMemoryBridge();
      bridge.saveBookmark = async () => {
        throw new Error("python CLI crashed");
      };
      const sink = makePanelSink();
      const handlers = sharedHandlers({ root: "/r", panel: sink.panel, annotationsBridge: bridge });

      await handlers.hubSaveBookmark({ binaryPath: "/bin/a", addr: "0x1000" });

      expect(showErrorMessage.calledOnce).to.equal(true);
      expect(String(showErrorMessage.firstCall.args[0])).to.include("bookmark");
      expect(String(showErrorMessage.firstCall.args[0])).to.include("python CLI crashed");
    });

    it("does not post a hubAnnotations update when saveBookmark rejects, leaving the webview's last-known state untouched", async () => {
      const showErrorMessage = sinon.stub();
      const sharedHandlers = proxyquire("../shared/sharedHandlers", {
        vscode: {
          window: {
            showErrorMessage,
            showInformationMessage: sinon.stub(),
            showWarningMessage: sinon.stub(),
          },
        },
      });
      const bridge = makeInMemoryBridge();
      bridge.saveBookmark = async () => {
        throw new Error("python CLI crashed");
      };
      const sink = makePanelSink();
      const handlers = sharedHandlers({ root: "/r", panel: sink.panel, annotationsBridge: bridge });

      await handlers.hubSaveBookmark({ binaryPath: "/bin/a", addr: "0x1000" });

      const annotationsMessages = sink.messages.filter((m) => m.type === "hubAnnotations");
      expect(annotationsMessages).to.have.length(0);
    });
  });
});
