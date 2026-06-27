const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const path = require("path");

const sharedHandlers = require("../src/shared/sharedHandlers");

function makePanelSink() {
  const messages = [];
  return {
    messages,
    panel: {
      webview: {
        postMessage: (message) => {
          messages.push(message);
        },
      },
    },
  };
}

function readOnlyAnnotationFile(root) {
  const dir = path.join(root, ".pile-ou-face", "annotations");
  const files = fs.readdirSync(dir).filter((name) => name.endsWith(".json"));
  expect(files).to.have.length(1);
  return JSON.parse(fs.readFileSync(path.join(dir, files[0]), "utf8"));
}

describe("bookmark persistence", () => {
  it("stores bookmarks in the selected binary annotation file", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "pof-bookmarks-"));
    const binaryA = path.join(root, "samples", "sparc32.elf");
    const binaryB = path.join(root, "samples", "riscv32.elf");
    fs.mkdirSync(path.dirname(binaryA), { recursive: true });
    fs.writeFileSync(binaryA, "a");
    fs.writeFileSync(binaryB, "b");

    const sinkA = makePanelSink();
    const handlersA = sharedHandlers({ root, panel: sinkA.panel });
    handlersA.hubSaveBookmark({ binaryPath: binaryA, addr: "0x1000" });

    const annA = readOnlyAnnotationFile(root);
    expect(annA["0x1000"]).to.include({ bookmark: true });

    const sinkB = makePanelSink();
    const handlersB = sharedHandlers({ root, panel: sinkB.panel });
    handlersB.hubLoadAnnotations({ binaryPath: binaryB });
    const loadedForB = sinkB.messages.find((message) => message.type === "hubAnnotations");

    expect(loadedForB.annotations).to.deep.equal({});
  });

  it("stores manual function review metadata in the annotation file", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "pof-function-review-"));
    const binary = path.join(root, "samples", "review-target.elf");
    fs.mkdirSync(path.dirname(binary), { recursive: true });
    fs.writeFileSync(binary, "review");

    const sink = makePanelSink();
    const handlers = sharedHandlers({ root, panel: sink.panel });
    handlers.hubSaveFunctionReview({
      binaryPath: binary,
      addr: "0x401000",
      reviewStatus: "important",
      reviewNotes: "Pivot réseau à prioriser",
    });

    const ann = readOnlyAnnotationFile(root);
    expect(ann["0x401000"]).to.include({
      reviewStatus: "important",
      reviewNotes: "Pivot réseau à prioriser",
    });
  });
});
