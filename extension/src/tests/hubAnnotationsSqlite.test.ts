const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const path = require("path");

const sharedHandlers = require("../shared/sharedHandlers");

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

function extensionRoot() {
  return path.resolve(__dirname, "../..");
}

function annotationJsonPath(storageDir) {
  const dir = path.join(storageDir, "annotations");
  const files = fs.readdirSync(dir).filter((name) => name.endsWith(".json"));
  expect(files).to.have.length(1);
  return path.join(dir, files[0]);
}

describe("Hub annotations SQLite persistence", () => {
  let tempRoot;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pof-hub-ann-sqlite-"));
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it("reloads Hub annotations from SQLite when the compatibility JSON snapshot is gone", () => {
    const binary = path.join(tempRoot, "sample.elf");
    const storageDir = path.join(tempRoot, "storage");
    fs.writeFileSync(binary, "binary");

    const firstSink = makePanelSink();
    const firstHandlers = sharedHandlers({
      root: extensionRoot(),
      storageDir,
      panel: firstSink.panel,
    });
    firstHandlers.hubSaveBookmark({
      binaryPath: binary,
      addr: "0x401000",
      label: "Entrée",
      color: "#4ec9b0",
    });

    expect(fs.readdirSync(path.join(storageDir, "pfdb")).some((name) => name.endsWith(".pfdb"))).to.equal(true);
    fs.unlinkSync(annotationJsonPath(storageDir));

    const secondSink = makePanelSink();
    const secondHandlers = sharedHandlers({
      root: extensionRoot(),
      storageDir,
      panel: secondSink.panel,
    });
    secondHandlers.hubLoadAnnotations({ binaryPath: binary });

    const loaded = secondSink.messages.find((message) => message.type === "hubAnnotations");
    expect(loaded.annotations["0x401000"]).to.include({
      bookmark: true,
      bookmarkLabel: "Entrée",
      bookmarkColor: "#4ec9b0",
    });
  });

  it("migrates an existing JSON annotation snapshot into SQLite on first load", () => {
    const binary = path.join(tempRoot, "legacy.elf");
    const storageDir = path.join(tempRoot, "storage");
    fs.writeFileSync(binary, "binary");

    const seedSink = makePanelSink();
    const seedHandlers = sharedHandlers({
      root: extensionRoot(),
      storageDir,
      panel: seedSink.panel,
    });
    seedHandlers.hubSaveBookmark({ binaryPath: binary, addr: "0x5000" });
    const jsonPath = annotationJsonPath(storageDir);
    fs.rmSync(path.join(storageDir, "pfdb"), { recursive: true, force: true });
    fs.writeFileSync(jsonPath, JSON.stringify({
      "0x5000": {
        comment: "legacy comment",
        name: "legacy_name",
        reviewStatus: "important",
      },
    }, null, 2));

    const loadSink = makePanelSink();
    const loadHandlers = sharedHandlers({
      root: extensionRoot(),
      storageDir,
      panel: loadSink.panel,
    });
    loadHandlers.hubLoadAnnotations({ binaryPath: binary });
    fs.unlinkSync(jsonPath);

    const reloadSink = makePanelSink();
    const reloadHandlers = sharedHandlers({
      root: extensionRoot(),
      storageDir,
      panel: reloadSink.panel,
    });
    reloadHandlers.hubLoadAnnotations({ binaryPath: binary });

    const loaded = reloadSink.messages.find((message) => message.type === "hubAnnotations");
    expect(loaded.annotations["0x5000"]).to.include({
      comment: "legacy comment",
      name: "legacy_name",
      reviewStatus: "important",
    });
  });
});
