const { expect } = require("chai");

const {
  RAW_TAB_CAPABILITIES,
  RAW_UNSUPPORTED_TABS,
  getRawTabCapability,
  getRawTabsByLevel,
} = require("../shared/rawTabCapabilities.js");

describe("raw tab capabilities", () => {
  it("keeps raw-native static views fully available", () => {
    expect(getRawTabsByLevel("full")).to.have.members([
      "disasm",
      "discovered",
      "cfg",
      "callgraph",
      "hex",
      "sections",
      "info",
      "strings",
      "recherche",
      "typed_data",
      "script",
    ]);
  });

  it("marks heuristic public raw views as limited", () => {
    expect(getRawTabsByLevel("limited")).to.have.members([
      "symbols",
      "imports",
      "detection",
    ]);
  });

  it("keeps structured-binary-only views unavailable on raw blobs", () => {
    const unsupported = [
      "decompile",
      "stack",
      "pe_resources",
      "exceptions",
    ];

    expect(getRawTabsByLevel("unsupported")).to.have.members(unsupported);
    for (const tabId of unsupported) {
      expect(RAW_UNSUPPORTED_TABS).to.have.property(tabId);
    }
  });

  it("documents why stack remains unsupported for raw blobs", () => {
    expect(RAW_TAB_CAPABILITIES.stack.level).to.equal("unsupported");
    expect(RAW_TAB_CAPABILITIES.stack.note).to.contain("LIEF");
  });

  it("defaults unknown raw tabs to limited instead of disabled", () => {
    expect(getRawTabCapability("future_plugin_view")).to.deep.equal({
      level: "limited",
      note: "Compatibilité brute à confirmer pour cette vue.",
    });
  });
});
