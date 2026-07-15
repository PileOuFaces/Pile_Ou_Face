// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("static binary reset contract", () => {
  const outilsSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/outils.js"),
    "utf8",
  );

  function functionBody(source, name) {
    const start = source.indexOf(`function ${name}(`);
    expect(start, `${name} not found`).to.be.greaterThan(-1);
    const next = source.indexOf("\nfunction ", start + 1);
    expect(next, `${name} end not found`).to.be.greaterThan(start);
    return source.slice(start, next);
  }

  it("keeps resetStaticBinaryDerivedState grouped by binary-scoped state families", () => {
    const source = outilsSource();
    const body = functionBody(source, "resetStaticBinaryDerivedState");

    expect(body).to.include("resetHexDerivedState()");
    expect(body).to.include("resetStackAndDecompileDerivedState()");
    expect(body).to.include("resetTypedDataDerivedState()");
    expect(body).to.include("resetGraphDerivedState()");
    expect(body).to.include("tabDataCache = {}");
    expect(body).to.include("window.sectionsCache = []");
    expect(body).to.include("window._annotations = {}");
  });

  it("documents which state each reset helper owns", () => {
    const source = outilsSource();

    expect(functionBody(source, "resetHexDerivedState")).to.include("hexSelectionModel = {");
    expect(functionBody(source, "resetHexDerivedState")).to.include("resetHexPatchSessionState()");

    const stackDecompile = functionBody(source, "resetStackAndDecompileDerivedState");
    expect(stackDecompile).to.include("stackFrameCache = {}");
    expect(stackDecompile).to.include("pendingStackFrameRequests.clear()");
    expect(stackDecompile).to.include("clearDecompileCaches()");
    expect(stackDecompile).to.include("decompileUiState.renderedBinaryPath = ''");

    const typedData = functionBody(source, "resetTypedDataDerivedState");
    expect(typedData).to.include("typedDataUiState.appliedStructName = ''");
    expect(typedData).to.include("typedDataUiState.hexStructPreview = null");

    const graphs = functionBody(source, "resetGraphDerivedState");
    expect(graphs).to.include("cfgUiState.funcAddr = ''");
    expect(graphs).to.include("callGraphUiState.binaryPath = ''");
    expect(graphs).to.include("window._pendingCfgHighlightAddr = null");
  });
});
