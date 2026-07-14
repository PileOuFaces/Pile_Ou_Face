// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("Functions binary-change reset", () => {
  const outilsSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/outils.js"),
    "utf8",
  );

  it("clears cached function rows and radar state when the selected binary changes", () => {
    const source = outilsSource();
    expect(source).to.include("window.discoveredFunctionsCache = [];");
    expect(source).to.include("window.functionListCache = [];");
    expect(source).to.include("window.functionRadarCache = null;");
    expect(source).to.include("window.functionWorkspaceState = null;");
  });

  it("resets Functions filters so stale filters from another binary cannot hide new results", () => {
    const source = outilsSource();
    expect(source).to.include("functionsUiState.quickFilter = 'all';");
    expect(source).to.include("functionsUiState.reviewFilter = 'all';");
    expect(source).to.include("functionsUiState.signalFilter = 'all';");
    expect(source).to.include("functionsUiState.selectedAddr = '';");
  });

  it("clears persisted binary-scoped filters and selections on binary change", () => {
    const source = outilsSource();
    const resetStart = source.indexOf("function resetStaticBinaryDerivedState()");
    expect(resetStart).to.be.greaterThan(-1);
    const resetEnd = source.indexOf("function applyStaticBinarySelectionUi", resetStart);
    const resetBody = source.slice(resetStart, resetEnd);

    expect(resetBody).to.include("functionsSelectedAddr: ''");
    expect(resetBody).to.include("decompileAddr: ''");
    expect(resetBody).to.include("decompileSearch: ''");
    expect(resetBody).to.include("cfgSearch: ''");
    expect(resetBody).to.include("cgSearch: ''");
  });

  it("resets binary-scoped decompile and graph UI state on binary change", () => {
    const source = outilsSource();
    const resetStart = source.indexOf("function resetStaticBinaryDerivedState()");
    expect(resetStart).to.be.greaterThan(-1);
    const resetEnd = source.indexOf("function applyStaticBinarySelectionUi", resetStart);
    const resetBody = source.slice(resetStart, resetEnd);

    expect(resetBody).to.include("decompileUiState.selectedAddr = '';");
    expect(resetBody).to.include("decompileUiState.searchQuery = '';");
    expect(resetBody).to.include("decompileUiState.activeSearchHit = -1;");
    expect(resetBody).to.include("cfgUiState.search = '';");
    expect(resetBody).to.include("callGraphUiState.search = '';");
  });
});
