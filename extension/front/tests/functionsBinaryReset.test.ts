// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("Functions binary-change reset", () => {
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
    const resetBody = functionBody(source, "resetGraphDerivedState");

    expect(resetBody).to.include("functionsSelectedAddr: ''");
    expect(resetBody).to.include("decompileAddr: ''");
    expect(resetBody).to.include("decompileSearch: ''");
    expect(resetBody).to.include("cfgSearch: ''");
    expect(resetBody).to.include("cgSearch: ''");
  });

  it("resets binary-scoped decompile and graph UI state on binary change", () => {
    const source = outilsSource();
    const stackDecompileBody = functionBody(source, "resetStackAndDecompileDerivedState");
    const graphBody = functionBody(source, "resetGraphDerivedState");

    expect(stackDecompileBody).to.include("decompileUiState.selectedAddr = '';");
    expect(stackDecompileBody).to.include("decompileUiState.searchQuery = '';");
    expect(stackDecompileBody).to.include("decompileUiState.activeSearchHit = -1;");
    expect(graphBody).to.include("cfgUiState.search = '';");
    expect(graphBody).to.include("callGraphUiState.search = '';");
  });
});
