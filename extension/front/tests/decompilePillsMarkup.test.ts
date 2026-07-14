// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("decompile pills UI markup", () => {
  const payloadSource = () => fs.readFileSync(
    path.resolve(__dirname, "../static/payload.js"),
    "utf8",
  );
  const cssSource = () => fs.readFileSync(
    path.resolve(__dirname, "../static/decompile.css"),
    "utf8",
  );
  const baseCssSource = () => fs.readFileSync(
    path.resolve(__dirname, "../base.css"),
    "utf8",
  );
  const searchSource = () => fs.readFileSync(
    path.resolve(__dirname, "../static/search.js"),
    "utf8",
  );
  const toolsSource = () => fs.readFileSync(
    path.resolve(__dirname, "../static/tools.js"),
    "utf8",
  );
  const disasmCssSource = () => fs.readFileSync(
    path.resolve(__dirname, "../static/disasm.css"),
    "utf8",
  );

  it("renders decompiler name, status and score as separate pill elements", () => {
    const source = payloadSource();

    expect(source).to.include("decompile-pill-label");
    expect(source).to.include("decompile-pill-score");
    expect(source).to.include("decompile-pill-spinner");
    expect(source).to.include("aria-disabled");
    expect(source).to.not.include("pill.disabled = true");
    expect(source).to.not.include("scoreStr =");
  });

  it("ships CSS for decompile pills and the running spinner", () => {
    const source = cssSource();

    expect(source).to.include(".decompile-pills");
    expect(source).to.include(".decompile-pill-score");
    expect(source).to.include("@keyframes decompile-pill-spin");
  });

  it("renders the shared static loading state with a visible spinner", () => {
    expect(searchSource()).to.include("static-loading-spinner");
    expect(baseCssSource()).to.include(".static-loading-spinner");
  });

  it("does not render the legacy fast/precision quality chip", () => {
    expect(payloadSource()).to.not.include("_formatDecompileQualityLabel");
    expect(toolsSource()).to.not.include("_formatDecompileQualityLabel");
  });

  it("uses annotation renames in the decompile function selector", () => {
    const source = payloadSource();

    expect(source).to.include("function getAnnotatedFunctionDisplayName");
    expect(source).to.include("window._annotations?.[normalized]?.name");
    expect(source).to.include("const displayName = getAnnotatedFunctionDisplayName(normalized, name)");
    expect(source).to.include("name: displayName");
  });

  it("ships visual styles for function vs note annotations", () => {
    const source = disasmCssSource();

    expect(source).to.include(".annotation-item-function");
    expect(source).to.include(".annotation-item-note");
    expect(source).to.include(".ann-kind-function");
    expect(source).to.include(".ann-kind-note");
    expect(source).to.include(".ann-edit");
  });
});
