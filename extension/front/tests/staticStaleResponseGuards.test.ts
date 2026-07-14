// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("static stale response guards", () => {
  const messagesSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/messages.js"),
    "utf8",
  );

  function handlerFor(source, type, nextType) {
    const start = source.indexOf(`msg.type === '${type}'`);
    expect(start, `${type} handler not found`).to.be.greaterThan(-1);
    const end = nextType
      ? source.indexOf(`msg.type === '${nextType}'`, start + 1)
      : source.indexOf("\n  if (msg.type === '", start + 1);
    expect(end, `${type} handler end not found`).to.be.greaterThan(start);
    return source.slice(start, end);
  }

  it("guards disasm-ready before invalidating graph caches", () => {
    const handler = handlerFor(messagesSource(), "hubDisasmReady", "hubStaticCompileDone");
    const guardIndex = handler.indexOf("isStaleStaticBinaryResponse(msg, 'static-disasm-ready')");
    const mutationIndex = handler.indexOf("tabDataCache.disasm");
    expect(guardIndex).to.be.greaterThan(-1);
    expect(mutationIndex).to.be.greaterThan(-1);
    expect(guardIndex).to.be.lessThan(mutationIndex);
  });

  it("guards dynamic symbols before mutating the start symbol select", () => {
    const handler = handlerFor(messagesSource(), "symbols", "generatedFiles");
    const guardIndex = handler.indexOf("isStaleStaticBinaryResponse(msg, 'dynamic-symbols')");
    const mutationIndex = handler.indexOf("sel.innerHTML = ''");
    expect(guardIndex).to.be.greaterThan(-1);
    expect(mutationIndex).to.be.greaterThan(-1);
    expect(guardIndex).to.be.lessThan(mutationIndex);
  });

  it("guards script and typed-struct async results", () => {
    const source = messagesSource();
    expect(handlerFor(source, "hubScriptResult", "hubScriptLoaded"))
      .to.include("isStaleStaticBinaryResponse(msg, 'static-script')");
    expect(handlerFor(source, "hubTypedStructPreviewDone", "hubTypedDataDone"))
      .to.include("isStaleStaticBinaryResponse(msg, 'static-typed-struct-preview')");
  });

  it("uses the generic guard for graph and string results", () => {
    const source = messagesSource();
    expect(handlerFor(source, "hubStrings", "hubPayloadHex"))
      .to.include("isStaleStaticBinaryResponse(msg, 'static-strings')");
    expect(handlerFor(source, "hubCfg", "hubCallGraph"))
      .to.include("isStaleStaticBinaryResponse(msg, 'static-cfg')");
    expect(handlerFor(source, "hubCallGraph", "hubDiscoveredFunctions"))
      .to.include("isStaleStaticBinaryResponse(msg, 'static-callgraph')");
  });
});
