// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("typed struct editor contract", () => {
  const searchSource = () => fs.readFileSync(
    path.resolve(__dirname, "../static/search.js"),
    "utf8",
  );
  const messagesSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/messages.js"),
    "utf8",
  );
  const handlersSource = () => fs.readFileSync(
    path.resolve(__dirname, "../../src/static/staticHandlers.ts"),
    "utf8",
  );

  it("shows a catalog for structs, unions, and enums", () => {
    const source = searchSource();

    expect(source).to.include("function renderTypedStructCatalog(container, types)");
    expect(source).to.include("entry?.value_count");
    expect(source).to.include("entry?.field_count");
    expect(source).to.include("typed-data-type-catalog-empty");
  });

  it("keeps the editor open while definitions are saved", () => {
    const source = searchSource();
    const start = source.indexOf("function openTypedStructEditor(");
    const end = source.indexOf("\nfunction initCfgZoom", start);
    const editor = source.slice(start, end);

    expect(editor).to.include("saveBtn.disabled = true");
    expect(editor).to.include("type: 'hubSaveStructs'");
    expect(editor).to.include("binaryPath: getStaticBinaryPath()");
    expect(editor).to.not.include("vscode.postMessage({ type: 'hubSaveStructs', sourceText: textarea.value });\n    popup.remove();");
  });

  it("preserves the last valid catalog and reports save errors in place", () => {
    const source = messagesSource();
    const start = source.indexOf("msg.type === 'hubStructsDone'");
    const end = source.indexOf("msg.type === 'hubTypedStructPreviewDone'", start);
    const handler = source.slice(start, end);
    const errorIndex = handler.indexOf("if (data.error)");
    const catalogUpdateIndex = handler.indexOf("syncTypedDataStructSelect");

    expect(handler).to.include("updateTypedStructEditorResult(data, data.error)");
    expect(errorIndex).to.be.greaterThan(-1);
    expect(catalogUpdateIndex).to.be.greaterThan(errorIndex);
  });

  it("threads the active binary through host load and save commands", () => {
    const source = handlersSource();
    const start = source.indexOf("hubLoadStructs: async");
    const end = source.indexOf("hubSaveTypedStructRef: async", start);
    const handlers = source.slice(start, end);

    expect(handlers).to.include("hubLoadStructs: async (message)");
    expect(handlers.match(/'--binary'/g)).to.have.length(2);
    expect(handlers.match(/String\(message\.binaryPath \|\| ''\)/g)).to.have.length(2);
  });
});
