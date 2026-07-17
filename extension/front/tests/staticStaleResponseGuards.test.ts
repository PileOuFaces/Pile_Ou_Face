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

  it("guards all annotation handlers before replacing annotation state", () => {
    const source = messagesSource();
    let searchFrom = 0;
    let guardedHandlers = 0;

    while (true) {
      const start = source.indexOf("msg.type === 'hubAnnotations'", searchFrom);
      if (start === -1) break;
      const end = source.indexOf("\n  if (msg.type === '", start + 1);
      expect(end, "hubAnnotations handler end not found").to.be.greaterThan(start);
      const handler = source.slice(start, end);
      const guardIndex = handler.indexOf("isStaleStaticBinaryResponse(msg, 'static-annotations')");
      const mutationIndex = handler.indexOf("window._annotations");
      expect(guardIndex).to.be.greaterThan(-1);
      expect(mutationIndex).to.be.greaterThan(-1);
      expect(guardIndex).to.be.lessThan(mutationIndex);
      guardedHandlers += 1;
      searchFrom = end;
    }

    expect(guardedHandlers).to.be.greaterThan(0);
  });

  it("refreshes disassembly silently without cache when annotations include names or comments", () => {
    const source = messagesSource();
    const start = source.indexOf("function refreshDisasmForAnnotations");
    expect(start).to.be.greaterThan(-1);
    const end = source.indexOf("window.addEventListener", start);
    expect(end).to.be.greaterThan(start);
    const helper = source.slice(start, end);

    expect(helper).to.include("type: 'hubOpenDisasm'");
    expect(helper).to.include("useCache: false");
    expect(helper).to.include("openInEditor: false");
    expect(helper).to.include("refreshReason: 'annotation-overlay'");
    expect(handlerFor(source, "hubAnnotations", "hubDisasmReady"))
      .to.include("refreshDisasmForAnnotations(msg.binaryPath, annotations)");
  });

  it("refreshes the decompile function select when annotation names change", () => {
    const source = messagesSource();
    expect(handlerFor(source, "hubAnnotations", "hubDisasmReady"))
      .to.include("populateDecompileSelect(window.symbolsCache || [])");
  });

  it("keeps hubUiConsumed acknowledgements from depending only on animation frames", () => {
    const source = messagesSource();
    const start = source.indexOf("if (!msg?.type || msg.type === 'hubUiConsumed') return;");
    expect(start).to.be.greaterThan(-1);
    const helper = source.slice(start, start + 700);

    expect(helper).to.include("let consumed = false");
    expect(helper).to.include("if (consumed) return");
    expect(helper).to.include("requestAnimationFrame(() => requestAnimationFrame(acknowledge))");
    expect(helper).to.include("setTimeout(acknowledge, 250)");
  });

  it("only refreshes disassembly after annotation saves when the overlay changed", () => {
    const source = messagesSource();
    const handler = handlerFor(source, "hubAnnotationSaved", "hubAnnotations");
    expect(handler).to.include("refreshDisasmForAnnotations(bp, window._annotations)");
    expect(handler).to.include("clearDecompileCaches()");
    expect(handler).to.not.include("type: 'hubOpenDisasm'");
  });

  it("adopts the annotation signature after a fresh disasm build instead of rebuilding", () => {
    const source = messagesSource();
    expect(handlerFor(source, "hubDisasmReady", "hubStaticCompileDone"))
      .to.include("window._adoptAnnotationDisasmSignatureFor = msg.binaryPath.trim()");
    const start = source.indexOf("function refreshDisasmForAnnotations");
    const end = source.indexOf("window.addEventListener", start);
    const helper = source.slice(start, end);
    expect(helper).to.include("window._adoptAnnotationDisasmSignatureFor === bp");
    expect(helper).to.include("previousSameBinary");
  });

  it("renders annotation kind badges and edit actions", () => {
    const source = messagesSource();
    const renderStart = source.indexOf("function renderAnnotationsList");
    expect(renderStart).to.be.greaterThan(-1);
    const renderEnd = source.indexOf("window.addEventListener", renderStart);
    expect(renderEnd).to.be.greaterThan(renderStart);
    const renderer = source.slice(renderStart, renderEnd);

    expect(source).to.include("function isAnnotatedFunctionAddress");
    expect(source).to.include("window.annotationFunctionAddrs");
    expect(source).to.include("function mergeAnnotationFunctionAddrs");
    expect(source).to.include("document.getElementById('decompileAddrSelect')");
    expect(source).to.include("function focusAnnotationEditor");
    expect(renderer).to.include("annotation-item-function");
    expect(renderer).to.include("annotation-item-note");
    expect(renderer).to.include("Fonction");
    expect(renderer).to.include("Annotation");
    expect(renderer).to.include("ann-edit");
    expect(renderer).to.include("Modifier cette annotation");
  });

  it("does not navigate to disassembly from the annotation edit action", () => {
    const source = messagesSource();
    const renderStart = source.indexOf("function renderAnnotationsList");
    expect(renderStart).to.be.greaterThan(-1);
    const renderEnd = source.indexOf("window.addEventListener", renderStart);
    expect(renderEnd).to.be.greaterThan(renderStart);
    const renderer = source.slice(renderStart, renderEnd);
    const editStart = renderer.indexOf("listEl.querySelectorAll('.ann-edit')");
    expect(editStart).to.be.greaterThan(-1);
    const deleteStart = renderer.indexOf("listEl.querySelectorAll('.ann-delete')", editStart);
    expect(deleteStart).to.be.greaterThan(editStart);
    const editHandler = renderer.slice(editStart, deleteStart);

    expect(editHandler).to.include("focusAnnotationEditor(a, annotations[a])");
    expect(editHandler).to.not.include("hubGoToAddress");
  });

  it("rerenders annotation badges after function caches are updated", () => {
    const source = messagesSource();
    expect(handlerFor(source, "hubAnnotations", "hubDisasmReady"))
      .to.include("renderAnnotationsList(annotations)");
    expect(handlerFor(source, "hubAnnotations", "hubDisasmReady"))
      .to.include("msg.functionAddrs");
    expect(handlerFor(source, "hubDisasmReady", "hubStaticCompileDone"))
      .to.include("mergeAnnotationFunctionAddrs(msg.functionAddrs)");
    expect(handlerFor(source, "hubDisasmReady", "hubStaticCompileDone"))
      .to.include("renderAnnotationsList()");
    expect(handlerFor(source, "hubDiscoveredFunctions", "hubFunctionsDone"))
      .to.include("renderAnnotationsList()");
    expect(handlerFor(source, "hubFunctionsDone", "hubDecompilerList"))
      .to.include("renderAnnotationsList()");
  });
});
