// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("hubDecompile stale response guard", () => {
  const messagesSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/messages.js"),
    "utf8",
  );

  it("drops a decompile result for a binary/address the user has navigated away from", () => {
    const source = messagesSource();
    const handlerStart = source.indexOf("msg.type === 'hubDecompile'");
    expect(handlerStart, "hubDecompile handler not found").to.be.greaterThan(-1);
    const handlerEnd = source.indexOf("msg.type === 'hubRecherche'", handlerStart);
    const handler = source.slice(handlerStart, handlerEnd);

    // The guard must compare the incoming payload against the *current* UI
    // selection (not just the requested decompiler), otherwise a slow,
    // Docker-backed decompile for a function the user already navigated away
    // from can land after a newer request and overwrite the loader / content
    // of the function currently being viewed.
    expect(handler).to.include("isStaleForCurrentSelection");
    expect(handler).to.include("getStaticBinaryPath()");
    expect(handler).to.include("getDecompileSelectionContext()");

    const staleGuardIndex = handler.indexOf("isStaleForCurrentSelection");
    const firstRenderIndex = handler.indexOf("renderDecompilePayload(container, payload)");
    expect(staleGuardIndex).to.be.greaterThan(-1);
    expect(firstRenderIndex).to.be.greaterThan(-1);
    expect(staleGuardIndex).to.be.lessThan(
      firstRenderIndex,
      "the staleness guard must run before the DOM is ever touched",
    );

    // The guard must bail out (return) before reaching the render calls.
    const guardBlock = handler.slice(staleGuardIndex, firstRenderIndex);
    expect(guardBlock).to.include("return;");
  });
});
