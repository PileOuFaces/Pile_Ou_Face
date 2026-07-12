// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("disasm autoload loop guard (skipAutoLoad threaded through nav chain)", () => {
  const binarySourceControllerSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/binarySourceController.js"),
    "utf8",
  );
  const navSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/nav.js"),
    "utf8",
  );

  it("passes skipAutoLoad from hubSetBinaryPath through to applyStaticBinarySelectionUi", () => {
    const source = binarySourceControllerSource();
    const handlerStart = source.indexOf("msg.type === 'hubSetBinaryPath'");
    expect(handlerStart, "hubSetBinaryPath handler not found").to.be.greaterThan(-1);
    const handlerEnd = source.indexOf("msg.type === 'hubForgetRecentBinary'", handlerStart);
    const handler = source.slice(handlerStart, handlerEnd);

    // hubSetBinaryPath is posted with skipAutoLoad:true right before hubDisasmReady
    // fires (see finalizeDisasmOpen). If the UI-refresh path triggered by this
    // message doesn't propagate that flag all the way down to _autoLoadTab, the
    // refresh re-triggers disassembly before the cache populated by
    // hubDisasmReady's handler has a chance to short-circuit it, causing an
    // infinite disasm loop.
    expect(handler).to.include("applyStaticBinarySelectionUi(bp, nextMeta, skipAutoLoad)");
  });

  it("showGroup forwards skipAutoLoad to showSubTab", () => {
    const source = navSource();
    const fnStart = source.indexOf("function showGroup(");
    expect(fnStart, "showGroup not found").to.be.greaterThan(-1);
    const fnEnd = source.indexOf("function _refreshArchSupportBadges", fnStart);
    const fn = source.slice(fnStart, fnEnd);

    expect(fn).to.include("skipAutoLoad");

    const callIndex = fn.indexOf("showSubTab(groupId, targetTab, skipAutoLoad)");
    expect(callIndex, "showGroup must forward skipAutoLoad to showSubTab").to.be.greaterThan(-1);
  });

  it("showSubTab only calls _autoLoadTab when skipAutoLoad is not set", () => {
    const source = navSource();
    const fnStart = source.indexOf("function showSubTab(");
    expect(fnStart, "showSubTab not found").to.be.greaterThan(-1);
    const nextFnStart = source.indexOf("\nfunction ", fnStart + 1);
    const fnEnd = nextFnStart > -1 ? nextFnStart : source.indexOf("document.querySelectorAll('.group-tab')", fnStart);
    const fn = source.slice(fnStart, fnEnd);

    const guardIndex = fn.indexOf("if (!skipAutoLoad)");
    const autoLoadCallIndex = fn.indexOf("_autoLoadTab(tabId)");
    expect(guardIndex, "showSubTab must guard the _autoLoadTab call with skipAutoLoad").to.be.greaterThan(-1);
    expect(autoLoadCallIndex, "_autoLoadTab(tabId) call not found").to.be.greaterThan(-1);
    expect(guardIndex).to.be.lessThan(
      autoLoadCallIndex,
      "the skipAutoLoad guard must precede the _autoLoadTab call it protects",
    );
  });
});
