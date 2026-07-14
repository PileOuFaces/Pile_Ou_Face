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

  it("drops stale automatic hubSetBinaryPath responses before mutating the selected binary", () => {
    const source = binarySourceControllerSource();
    const handlerStart = source.indexOf("msg.type === 'hubSetBinaryPath'");
    expect(handlerStart, "hubSetBinaryPath handler not found").to.be.greaterThan(-1);
    const handlerEnd = source.indexOf("msg.type === 'hubForgetRecentBinary'", handlerStart);
    const handler = source.slice(handlerStart, handlerEnd);

    const staleGuardIndex = handler.indexOf("normalizeBinaryPathForCompare(prevBp) !== normalizeBinaryPathForCompare(bp)");
    const applyIndex = handler.indexOf("applyStaticBinarySelectionUi(bp, nextMeta, skipAutoLoad)");
    expect(staleGuardIndex, "stale hubSetBinaryPath guard missing").to.be.greaterThan(-1);
    expect(applyIndex, "selection mutation missing").to.be.greaterThan(-1);
    expect(staleGuardIndex).to.be.lessThan(applyIndex);

    const staleGuardBlock = handler.slice(staleGuardIndex, applyIndex);
    expect(staleGuardBlock).to.include("event: 'ignored-stale-response'");
    expect(staleGuardBlock).to.include("return true;");
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

    // Assert the guard and the call form a single compound statement, not just
    // that the guard text appears somewhere before the call — otherwise a
    // refactor could split them apart (e.g. an unrelated `if (!skipAutoLoad)`
    // followed later by an unconditional `_autoLoadTab(tabId)`) and this test
    // would keep passing while silently reintroducing the infinite loop.
    expect(fn).to.include("if (!skipAutoLoad) _autoLoadTab(tabId)");
  });
});
