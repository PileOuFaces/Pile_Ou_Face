// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("CFG empty state markup", () => {
  const messagesSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/messages.js"),
    "utf8",
  );
  const graphRenderersSource = () => fs.readFileSync(
    path.resolve(__dirname, "../../src/static/hub/graphRenderers.ts"),
    "utf8",
  );

  it("does not ask to open disassembly when a loaded CFG has no blocks", () => {
    const source = messagesSource();

    expect(source).to.include("Aucun bloc CFG détecté pour cette fonction.");
    expect(source).to.not.include("btnOpen.textContent = 'Ouvrir le désassemblage'");
    expect(source).to.not.include("Aucun bloc détecté. Ouvrez le désassemblage puis rechargez.");
  });

  it("guards CFG responses by binary path to avoid stale cross-binary cache hits", () => {
    expect(graphRenderersSource()).to.include("hubPost('hubCfg', { binaryPath");
    expect(messagesSource()).to.include("normalizeCfgBinaryPath(responseBinaryPath) !== normalizeCfgBinaryPath(currentBinaryPath)");
    expect(messagesSource()).to.include("tabDataCache.cfg = { binaryPath: responseBinaryPath || currentBinaryPath }");
  });
});
