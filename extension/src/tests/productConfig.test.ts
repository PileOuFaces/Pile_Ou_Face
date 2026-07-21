const { expect } = require("chai");
const os = require("os");
const fs = require("fs");
const path = require("path");

const {
  NEUTRAL_CONFIG,
  loadProductConfig,
} = require("../shared/productConfig");

function mkTmpRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "pof-productcfg-"));
}

describe("product config layer", () => {
  it("is neutral (no company endpoint) when no config files are present", () => {
    const root = mkTmpRoot();
    try {
      const cfg = loadProductConfig(root);
      expect(cfg.authProviderUrl).to.equal("");
      expect(cfg.collabProviderUrl).to.equal("");
      expect(cfg.telemetryProviderUrl).to.equal("");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps the neutral default map empty", () => {
    expect(NEUTRAL_CONFIG.authProviderUrl).to.equal("");
    expect(NEUTRAL_CONFIG.collabProviderUrl).to.equal("");
    expect(NEUTRAL_CONFIG.telemetryProviderUrl).to.equal("");
  });

  it("reads the versioned neutral default file", () => {
    const root = mkTmpRoot();
    try {
      fs.writeFileSync(
        path.join(root, "product.default.json"),
        JSON.stringify({ authProviderUrl: "", collabProviderUrl: "", telemetryProviderUrl: "" }),
      );
      const cfg = loadProductConfig(root);
      expect(cfg.authProviderUrl).to.equal("");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("lets the official build overlay (product.json) populate provider URLs", () => {
    const root = mkTmpRoot();
    try {
      fs.writeFileSync(
        path.join(root, "product.default.json"),
        JSON.stringify({ authProviderUrl: "", collabProviderUrl: "", telemetryProviderUrl: "" }),
      );
      fs.writeFileSync(
        path.join(root, "product.json"),
        JSON.stringify({
          authProviderUrl: "https://auth.official.example",
          collabProviderUrl: "https://collab.official.example",
          telemetryProviderUrl: "https://telemetry.official.example",
        }),
      );
      const cfg = loadProductConfig(root);
      expect(cfg.authProviderUrl).to.equal("https://auth.official.example");
      expect(cfg.collabProviderUrl).to.equal("https://collab.official.example");
      expect(cfg.telemetryProviderUrl).to.equal("https://telemetry.official.example");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
