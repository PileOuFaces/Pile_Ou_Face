// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const os = require("os");
const path = require("path");
const fs = require("fs");

const archSupport = require("../src/static/hub/archSupport");

// ── Fixture helpers ──────────────────────────────────────────────────────────

function makeArchPayload(archKey = "x86_64", overrides = {}) {
  const defaultSupport = {
    disasm:               { level: "full",        note: "Capstone x86/x64" },
    discover_functions:   { level: "full",        note: "Prologues and calls" },
    cfg:                  { level: "full",        note: "Jump tables and branches" },
    xrefs:                { level: "full",        note: "Code and data refs" },
    call_graph:           { level: "full",        note: "Direct calls" },
    stack_frame:          { level: "full",        note: "Frame-pointer and frame-pointer-less" },
    calling_convention:   { level: "full",        note: "SysV/Win64" },
  };
  return {
    key: archKey,
    family: "x86",
    display_name: "x86-64",
    bits: 64,
    ptr_size: 8,
    abi: "sysv",
    endian: "little",
    support: Object.assign({}, defaultSupport, overrides),
  };
}

function writeTmpMapping(obj) {
  const dir = os.tmpdir();
  const file = path.join(dir, `mapping-${Date.now()}.json`);
  fs.writeFileSync(file, JSON.stringify(obj), "utf8");
  return file;
}

// ── FEATURES & FEATURE_LEVELS ────────────────────────────────────────────────

describe("archSupport — constants", () => {
  it("FEATURES contains the 7 expected feature names", () => {
    expect(archSupport.FEATURES).to.deep.equal([
      "disasm",
      "discover_functions",
      "cfg",
      "xrefs",
      "call_graph",
      "stack_frame",
      "calling_convention",
    ]);
  });

  it("FEATURE_LEVELS is ordered from worst to best", () => {
    expect(archSupport.FEATURE_LEVELS).to.deep.equal([
      "unsupported",
      "disasm-only",
      "partial",
      "full",
    ]);
  });
});

// ── readArchSupportFromMapping ───────────────────────────────────────────────

describe("archSupport — readArchSupportFromMapping", () => {
  it("returns null for a non-existent path", () => {
    expect(archSupport.readArchSupportFromMapping("/does/not/exist.json", fs)).to.be.null;
  });

  it("returns null for a mapping without an arch field", () => {
    const file = writeTmpMapping({ functions: [] });
    try {
      expect(archSupport.readArchSupportFromMapping(file, fs)).to.be.null;
    } finally {
      fs.unlinkSync(file);
    }
  });

  it("returns null if arch is not an object", () => {
    const file = writeTmpMapping({ arch: "x86_64" });
    try {
      expect(archSupport.readArchSupportFromMapping(file, fs)).to.be.null;
    } finally {
      fs.unlinkSync(file);
    }
  });

  it("returns the arch payload from a valid mapping", () => {
    const payload = makeArchPayload();
    const file = writeTmpMapping({ arch: payload, functions: [] });
    try {
      const result = archSupport.readArchSupportFromMapping(file, fs);
      expect(result).to.deep.equal(payload);
    } finally {
      fs.unlinkSync(file);
    }
  });

  it("returns null for malformed JSON", () => {
    const dir = os.tmpdir();
    const file = path.join(dir, `bad-mapping-${Date.now()}.json`);
    fs.writeFileSync(file, "{ not json ]", "utf8");
    try {
      expect(archSupport.readArchSupportFromMapping(file, fs)).to.be.null;
    } finally {
      fs.unlinkSync(file);
    }
  });
});

// ── getFeatureEntry ──────────────────────────────────────────────────────────

describe("archSupport — getFeatureEntry", () => {
  it("returns level and note for a known feature", () => {
    const payload = makeArchPayload();
    const entry = archSupport.getFeatureEntry(payload, "cfg");
    expect(entry).to.deep.equal({ level: "full", note: "Jump tables and branches" });
  });

  it("returns null for an unknown feature", () => {
    const payload = makeArchPayload();
    expect(archSupport.getFeatureEntry(payload, "unknown_feature")).to.be.null;
  });

  it("returns null if archPayload is null", () => {
    expect(archSupport.getFeatureEntry(null, "cfg")).to.be.null;
  });

  it("returns null if support is missing", () => {
    expect(archSupport.getFeatureEntry({ key: "x86_64" }, "cfg")).to.be.null;
  });
});

// ── getFeatureLevel ──────────────────────────────────────────────────────────

describe("archSupport — getFeatureLevel", () => {
  it("returns the level string for a known feature", () => {
    const payload = makeArchPayload("arm64", {
      calling_convention: { level: "partial", note: "AAPCS64" },
    });
    expect(archSupport.getFeatureLevel(payload, "calling_convention")).to.equal("partial");
  });

  it("returns null for an unknown feature", () => {
    expect(archSupport.getFeatureLevel(makeArchPayload(), "no_such_feature")).to.be.null;
  });

  it("returns 'unsupported' for a feature explicitly marked unsupported", () => {
    const payload = makeArchPayload("mips32", {
      stack_frame: { level: "unsupported", note: "No ISA semantics table" },
    });
    expect(archSupport.getFeatureLevel(payload, "stack_frame")).to.equal("unsupported");
  });
});

// ── isFeatureAtLeast ─────────────────────────────────────────────────────────

describe("archSupport — isFeatureAtLeast", () => {
  const payload = makeArchPayload("arm64", {
    calling_convention: { level: "partial", note: "" },
    cfg:                { level: "full",    note: "" },
    stack_frame:        { level: "disasm-only", note: "" },
  });

  it("full >= full is true", () => {
    expect(archSupport.isFeatureAtLeast(payload, "cfg", "full")).to.be.true;
  });

  it("partial >= partial is true", () => {
    expect(archSupport.isFeatureAtLeast(payload, "calling_convention", "partial")).to.be.true;
  });

  it("partial >= full is false", () => {
    expect(archSupport.isFeatureAtLeast(payload, "calling_convention", "full")).to.be.false;
  });

  it("disasm-only >= partial is false", () => {
    expect(archSupport.isFeatureAtLeast(payload, "stack_frame", "partial")).to.be.false;
  });

  it("disasm-only >= disasm-only is true", () => {
    expect(archSupport.isFeatureAtLeast(payload, "stack_frame", "disasm-only")).to.be.true;
  });

  it("null payload returns false", () => {
    expect(archSupport.isFeatureAtLeast(null, "cfg", "partial")).to.be.false;
  });
});

// ── isFeatureUsable & isFeatureFull ─────────────────────────────────────────

describe("archSupport — isFeatureUsable / isFeatureFull", () => {
  const payload = makeArchPayload("arm32", {
    disasm:             { level: "full",        note: "" },
    cfg:                { level: "partial",     note: "" },
    stack_frame:        { level: "disasm-only", note: "" },
    calling_convention: { level: "unsupported", note: "" },
  });

  it("isFeatureUsable: full → true", () => {
    expect(archSupport.isFeatureUsable(payload, "disasm")).to.be.true;
  });

  it("isFeatureUsable: partial → true", () => {
    expect(archSupport.isFeatureUsable(payload, "cfg")).to.be.true;
  });

  it("isFeatureUsable: disasm-only → false", () => {
    expect(archSupport.isFeatureUsable(payload, "stack_frame")).to.be.false;
  });

  it("isFeatureUsable: unsupported → false", () => {
    expect(archSupport.isFeatureUsable(payload, "calling_convention")).to.be.false;
  });

  it("isFeatureFull: full → true", () => {
    expect(archSupport.isFeatureFull(payload, "disasm")).to.be.true;
  });

  it("isFeatureFull: partial → false", () => {
    expect(archSupport.isFeatureFull(payload, "cfg")).to.be.false;
  });
});

// ── worstFeatureEntry ────────────────────────────────────────────────────────

describe("archSupport — worstFeatureEntry", () => {
  const payload = makeArchPayload("arm64", {
    cfg:              { level: "full",    note: "" },
    call_graph:       { level: "partial", note: "ARM64 partial" },
    stack_frame:      { level: "full",    note: "" },
  });

  it("returns the worst entry among a feature list", () => {
    const worst = archSupport.worstFeatureEntry(payload, ["cfg", "call_graph", "stack_frame"]);
    expect(worst).to.deep.equal({ level: "partial", note: "ARM64 partial" });
  });

  it("returns null for an empty feature list", () => {
    expect(archSupport.worstFeatureEntry(payload, [])).to.be.null;
  });

  it("returns null if archPayload is null", () => {
    expect(archSupport.worstFeatureEntry(null, ["cfg"])).to.be.null;
  });

  it("ignores features not present in the support map", () => {
    const worst = archSupport.worstFeatureEntry(payload, ["cfg", "unknown_feature"]);
    expect(worst).to.deep.equal({ level: "full", note: "" });
  });
});
