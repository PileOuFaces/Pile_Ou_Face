// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");

const payloadCore = require("../static/payloadCore");

describe("webview static payloadCore", () => {
  describe("source hints", () => {
    it("prefers explicit source enrichment messages", () => {
      expect(payloadCore.buildSourceHintText({
        sourcePath: "/tmp/main.c",
        sourceEnrichmentMessage: "Analyse source prête.",
      })).to.equal("Analyse source prête.");
    });

    it("describes enabled, missing, ready and absent source states", () => {
      expect(payloadCore.buildSourceHintText({
        sourcePath: "/tmp/main.c",
        sourceEnrichmentEnabled: true,
      })).to.equal("Code source détecté — analyse enrichie activée.");

      expect(payloadCore.buildSourceHintText({
        sourcePath: "/tmp/main.c",
        sourceEnrichmentStatus: "missing",
      })).to.equal("Code source fourni introuvable ; analyse binaire seule.");

      expect(payloadCore.buildSourceHintText({ sourcePath: "/tmp/main.c" }))
        .to.equal("Code source sélectionné — enrichissement prêt au prochain run.");

      expect(payloadCore.buildSourceHintText())
        .to.equal("Pour une meilleure analyse, ajoutez le code source C du programme.");
    });
  });

  describe("payload target and mode normalization", () => {
    it("normalizes target modes and labels", () => {
      expect(payloadCore.normalizePayloadTargetMode(" STDIN ")).to.equal("stdin");
      expect(payloadCore.normalizePayloadTargetMode("bogus")).to.equal("auto");
      expect(payloadCore.normalizeEffectiveTarget("both")).to.equal("both");
      expect(payloadCore.normalizeEffectiveTarget("auto")).to.equal("argv1");
      expect(payloadCore.payloadTargetLabel("stdin")).to.equal("stdin");
      expect(payloadCore.payloadTargetLabel("both")).to.equal("stdin + argv[1]");
      expect(payloadCore.payloadTargetLabel("argv1")).to.equal("argv[1]");
    });

    it("normalizes payload modes and builder levels", () => {
      expect(payloadCore.normalizePayloadMode("simple")).to.equal("payload_builder");
      expect(payloadCore.normalizePayloadMode("python")).to.equal("payload_builder");
      expect(payloadCore.normalizePayloadMode("file")).to.equal("file");
      expect(payloadCore.normalizePayloadMode("unknown")).to.equal("payload_builder");

      expect(payloadCore.normalizePayloadBuilderLevel("advanced")).to.equal("advanced");
      expect(payloadCore.normalizePayloadBuilderLevel("beginner", "advanced")).to.equal("beginner");
      expect(payloadCore.normalizePayloadBuilderLevel("weird", "advanced")).to.equal("advanced");
      expect(payloadCore.normalizePayloadBuilderLevel("weird")).to.equal("beginner");
    });
  });

  describe("payload expression previews", () => {
    it("returns literal previews for plain text", () => {
      expect(payloadCore.parsePayloadExpressionPreview("hello")).to.deep.equal({
        bytes: 5,
        preview: "hello",
      });
    });

    it("expands repeated parts and counts escaped bytes", () => {
      expect(payloadCore.parsePayloadExpressionPreview("A*20+\\x00+é")).to.deep.equal({
        bytes: 23,
        preview: `${"A".repeat(16)}\\x00é`,
      });
    });

    it("returns an empty preview for empty expressions", () => {
      expect(payloadCore.parsePayloadExpressionPreview("   ")).to.deep.equal({
        bytes: 0,
        preview: "",
      });
    });
  });

  describe("byte and hex helpers", () => {
    it("formats bytes as compact, spaced and escaped hex", () => {
      expect(payloadCore.bytesToCompactHex([0, 1, 255])).to.equal("0x0001ff");
      expect(payloadCore.bytesToSpacedHex([0, 1, 255])).to.equal("00 01 ff");
      expect(payloadCore.bytesToEscapedHex([0, 1, 255])).to.equal("\\x00\\x01\\xFF");
      expect(payloadCore.formatPayloadSize(1)).to.equal("1 byte");
      expect(payloadCore.formatPayloadSize(3)).to.equal("3 bytes");
      expect(payloadCore.formatPayloadSize(-3)).to.equal("0 bytes");
    });

    it("converts arrays and typed arrays to lowercase hex", () => {
      expect(payloadCore.byteArrayToHex([0x41, 0x42, 0xff])).to.equal("4142ff");
      expect(payloadCore.byteArrayToHex(new Uint8Array([0x41, 0x42]))).to.equal("4142");
    });

    it("parses even-length hex strings into byte arrays", () => {
      expect(payloadCore.hexToByteArray("0x4142")).to.deep.equal([0x41, 0x42]);
      expect(payloadCore.hexToByteArray("41 42")).to.deep.equal([0x41, 0x42]);
      expect(payloadCore.hexToByteArray("abc")).to.deep.equal([]);
      expect(payloadCore.hexToByteArray("")).to.deep.equal([]);
    });

    it("detects null bytes in normalized hex", () => {
      expect(payloadCore.hexHasNullByte("41420043")).to.equal(true);
      expect(payloadCore.hexHasNullByte("414243")).to.equal(false);
    });
  });

  describe("capture normalization", () => {
    it("prefers valid explicit hex", () => {
      expect(payloadCore.normalizeCaptureHex({ hex: "0x41 42" })).to.equal("4142");
    });

    it("normalizes array, typed array, hex string and text captures", () => {
      expect(payloadCore.normalizeCaptureHex({ data: [0x41, 0x42] })).to.equal("4142");
      expect(payloadCore.normalizeCaptureHex({ data: new Uint8Array([0x43, 0x44]) })).to.equal("4344");
      expect(payloadCore.normalizeCaptureHex({ data: "0x4546" })).to.equal("4546");
      expect(payloadCore.normalizeCaptureHex({ data: "AZ" })).to.equal("415a");
      expect(payloadCore.normalizeCaptureHex({})).to.equal("");
    });
  });

  describe("endian hints", () => {
    it("explains little-endian dword reversal when useful", () => {
      expect(payloadCore.buildPayloadEndianHint("\\xEF\\xBE\\xAD\\xDE"))
        .to.equal("Endian: ef be ad de donne 0xdeadbeef si le programme relit ce dword en little-endian. Pour viser 0xefbeadde, utilise \\xDE\\xAD\\xBE\\xEF.");
    });

    it("omits endian hints for empty, non-dword and symmetrical values", () => {
      expect(payloadCore.buildPayloadEndianHint("")).to.equal("");
      expect(payloadCore.buildPayloadEndianHint("\\x41\\x42")).to.equal("");
      expect(payloadCore.buildPayloadEndianHint("\\x11\\x22\\x22\\x11")).to.equal("");
    });
  });
});
