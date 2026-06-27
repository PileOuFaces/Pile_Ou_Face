const { expect } = require("chai");

describe("payloadToHex", () => {
  let extension;

  beforeEach(() => {
    extension = require("../src/extension");
  });

  it("converts hex string to hex", () => {
    expect(extension.payloadToHex("43434343")).to.equal("43434343");
    expect(extension.payloadToHex("0x43434343")).to.equal("43434343");
  });

  it("strips spaces from hex", () => {
    expect(extension.payloadToHex("43 43 43 43")).to.equal("43434343");
  });

  it("expands expressions and raw byte escapes to hex", () => {
    expect(extension.payloadToHex("A*4+\\xef\\xbe\\xad\\xde")).to.equal("41414141efbeadde");
  });

  it("throws on empty input", () => {
    expect(() => extension.payloadToHex("")).to.throw("payload vide");
    expect(() => extension.payloadToHex("   ")).to.throw("payload vide");
  });

  it("throws on odd hex length", () => {
    expect(() => extension.payloadToHex("4343434")).to.throw(/impair|hex/);
  });
});

describe("parseStdinExpression", () => {
  let extension;

  beforeEach(() => {
    extension = require("../src/extension");
  });

  it("returns literal when no expression", () => {
    expect(extension.parseStdinExpression("hello")).to.equal("hello");
  });

  it("expands A*64 to 64 A's", () => {
    const result = extension.parseStdinExpression("A*64");
    expect(result).to.have.length(64);
    expect(result).to.equal("A".repeat(64));
  });

  it("concatenates parts with +", () => {
    const result = extension.parseStdinExpression("A*4+BBBB");
    expect(result).to.equal("AAAABBBB");
  });
});
