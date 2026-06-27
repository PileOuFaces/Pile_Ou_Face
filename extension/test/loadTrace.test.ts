const { expect } = require("chai");
const sinon = require("sinon");
const fs = require("fs");

describe("loadTraceFromWorkspace", () => {
  let vscode;
  let extension;
  let showErrorStub;

  beforeEach(() => {
    showErrorStub = sinon.stub();
    vscode = require("vscode");
    vscode.workspace = { workspaceFolders: undefined };
    vscode.window.showErrorMessage = showErrorStub;

    extension = require("../src/extension");
  });

  afterEach(() => {
    sinon.restore();
  });

  it("returns empty when no workspace", () => {
    const res = extension.loadTraceFromWorkspace();
    expect(res).to.have.property("snapshots").with.length(0);
    expect(showErrorStub.called).to.be.true;
  });

  it("returns empty when output.json missing", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const existsStub = sinon.stub(fs, "existsSync").callsFake((_p) => false);

    const res = extension.loadTraceFromWorkspace();
    expect(res.snapshots).to.be.an("array").that.is.empty;
    expect(showErrorStub.called).to.be.true;
    existsStub.restore();
  });

  it("parses array-style output.json", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const fakeJson = JSON.stringify([{ a: 1 }, { b: 2 }]);
    sinon.stub(fs, "existsSync").callsFake((_p) => true);
    sinon.stub(fs, "readFileSync").callsFake((_p, _enc) => fakeJson);

    const res = extension.loadTraceFromWorkspace();
    expect(res.snapshots).to.deep.equal([{ a: 1 }, { b: 2 }]);
  });

  it("preserves enriched top-level dynamic analysis fields", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const fakeJson = JSON.stringify({
      snapshots: [{ step: 1, instr: "push rbp" }],
      risks: [],
      diagnostics: [{ kind: "invalid_control_flow", step: 1 }],
      crash: {
        type: "unmapped_fetch",
        step: 1,
        instructionAddress: "0x401000",
        instructionText: "ret",
      },
      analysisByStep: {
        "1": {
          frame: { slots: [{ label: "saved_rbp" }] },
          explanationBullets: ["Instruction: push rbp"]
        }
      },
      meta: { dynamic_model_version: 2 }
    });
    sinon.stub(fs, "existsSync").callsFake((_p) => true);
    sinon.stub(fs, "readFileSync").callsFake((_p, _enc) => fakeJson);

    const res = extension.loadTraceFromWorkspace();
    expect(res.analysisByStep).to.deep.equal({
      "1": {
        frame: { slots: [{ label: "saved_rbp" }] },
        explanationBullets: ["Instruction: push rbp"],
        diagnostics: [{ kind: "invalid_control_flow", step: 1 }]
      }
    });
    expect(res.diagnostics).to.deep.equal([{ kind: "invalid_control_flow", step: 1 }]);
    expect(res.crash).to.deep.equal({
      type: "unmapped_fetch",
      step: 1,
      instructionAddress: "0x401000",
      instructionText: "ret",
    });
    expect(res.meta.dynamic_model_version).to.equal(2);
  });

  it("synthesizes fallback diagnostics from legacy overflow analysis when top-level diagnostics are missing", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const fakeJson = JSON.stringify({
      snapshots: [{
        step: 10,
        instr: "call 0x401050",
        rip: "0x4011bd",
        func: "main",
        memory: {
          writes: [{
            addr: "0x7fffffffde08",
            size: 33,
            bytes: "41 41 41 41 00"
          }]
        }
      }],
      risks: [],
      analysisByStep: {
        "10": {
          buffer: {
            start: "0x7fffffffde08",
            end: "0x7fffffffde28",
            size: 32
          },
          overflow: {
            active: true,
            bufferName: "local_buf_21h",
            reached: ["saved_bp", "return_address"],
            frontier: "0x7fffffffdf58"
          },
          frame: {
            slots: [
              {
                role: "buffer",
                label: "local_buf_21h",
                start: "0x7fffffffde08",
                offsetFromBpHex: "-0x110",
                bytesHex: "41 41 41 41 00"
              },
              {
                role: "saved_bp",
                label: "saved_rbp",
                start: "0x7fffffffdf18",
                offsetFromBpHex: "+0x0",
                valueHex: "0x8049196",
                bytesHex: "96 91 04 08 00",
                flags: ["corrupted"]
              },
              {
                role: "return_address",
                label: "ret_addr",
                start: "0x7fffffffdf20",
                offsetFromBpHex: "+0x8",
                valueHex: "0x0",
                bytesHex: "00 00 00 00 00 00 00 00",
                flags: ["corrupted"]
              }
            ]
          }
        }
      },
      meta: {
        dynamic_model_version: 2,
        payload_target: "stdin"
      }
    });
    sinon.stub(fs, "existsSync").callsFake((_p) => true);
    sinon.stub(fs, "readFileSync").callsFake((_p, _enc) => fakeJson);

    const res = extension.loadTraceFromWorkspace();

    expect(res.diagnostics.map((entry) => entry.kind)).to.include("buffer_overflow");
    expect(res.diagnostics.map((entry) => entry.kind)).to.include("saved_bp_corrupted");
    expect(res.diagnostics.map((entry) => entry.kind)).to.include("return_address_corrupted");
    expect(res.analysisByStep["10"].diagnostics).to.be.an("array").that.is.not.empty;
  });

  it("filters stale top-level corruption diagnostics without current write evidence", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const fakeJson = JSON.stringify({
      snapshots: [{
        step: 1,
        instr: "mov eax, eax",
        rip: "0x401010",
        func: "main",
        memory: { writes: [] }
      }],
      risks: [],
      diagnostics: [{
        kind: "return_address_corrupted",
        severity: "error",
        step: 1,
        instructionAddress: "0x401010",
        slot: {
          kind: "return_address",
          address: "0x7fffffffe008"
        }
      }],
      analysisByStep: {
        "1": {
          overflow: {
            active: true,
            reached: ["return_address"],
            progressBytes: 0
          },
          frame: {
            slots: [{
              role: "return_address",
              start: "0x7fffffffe008",
              flags: ["corrupted"],
              valueHex: "0x0"
            }]
          },
          delta: { writes: [] }
        }
      },
      meta: {}
    });
    sinon.stub(fs, "existsSync").callsFake((_p) => true);
    sinon.stub(fs, "readFileSync").callsFake((_p, _enc) => fakeJson);

    const res = extension.loadTraceFromWorkspace();

    expect(res.diagnostics).to.deep.equal([]);
    expect(res.analysisByStep["1"]).to.not.have.property("diagnostics");
  });
});
