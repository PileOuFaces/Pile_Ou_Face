const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

describe("staticHandlers ROP architecture forwarding", () => {
  let execFile;
  let staticHandlers;

  beforeEach(() => {
    execFile = sinon.stub().callsFake((_python, _args, _opts, cb) => {
      cb(null, "[]", "");
    });
    staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
    });
  });

  afterEach(() => {
    sinon.restore();
  });

  function makeHandlers() {
    return staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: sinon.spy() } },
    });
  }

  it("passes the selected raw blob architecture to the offensive plugin runtime command", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadRop({
      binaryPath: "/tmp/blob.raw",
      binaryMeta: {
        kind: "raw",
        rawConfig: { arch: "riscv64", endian: "little", baseAddr: "0x0" },
      },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include.members([
      "/repo/backends/plugins/runtime.py",
      "invoke",
      "offensive.rop.run",
    ]);
    const payloadIndex = args.indexOf("--payload-json");
    const payload = JSON.parse(args[payloadIndex + 1]);
    expect(payload.arch).to.equal("riscv64");
  });

  it("maps detected native architecture names before invoking the offensive plugin command", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadRop({
      binaryPath: "/tmp/sparc32.elf",
      binaryMeta: { kind: "native", arch: "SPARC32" },
    });

    const args = execFile.firstCall.args[1];
    const payloadIndex = args.indexOf("--payload-json");
    const payload = JSON.parse(args[payloadIndex + 1]);
    expect(payload.arch).to.equal("sparc");
  });

  it("uses the shared raw architecture aliases for native names", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadRop({
      binaryPath: "/tmp/demo.elf",
      binaryMeta: { kind: "native", arch: "PowerPC64" },
    });

    const args = execFile.firstCall.args[1];
    const payloadIndex = args.indexOf("--payload-json");
    const payload = JSON.parse(args[payloadIndex + 1]);
    expect(payload.arch).to.equal("ppc64");
  });

  it("passes raw base address to typed data for blob views", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadTypedData({
      binaryPath: "/tmp/blob.raw",
      section: "raw",
      valueType: "str",
      binaryMeta: {
        kind: "raw",
        rawConfig: { arch: "riscv64", endian: "little", baseAddr: "0x417000" },
      },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include("--raw-base-addr");
    expect(args[args.indexOf("--raw-base-addr") + 1]).to.equal("0x417000");
    expect(args).to.include("--raw-arch");
    expect(args[args.indexOf("--raw-arch") + 1]).to.equal("riscv64");
    expect(args).to.include("--raw-endian");
    expect(args[args.indexOf("--raw-endian") + 1]).to.equal("little");
  });

  it("passes raw architecture metadata to hex view for blob views", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadHexView({
      binaryPath: "/tmp/blob.raw",
      offset: 0,
      length: 128,
      binaryMeta: {
        kind: "raw",
        rawConfig: { arch: "thumb", endian: "little", baseAddr: "0x710000" },
      },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include("--raw-base-addr");
    expect(args[args.indexOf("--raw-base-addr") + 1]).to.equal("0x710000");
    expect(args).to.include("--raw-arch");
    expect(args[args.indexOf("--raw-arch") + 1]).to.equal("thumb");
    expect(args).to.include("--raw-endian");
    expect(args[args.indexOf("--raw-endian") + 1]).to.equal("little");
  });
});
