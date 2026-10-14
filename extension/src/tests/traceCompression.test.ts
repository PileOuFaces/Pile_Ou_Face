const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { readTraceJson, writeTraceJson } = require('../shared/trace');

describe('compressed trace persistence', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-trace-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('round-trips plain JSON traces unchanged', () => {
    const tracePath = path.join(tempDir, 'output.run-1-plain.json');
    writeTraceJson(tracePath, { snapshots: [{ step: 1 }], risks: [], meta: {} });

    expect(fs.readFileSync(tracePath, 'utf8').trimStart()).to.match(/^\{/);
    expect(readTraceJson(tracePath).snapshots).to.deep.equal([{ step: 1 }]);
  });

  it('round-trips gzip traces based on the .json.gz extension', () => {
    const tracePath = path.join(tempDir, 'output.run-2-compressed.json.gz');
    const disasmPath = path.join(tempDir, 'output.run-2-compressed.disasm.asm');
    fs.writeFileSync(disasmPath, '0x401000: ret\n');
    writeTraceJson(tracePath, { snapshots: [{ step: 2 }], risks: [], meta: {} });

    const contents = fs.readFileSync(tracePath);
    expect([...contents.subarray(0, 2)]).to.deep.equal([0x1f, 0x8b]);
    const trace = readTraceJson(tracePath);
    expect(trace.snapshots).to.deep.equal([{ step: 2 }]);
    expect(trace.meta.disasm_path).to.equal(disasmPath);
  });
});
