// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const { createAnalysisContext } = require('../static/hub/analysisContext');

function makeContext(root, tempDir, lines) {
  return createAnalysisContext({
    root,
    pythonExe: 'python3',
    logChannel: {
      appendLine: (line) => lines.push(line),
      append: (line) => lines.push(line),
    },
    runCommand: sinon.stub(),
    runPythonJson: sinon.stub(),
    runPythonTextFile: sinon.stub(),
    resolvePathFromWorkspace: (value) => path.resolve(root, value),
    toWebviewPath: (value) => value,
    storageDir: tempDir,
    ensureTempDir: () => tempDir,
    getRawProfile: () => null,
    vscode: {},
    fs,
    path,
    crypto: require('crypto'),
    inspectBinaryInput: () => ({ supported: true, format: 'ELF' }),
    normalizeRawProfile: () => null,
    getRawArchDescriptor: () => ({}),
    readCache: sinon.stub(),
    writeCache: sinon.stub(),
    getDisasmScript: () => path.join(root, 'disasm.py'),
    getHeadersScript: () => path.join(root, 'headers.py'),
    getSymbolsScript: () => path.join(root, 'symbols.py'),
    getOffsetToVaddrScript: () => path.join(root, 'offset.py'),
    getDiscoverFunctionsScript: () => path.join(root, 'discover.py'),
    getExampleCandidates: () => [],
    normalizeAddress: (value) => value,
  });
}

describe('analysisContext artifact fallback', () => {
  it('can build disassembly args that bypass cache reads but still target the cache DB', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-artifact-fallback-'));
    const tempDir = path.join(root, '.pile-ou-face');
    fs.mkdirSync(tempDir, { recursive: true });
    const ctx = makeContext(root, tempDir, []);
    const args = ctx.buildDisasmArgs({
      binaryPath: path.join(root, 'sample.elf'),
      disasmPath: path.join(tempDir, 'sample.disasm.asm'),
      mappingPath: path.join(tempDir, 'sample.disasm.mapping.json'),
      useCacheDb: true,
      cacheWriteOnly: true,
    });

    expect(args).to.include('--cache-db');
    expect(args).to.include('--cache-write-only');
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('does not reuse another binary mapping when the requested mapping is missing', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-artifact-fallback-'));
    const tempDir = path.join(root, '.pile-ou-face');
    fs.mkdirSync(tempDir, { recursive: true });
    const lines = [];
    const rootme = path.join(root, 'rootme1.elf');
    const ls = path.join(root, 'ls');
    fs.writeFileSync(rootme, 'ELF');
    fs.writeFileSync(ls, 'ELF');
    fs.writeFileSync(
      path.join(tempDir, 'rootme1.disasm.mapping.json'),
      JSON.stringify({ binary: rootme, path: path.join(tempDir, 'rootme1.disasm.asm') }),
    );

    const ctx = makeContext(root, tempDir, lines);
    const missingLsMapping = path.join(tempDir, 'ls.disasm.mapping.json');
    const resolved = ctx.resolveLegacyArtifactFallback({
      tempDir,
      mappingPath: missingLsMapping,
      disasmPath: path.join(tempDir, 'ls.disasm.asm'),
      symbolsPath: path.join(tempDir, 'ls.symbols.json'),
      discoveredPath: path.join(tempDir, 'ls.discovered.json'),
      effectiveAbsPath: ls,
      logPrefix: 'CFG',
    });

    expect(resolved.mappingPath).to.equal(missingLsMapping);
    expect(resolved.disasmPath).to.equal(path.join(tempDir, 'ls.disasm.asm'));
    expect(lines).to.deep.include('[CFG] Mapping fallback ignoré: aucun mapping ne correspond au binaire courant');

    fs.rmSync(root, { recursive: true, force: true });
  });

  it('allows legacy fallback only when the mapping binary matches the requested binary', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-artifact-fallback-'));
    const tempDir = path.join(root, '.pile-ou-face');
    fs.mkdirSync(tempDir, { recursive: true });
    const lines = [];
    const binary = path.join(root, 'sample.elf');
    fs.writeFileSync(binary, 'ELF');
    fs.writeFileSync(
      path.join(tempDir, 'legacy.disasm.mapping.json'),
      JSON.stringify({ binary, path: path.join(tempDir, 'legacy.disasm.asm') }),
    );

    const ctx = makeContext(root, tempDir, lines);
    const resolved = ctx.resolveLegacyArtifactFallback({
      tempDir,
      mappingPath: path.join(tempDir, 'sample.disasm.mapping.json'),
      disasmPath: path.join(tempDir, 'sample.disasm.asm'),
      symbolsPath: path.join(tempDir, 'sample.symbols.json'),
      discoveredPath: path.join(tempDir, 'sample.discovered.json'),
      effectiveAbsPath: binary,
      logPrefix: 'CFG',
    });

    expect(resolved.mappingPath).to.equal(path.join(tempDir, 'legacy.disasm.mapping.json'));
    expect(resolved.disasmPath).to.equal(path.join(tempDir, 'legacy.disasm.asm'));
    expect(resolved.symbolsPath).to.equal(path.join(tempDir, 'legacy.symbols.json'));
    expect(resolved.discoveredPath).to.equal(path.join(tempDir, 'legacy.discovered.json'));
    expect(lines).to.deep.include('[CFG] Mapping fallback: legacy.disasm.mapping.json');

    fs.rmSync(root, { recursive: true, force: true });
  });
});
