// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  applyAnnotationOverlayMutation,
  splitAsmLine,
  stackHintsPart,
  typedStructPart,
  commentSuffix,
} = require('../shared/annotationOverlayPatch');

function writeArtifacts(dir, { asmLines, mappingLines, functions = [] }) {
  const asmPath = path.join(dir, 'sample.disasm.asm');
  const mappingPath = path.join(dir, 'sample.disasm.mapping.json');
  fs.writeFileSync(asmPath, asmLines.join('\n'), 'utf8');
  fs.writeFileSync(mappingPath, JSON.stringify({ lines: mappingLines, functions }), 'utf8');
  return { asmPath, mappingPath };
}

describe('annotationOverlayPatch', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-overlay-patch-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('patches a comment onto a line without any suffix', () => {
    const { asmPath, mappingPath } = writeArtifacts(dir, {
      asmLines: ['  0x401000:  mov eax, 1', '  0x401004:  ret'],
      mappingLines: [
        { addr: '0x401000', line: 1, label: null, comment: null, stack_hints: [], typed_struct_hints: [] },
        { addr: '0x401004', line: 2, label: null, comment: null, stack_hints: [], typed_struct_hints: [] },
      ],
    });
    const verdict = applyAnnotationOverlayMutation({ mappingPath, addr: '0x401004', comment: 'sortie' });
    expect(verdict).to.equal('patched');
    const asm = fs.readFileSync(asmPath, 'utf8').split('\n');
    expect(asm[1]).to.equal('  0x401004:  ret  ; sortie');
    const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
    expect(mapping.lines[1].comment).to.equal('sortie');
  });

  it('replaces a comment while preserving dwarf src and hints', () => {
    const stackHints = [{ kind: 'var', name: 'x', location: 'rbp-0x8' }];
    const { asmPath, mappingPath } = writeArtifacts(dir, {
      asmLines: [
        '  0x401000:  mov eax, 1  ; main.c:12 | ancien | var x @ rbp-0x8',
      ],
      mappingLines: [
        { addr: '0x401000', line: 1, label: null, comment: 'ancien', stack_hints: stackHints, typed_struct_hints: [] },
      ],
    });
    const verdict = applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', comment: 'nouveau' });
    expect(verdict).to.equal('patched');
    const asm = fs.readFileSync(asmPath, 'utf8');
    expect(asm).to.equal('  0x401000:  mov eax, 1  ; main.c:12 | nouveau | var x @ rbp-0x8');
  });

  it('removes a comment but keeps the remaining hint parts', () => {
    const stackHints = [{ kind: 'arg', name: 'argc', location: 'edi' }];
    const { asmPath, mappingPath } = writeArtifacts(dir, {
      asmLines: ['  0x401000:  mov eax, edi  ; a-virer | arg argc @ edi'],
      mappingLines: [
        { addr: '0x401000', line: 1, label: null, comment: 'a-virer', stack_hints: stackHints, typed_struct_hints: [] },
      ],
    });
    const verdict = applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', deleted: true });
    expect(verdict).to.equal('patched');
    expect(fs.readFileSync(asmPath, 'utf8')).to.equal('  0x401000:  mov eax, edi  ; arg argc @ edi');
  });

  it('requires a rebuild when a rename changes the baked label', () => {
    const { mappingPath } = writeArtifacts(dir, {
      asmLines: ['  0x401000:  ret'],
      mappingLines: [
        { addr: '0x401000', line: 1, label: null, comment: null, stack_hints: [], typed_struct_hints: [] },
      ],
    });
    expect(applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', name: 'entry_point' }))
      .to.equal('rebuild-required');
  });

  it('requires a rebuild when deleting a baked user rename', () => {
    const { mappingPath } = writeArtifacts(dir, {
      asmLines: ['; -- function rename @ 0x401000 --', 'mon_entree:', '  0x401000:  ret'],
      mappingLines: [
        { addr: '0x401000', line: 3, label: 'mon_entree', comment: null, stack_hints: [], typed_struct_hints: [] },
      ],
      functions: [{ addr: '0x401000', name: 'entry0' }],
    });
    expect(applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', deleted: true }))
      .to.equal('rebuild-required');
  });

  it('treats a rename equal to the original function name as patchable', () => {
    const { asmPath, mappingPath } = writeArtifacts(dir, {
      asmLines: ['; -- function rename @ 0x401000 --', 'entry0:', '  0x401000:  ret'],
      mappingLines: [
        { addr: '0x401000', line: 3, label: 'entry0', comment: null, stack_hints: [], typed_struct_hints: [] },
      ],
      functions: [{ addr: '0x401000', name: 'entry0' }],
    });
    const verdict = applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', name: 'entry0', comment: 'point d entree' });
    expect(verdict).to.equal('patched');
    expect(fs.readFileSync(asmPath, 'utf8').split('\n')[2])
      .to.equal('  0x401000:  ret  ; point d entree');
  });

  it('falls back to rebuild when the mapping line does not match the asm', () => {
    const { mappingPath } = writeArtifacts(dir, {
      asmLines: ['  0x401000:  mov eax, 1', '  0x401004:  ret'],
      mappingLines: [
        { addr: '0x401004', line: 1, label: null, comment: null, stack_hints: [], typed_struct_hints: [] },
      ],
    });
    expect(applyAnnotationOverlayMutation({ mappingPath, addr: '0x401004', comment: 'x' }))
      .to.equal('rebuild-required');
  });

  it('reports unchanged for identical comments and unknown addresses', () => {
    const { mappingPath } = writeArtifacts(dir, {
      asmLines: ['  0x401000:  ret  ; pareil'],
      mappingLines: [
        { addr: '0x401000', line: 1, label: null, comment: 'pareil', stack_hints: [], typed_struct_hints: [] },
      ],
    });
    expect(applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', comment: 'pareil' }))
      .to.equal('unchanged');
    expect(applyAnnotationOverlayMutation({ mappingPath, addr: '0xdead', comment: 'x' }))
      .to.equal('unchanged');
  });

  it('reports unchanged when artifacts do not exist yet', () => {
    const mappingPath = path.join(dir, 'missing.disasm.mapping.json');
    expect(applyAnnotationOverlayMutation({ mappingPath, addr: '0x401000', comment: 'x' }))
      .to.equal('unchanged');
  });

  it('mirrors disasm.py suffix building rules', () => {
    expect(commentSuffix([])).to.equal('');
    expect(commentSuffix(['', 'a', ' b '])).to.equal('  ; a | b');
    expect(stackHintsPart([{ kind: 'var', name: 'x', location: 'rbp-0x8' }, { kind: 'arg', name: 'y', location: 'esi' }]))
      .to.equal('var x @ rbp-0x8, arg y @ esi');
    expect(typedStructPart([{ label: 'hdr' }, { addr: '0x10' }, { label: 'c' }]))
      .to.equal('struct hdr, 0x10, +1');
    expect(splitAsmLine('  0x1:  ret', { oldComment: '', stackPart: '', structPart: '' }))
      .to.deep.equal({ instr: '  0x1:  ret', src: '' });
    expect(splitAsmLine('  0x1:  ret  ; f.c:3', { oldComment: '', stackPart: '', structPart: '' }))
      .to.deep.equal({ instr: '  0x1:  ret', src: 'f.c:3' });
    expect(splitAsmLine('  0x1:  ret  ; x | y', { oldComment: 'z', stackPart: '', structPart: '' }))
      .to.equal(null);
  });
});
