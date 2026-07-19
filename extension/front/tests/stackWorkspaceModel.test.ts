const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('stackWorkspaceModel', () => {
  let buildStackWorkspaceModel;
  let resolveModelForFunction;
  let resolveModelForFunctionSelection;

  before(async () => {
    const coreModulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceCore.js');
    const debugModulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceDebug.js');
    ({ buildStackWorkspaceModel } = await import(pathToFileURL(coreModulePath).href));
    ({ resolveModelForFunction, resolveModelForFunctionSelection } = await import(pathToFileURL(debugModulePath).href));
  });

  function summarizeEntries(workspace) {
    return workspace.frameModel.entries.map((entry) => ({
      name: entry.name,
      kind: entry.kind,
      offset: entry.offset,
      size: entry.size
    }));
  }

  function assertControlSlotsProtected(workspace) {
    const saved = workspace.frameModel.entries.find((entry) => entry.kind === 'saved_bp');
    const ret = workspace.frameModel.entries.find((entry) => entry.kind === 'return_address');
    expect(saved).to.include({ isSensitive: true, provenance: 'control' });
    expect(ret).to.include({ isSensitive: true, provenance: 'control' });
  }

  function assertNoDuplicateOverlaps(workspace) {
    const entries = workspace.frameModel.entries;
    entries.forEach((left, leftIndex) => {
      entries.slice(leftIndex + 1).forEach((right) => {
        const overlaps = left.offset < right.offset + right.size && right.offset < left.offset + left.size;
        const allowedNestedModified = [left.kind, right.kind].includes('modified') && [left.kind, right.kind].includes('buffer');
        expect(overlaps && !allowedNestedModified, `${left.name} overlaps ${right.name}`).to.equal(false);
      });
    });
  }

  function assertNoUnexpectedSynthetic(workspace) {
    expect(workspace.frameModel.entries.some((entry) => (
      entry.isSynthetic && (entry.kind === 'unknown' || entry.kind === 'padding' || entry.kind === 'buffer')
    ))).to.equal(false);
  }

  function assertNoSyntheticInsideAnchoredRanges(workspace) {
    const anchored = workspace.frameModel.entries.filter((entry) => entry.provenance === 'source_c');
    const synthetic = workspace.frameModel.entries.filter((entry) => entry.isSynthetic);
    anchored.forEach((sourceEntry) => {
      synthetic.forEach((candidate) => {
        const inside = candidate.offset >= sourceEntry.offset && candidate.offset + candidate.size <= sourceEntry.offset + sourceEntry.size;
        expect(inside, `${candidate.name} is inside ${sourceEntry.name}`).to.equal(false);
      });
    });
  }

  function buildMainCallSiteWorkspace({ currentStep = 40 } = {}) {
    return buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x7fffffffe020',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe008',
          displayValue: '0x401262',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'argv',
          technicalLabel: 'var_30',
          semanticRole: 'local',
          size: 8,
          offsetFromBp: -48,
          offsetFromBpLabel: 'RBP -0x30',
          addressLabel: '0x7fffffffdfd0',
          displayValue: '0x7fffffffdf60',
          rawValue: '0x7fffffffdf60',
          pointerKind: 'stack',
          source: 'auto'
        },
        {
          key: 'argc',
          technicalLabel: 'var_24',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -36,
          offsetFromBpLabel: 'RBP -0x24',
          addressLabel: '0x7fffffffdfdc',
          displayValue: '0x2',
          rawValue: '0x2',
          source: 'auto'
        },
        {
          key: 'm',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdffc',
          displayValue: '0x7',
          rawValue: '0x7',
          source: 'auto'
        },
        {
          key: 'mainbuf',
          technicalLabel: 'stack_20h',
          semanticRole: 'unknown',
          size: 24,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffdfe0',
          displayValue: '"MMMM"',
          ascii: 'MMMM',
          bytesHex: '4d 4d 4d 4d',
          source: 'heuristic'
        },
        {
          key: 'ghost-buf',
          technicalLabel: 'stack_48h',
          semanticRole: 'unknown',
          size: 48,
          offsetFromBp: -72,
          offsetFromBpLabel: 'RBP -0x48',
          addressLabel: '0x7fffffffdfb8',
          displayValue: '"BBBB"',
          ascii: 'BBBB',
          source: 'heuristic'
        },
        {
          key: 'ghost-local',
          technicalLabel: 'var_50',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -80,
          offsetFromBpLabel: 'RBP -0x50',
          addressLabel: '0x7fffffffdfb0',
          displayValue: '0x0',
          source: 'auto'
        },
        {
          key: 'ghost-local2',
          technicalLabel: 'var_54',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -84,
          offsetFromBpLabel: 'RBP -0x54',
          addressLabel: '0x7fffffffdfac',
          displayValue: '0x0',
          source: 'auto'
        },
        {
          key: 'ghost-unknown',
          technicalLabel: 'stack_60h',
          semanticRole: 'unknown',
          size: 8,
          offsetFromBp: -96,
          offsetFromBpLabel: 'RBP -0x60',
          addressLabel: '0x7fffffffdfa0',
          displayValue: '0x0',
          source: 'heuristic'
        },
        {
          key: 'ghost-arg0',
          technicalLabel: 'arg_0',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: -104,
          offsetFromBpLabel: 'RBP -0x68',
          addressLabel: '0x7fffffffdf98',
          displayValue: '0x41414141',
          rawValue: '0x41414141',
          source: 'auto'
        },
        {
          key: 'ghost-arg1',
          technicalLabel: 'arg_1',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: -108,
          offsetFromBpLabel: 'RBP -0x6c',
          addressLabel: '0x7fffffffdf94',
          displayValue: '0x7',
          rawValue: '0x7',
          source: 'auto'
        }
      ],
      snapshots: [
        { step: currentStep, func: 'main' },
        {
          step: currentStep + 1,
          func: 'sink',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdf90',
                rdi: '0x7fffffffdf40',
                rdx: '0x30'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdf40', size: 48 }
            ]
          }
        }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/test3.elf'
      },
      currentStep,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 48,
          basePointer: '0x7fffffffe000',
          stackPointer: '0x7fffffffdfd0',
          registerArguments: [
            { location: 'rdi', name: 'argc', offset: null, size: 8, source: 'abi' },
            { location: 'rsi', name: 'argv', offset: null, size: 8, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffe000',
          retAddrAddr: '0x7fffffffe008'
        },
        delta: {
          writes: [
            { addr: '0x7fffffffdf40', size: 48 }
          ]
        }
      },
      mcp: {
        model: {
          name: 'main',
          locals: [
            { offset: -48, name: 'argv', role: 'argument', cType: 'char **', size: 8, source: 'mcp', confidence: 0.95 },
            { offset: -36, name: 'argc', role: 'argument', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -32, name: 'main_buf', role: 'buffer', cType: 'char[24]', size: 24, source: 'mcp', confidence: 0.95 },
            { offset: -4, name: 'main_local', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 }
          ]
        }
      }
    });
  }

  function buildSinkWorkspace({ currentStep = 42 } = {}) {
    return buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdf90',
          displayValue: '0x7fffffffe000',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffdf98',
          displayValue: '0x401251',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'arg-input',
          technicalLabel: 'var_68',
          semanticRole: 'local',
          size: 8,
          offsetFromBp: -104,
          offsetFromBpLabel: 'RBP -0x68',
          addressLabel: '0x7fffffffdf28',
          displayValue: '0x7fffffffdfb0',
          rawValue: '0x7fffffffdfb0',
          pointerKind: 'stack',
          source: 'auto'
        },
        {
          key: 'arg-n',
          technicalLabel: 'var_6c',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -108,
          offsetFromBpLabel: 'RBP -0x6c',
          addressLabel: '0x7fffffffdf24',
          displayValue: '0x7',
          rawValue: '0x7',
          source: 'auto'
        },
        {
          key: 'x',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdf8c',
          displayValue: '0x8',
          source: 'auto'
        },
        {
          key: 'y',
          technicalLabel: 'var_8',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -8,
          offsetFromBpLabel: 'RBP -0x8',
          addressLabel: '0x7fffffffdf88',
          displayValue: '0x9',
          source: 'auto'
        },
        {
          key: 'guard',
          technicalLabel: 'var_54',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -84,
          offsetFromBpLabel: 'RBP -0x54',
          addressLabel: '0x7fffffffdf3c',
          displayValue: '0x11223344',
          source: 'auto'
        },
        {
          key: 'small-frag1',
          technicalLabel: 'stack_20h',
          semanticRole: 'unknown',
          size: 8,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffdf70',
          displayValue: '"SSSS"',
          ascii: 'SSSS',
          source: 'heuristic'
        },
        {
          key: 'small-frag2',
          technicalLabel: 'stack_18h',
          semanticRole: 'unknown',
          size: 8,
          offsetFromBp: -24,
          offsetFromBpLabel: 'RBP -0x18',
          addressLabel: '0x7fffffffdf78',
          displayValue: '"SSSS"',
          ascii: 'SSSS',
          source: 'heuristic'
        },
        {
          key: 'big',
          technicalLabel: 'stack_50h',
          semanticRole: 'unknown',
          size: 48,
          offsetFromBp: -80,
          offsetFromBpLabel: 'RBP -0x50',
          addressLabel: '0x7fffffffdf40',
          displayValue: '"BBBB"',
          ascii: 'BBBB',
          source: 'heuristic'
        }
      ],
      snapshots: [
        {
          step: currentStep - 1,
          func: 'sink',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdf90',
                rdi: '0x7fffffffdf70',
                rdx: '0x10'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdf70', size: 16 }
            ]
          }
        },
        {
          step: currentStep,
          func: 'sink',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdf90',
                rdi: '0x7fffffffdf40',
                rdx: '0x30'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdf40', size: 48 }
            ]
          }
        }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/test3.elf'
      },
      currentStep,
      selectedFunction: 'sink',
      snapshot: {
        func: 'sink',
        cpu: {
          before: {
            registers: {
              rdi: '0x7fffffffdfb0',
              rsi: '0x7'
            }
          }
        }
      },
      analysis: {
        frame: {
          frameSize: 112,
          basePointer: '0x7fffffffdf90',
          stackPointer: '0x7fffffffdf20',
          registerArguments: [
            { location: 'rdi', name: 'input', offset: null, size: 8, source: 'abi' },
            { location: 'rsi', name: 'n', offset: null, size: 4, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffdf90',
          retAddrAddr: '0x7fffffffdf98'
        },
        delta: {
          writes: [
            { addr: '0x7fffffffdf70', size: 16 },
            { addr: '0x7fffffffdf40', size: 48 }
          ]
        }
      },
      mcp: {
        model: {
          name: 'sink',
          locals: [
            { offset: -104, name: 'input', role: 'argument', cType: 'char *', size: 8, source: 'mcp', confidence: 0.95 },
            { offset: -108, name: 'n', role: 'argument', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -80, name: 'big', role: 'buffer', cType: 'char[48]', size: 48, source: 'mcp', confidence: 0.95 },
            { offset: -32, name: 'small', role: 'buffer', cType: 'char[16]', size: 16, source: 'mcp', confidence: 0.95 },
            { offset: -84, name: 'guard', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -8, name: 'y', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -4, name: 'x', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 }
          ]
        }
      }
    });
  }

  it('builds a canonical x86 frame ordered by ebp offsets and merges buffer observations', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'argv-raw',
          technicalLabel: 'arg_c',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: 12,
          offsetFromBpLabel: 'EBP +0xc',
          addressLabel: '0xffffd03c',
          displayValue: '0xffffd100',
          source: 'static'
        },
        {
          key: 'argc-raw',
          technicalLabel: 'arg_8',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: 8,
          offsetFromBpLabel: 'EBP +0x8',
          addressLabel: '0xffffd038',
          displayValue: '0x2',
          source: 'static'
        },
        {
          key: 'saved-raw',
          technicalLabel: 'saved_ebp',
          semanticRole: 'saved_bp',
          size: 4,
          offsetFromBp: 0,
          offsetFromBpLabel: 'EBP +0x0',
          addressLabel: '0xffffd030',
          displayValue: '0xffffd090',
          source: 'control'
        },
        {
          key: 'ret-raw',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 4,
          offsetFromBp: 4,
          offsetFromBpLabel: 'EBP +0x4',
          addressLabel: '0xffffd034',
          displayValue: '0x80491ab',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'buffer-head',
          technicalLabel: 'stack_50h',
          semanticRole: 'unknown',
          size: 16,
          offsetFromBp: -80,
          offsetFromBpLabel: 'EBP -0x50',
          addressLabel: '0xffffcfe0',
          displayValue: '"AAAA"',
          bytesHex: '41 41 41 41',
          ascii: 'AAAA',
          source: 'heuristic'
        },
        {
          key: 'buffer-tail',
          technicalLabel: 'stack_48h',
          semanticRole: 'unknown',
          size: 64,
          offsetFromBp: -72,
          offsetFromBpLabel: 'EBP -0x48',
          addressLabel: '0xffffcfe8',
          displayValue: '"AAAA..."',
          bytesHex: '41 41 41 41 41 41 41 41',
          ascii: 'AAAAAAAA',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'modified-raw',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'EBP -0x4',
          addressLabel: '0xffffd02c',
          displayValue: '0x43434343',
          source: 'auto'
        }
      ],
      snapshots: [{ step: 1, func: 'main' }],
      meta: {
        arch_bits: 32,
        binary: 'examples/stack3.elf'
      },
      currentStep: 1,
      selectedFunction: 'main',
      selectedSlotKey: 'main:ebp:buffer:-80:64:frame',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 96,
          basePointer: '0xffffd030',
          stackPointer: '0xffffcfd0'
        },
        control: {
          savedBpAddr: '0xffffd030',
          retAddrAddr: '0xffffd034'
        }
      },
      mcp: {
        model: {
          name: 'main',
          locals: [
            { offset: -80, name: 'buffer', role: 'buffer', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.95 },
            { offset: -4, name: 'modified', role: 'modified', cType: 'int', size: 4, source: 'mcp', confidence: 0.96 }
          ]
        }
      }
    });

    expect(workspace.frameModel.entries.map((entry) => `${entry.name}:${entry.offsetLabel}`)).to.deep.equal([
      'argv:ebp+0xc',
      'argc:ebp+0x8',
      'return address:ebp+0x4',
      'saved ebp:ebp+0x0',
      'modified:ebp-0x4',
      'buffer:ebp-0x50'
    ]);
    expect(workspace.frameModel.entries.filter((entry) => entry.name === 'buffer')).to.have.length(1);
    expect(workspace.detailModel.title).to.equal('buffer');
    expect(workspace.detailModel.rows.find((row) => row.label === 'Type').value).to.equal('char[64]');
    expect(workspace.detailModel.rows.find((row) => row.label === 'Offset').value).to.equal('ebp-0x50');
  });

  it('keeps modified visible when a recovered buffer extent overlaps it after overflow', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'buffer-raw',
          technicalLabel: 'buffer',
          semanticRole: 'buffer',
          size: 80,
          offsetFromBp: -80,
          offsetFromBpLabel: 'RBP -0x50',
          addressLabel: '0x7fffffffde70',
          displayValue: '"AAAA..."',
          ascii: 'AAAA',
          bytesHex: '41 41 41 41',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'modified-raw',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdebc',
          displayValue: '0x43434343',
          ascii: 'CCCC',
          bytesHex: '43 43 43 43',
          recentWrite: true,
          source: 'auto'
        }
      ],
      snapshots: [{ step: 19, func: 'main' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3_strcpy.elf'
      },
      currentStep: 19,
      selectedFunction: 'main',
      snapshot: {
        func: 'main',
        effects: {
          external_symbol: 'strcpy'
        }
      },
      analysis: {
        frame: {
          frameSize: 104,
          basePointer: '0x7fffffffdec0',
          stackPointer: '0x7fffffffde58'
        },
        control: {
          savedBpAddr: '0x7fffffffdec0',
          retAddrAddr: '0x7fffffffdec8'
        },
        delta: {
          writes: [
            { addr: '0x7fffffffde70', size: 80 }
          ]
        }
      },
      mcp: {
        model: {
          name: 'main',
          locals: [
            { offset: -80, name: 'buffer', role: 'buffer', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.95 },
            { offset: -4, name: 'modified', role: 'modified', cType: 'int', size: 4, source: 'mcp', confidence: 0.96 }
          ]
        }
      }
    });

    expect(workspace.frameModel.entries.map((entry) => `${entry.name}:${entry.offsetLabel}:${entry.size}`)).to.deep.equal([
      'return address:rbp+0x8:8',
      'saved rbp:rbp+0x0:8',
      'modified:rbp-0x4:4',
      'buffer:rbp-0x50:80'
    ]);
  });

  it('uses deterministic local_N and unknown_N fallbacks instead of ida-style names', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'local-raw',
          technicalLabel: 'var_8',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -8,
          offsetFromBpLabel: 'RBP -0x8',
          addressLabel: '0x7fffffffdff0',
          displayValue: '0x0',
          source: 'auto'
        },
        {
          key: 'weak-local',
          technicalLabel: 'var_20',
          semanticRole: 'local',
          size: 8,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffdfd8',
          displayValue: '"ABCD"',
          ascii: 'ABCD',
          recentWrite: true,
          source: 'auto'
        },
        {
          key: 'unknown-raw',
          technicalLabel: 'stack_118h',
          semanticRole: 'unknown',
          size: 24,
          offsetFromBp: -280,
          offsetFromBpLabel: 'RBP -0x118',
          addressLabel: '0x7fffffffdee0',
          displayValue: '"..."',
          source: 'heuristic'
        }
      ],
      snapshots: [{ step: 1, func: 'vuln' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf'
      },
      currentStep: 1,
      selectedFunction: 'vuln',
      snapshot: { func: 'vuln' },
      analysis: {
        frame: {
          frameSize: 112,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffded8'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      }
    });

    const names = workspace.frameModel.entries.map((entry) => entry.name);
    expect(names).to.include('local_0');
    expect(names).to.include('local_1');
    expect(names).to.include('unknown_0');
    expect(names).to.not.include('var_8h');
    expect(names).to.not.include('var_20h');
    expect(names).to.not.include('donnee inconnue');
    expect(workspace.frameModel.entries.find((entry) => entry.name === 'local_1').kind).to.equal('local');
  });

  it('keeps a stable canonical key across steps when the same frame object remains', () => {
    const common = {
      snapshots: [{ step: 1, func: 'vuln' }, { step: 2, func: 'vuln' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf'
      },
      selectedFunction: 'vuln',
      snapshot: { func: 'vuln' },
      analysis: {
        frame: {
          frameSize: 16,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdfe8'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      },
      mcp: {
        model: {
          name: 'vuln',
          locals: [
            { offset: -4, name: 'modified', role: 'modified', cType: 'int', size: 4, source: 'mcp', confidence: 0.96 }
          ]
        }
      }
    };

    const first = buildStackWorkspaceModel({
      ...common,
      currentStep: 1,
      selectedSlotKey: '',
      slots: [
        {
          key: 'step1-var4',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdff4',
          displayValue: '0x1',
          source: 'auto'
        }
      ]
    });

    const selectedKey = first.frameModel.entries.find((entry) => entry.name === 'modified').key;

    const second = buildStackWorkspaceModel({
      ...common,
      currentStep: 2,
      selectedSlotKey: selectedKey,
      slots: [
        {
          key: 'step2-var4',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdff4',
          displayValue: '0x43434343',
          recentWrite: true,
          source: 'auto'
        }
      ]
    });

    expect(second.selectedSlotKey).to.equal(selectedKey);
    expect(second.detailModel.title).to.equal('modified');
    expect(second.detailModel.rows.find((row) => row.label === 'Offset').value).to.equal('rbp-0x4');
  });

  it('builds the function list from the trace and keeps the panel in function mode when nothing is selected', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [],
      snapshots: [
        { step: 1, func: 'main' },
        { step: 2, func: 'vuln' },
        { step: 3, func: 'vuln' },
        { step: 4, func: 'foo' }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf',
        functions: [
          { name: 'main', addr: '0x401100', type: 'T' },
          { name: 'vuln', addr: '0x401180', type: 'T' },
          { name: 'foo', addr: '0x4011c0', type: 'T' }
        ]
      },
      currentStep: 2,
      selectedFunction: '',
      snapshot: { func: 'vuln' }
    });

    expect(workspace.functionList.map((entry) => entry.displayName)).to.deep.equal(['main', 'vuln', 'foo']);
    expect(workspace.functionList.find((entry) => entry.displayName === 'vuln').isCurrent).to.equal(true);
    expect(workspace.functionList.some((entry) => entry.isSelected)).to.equal(false);
    expect(workspace.panelMode).to.equal('functions');
  });

  it('does not reuse the current snapshot model when another function is explicitly selected', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x401d3a',
          pointerKind: 'code',
          source: 'control'
        }
      ],
      snapshots: [
        { step: 10, func: 'win', rip: '0x401aae' }
      ],
      currentStep: 10,
      selectedFunction: 'challenge',
      snapshot: { func: 'win' },
      analysis: {
        frame: {
          frameSize: 0x860,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffd798'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      },
      mcp: {
        model: {
          name: 'win',
          locals: [
            { offset: -64, name: 'win_buf', role: 'buffer', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.95 }
          ]
        }
      }
    });

    expect(workspace.frameModel.functionName).to.equal('challenge');
    expect(workspace.frameModel.entries.map((entry) => entry.name)).to.not.include('win_buf');
    expect(workspace.frameModel.entries.every((entry) => String(entry.key).startsWith('challenge:'))).to.equal(true);
    expect(workspace.frameModel.debug).to.include({
      requestedFunction: 'challenge',
      rejectedFunction: 'win',
      rejectedReason: 'function_mismatch'
    });
  });

  it('rejects an explicit function selection when the available model belongs to another function', () => {
    const model = {
      name: 'main',
      locals: [
        { offset: -64, name: 'buffer', role: 'buffer', size: 64 }
      ]
    };

    const result = resolveModelForFunctionSelection(model, 'challenge', 'main');

    expect(resolveModelForFunction(model, 'challenge', 'main')).to.equal(null);
    expect(result.model).to.equal(null);
    expect(result).to.include({
      requestedFunction: 'challenge',
      resolvedFunction: 'main',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });
  });

  it('rejects an explicit function selection when model item ids belong to another function', () => {
    const model = {
      name: 'challenge',
      locals: [
        {
          id: 'main:rbp:buffer:-64:64:frame',
          offset: -64,
          name: 'buffer',
          role: 'buffer',
          size: 64
        }
      ]
    };

    const result = resolveModelForFunctionSelection(model, 'challenge', 'challenge');

    expect(result.model).to.equal(null);
    expect(result).to.include({
      requestedFunction: 'challenge',
      resolvedFunction: 'challenge',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });
  });

  it('accepts an explicit function selection when the model identity matches', () => {
    const model = {
      name: 'challenge',
      locals: [
        { offset: -448, name: 'buffer', role: 'buffer', size: 440 }
      ]
    };

    const result = resolveModelForFunctionSelection(model, 'challenge', 'main');

    expect(result.model).to.equal(model);
    expect(resolveModelForFunction(model, 'challenge', 'main')).to.equal(model);
    expect(result).to.include({
      requestedFunction: 'challenge',
      resolvedFunction: 'challenge',
      rejectedReason: ''
    });
  });

  it('preserves current-function fallback when no function is explicitly selected', () => {
    const model = {
      name: 'main',
      locals: [
        { offset: -64, name: 'buffer', role: 'buffer', size: 64 }
      ]
    };

    const result = resolveModelForFunctionSelection(model, '', 'main');

    expect(result.model).to.equal(model);
    expect(resolveModelForFunction(model, '', 'main')).to.equal(model);
    expect(result).to.include({
      requestedFunction: '',
      resolvedFunction: 'main',
      rejectedReason: ''
    });
  });

  it('normalizes function labels before matching explicit selections to models', () => {
    const model = {
      name: 'sym.challenge@0x1ec8',
      locals: [
        { id: 'challenge:rbp:buffer:-448:440:frame', offset: -448, name: 'buffer', role: 'buffer', size: 440 }
      ]
    };

    const result = resolveModelForFunctionSelection(model, 'challenge()', 'main');

    expect(result.model).to.equal(model);
    expect(result).to.include({
      requestedFunction: 'challenge',
      resolvedFunction: 'challenge',
      rejectedReason: ''
    });
  });

  it('renders an explicit empty frame instead of stale main entries when selecting challenge from main', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'main-buffer',
          technicalLabel: 'buffer',
          semanticRole: 'buffer',
          size: 64,
          offsetFromBp: -64,
          offsetFromBpLabel: 'RBP -0x40',
          addressLabel: '0x7fffffffdfc0',
          displayValue: '"AAAA"',
          source: 'static'
        }
      ],
      snapshots: [
        { step: 1, func: 'main' }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/pwncollege/latent-leakage-hard'
      },
      currentStep: 1,
      selectedFunction: 'challenge',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 64,
          basePointer: '0x7fffffffe000',
          stackPointer: '0x7fffffffdfc0'
        },
        control: {
          savedBpAddr: '0x7fffffffe000',
          retAddrAddr: '0x7fffffffe008'
        }
      },
      mcp: {
        model: {
          name: 'main',
          locals: [
            { id: 'main:rbp:buffer:-64:64:frame', offset: -64, name: 'buffer', role: 'buffer', size: 64 }
          ]
        }
      }
    });

    expect(workspace.frameModel.functionName).to.equal('challenge');
    expect(workspace.frameModel.entries).to.deep.equal([]);
    expect(workspace.frameModel.emptyText).to.equal('challenge() is selected, but the current trace step is still in main().');
    expect(workspace.frameModel.emptyState).to.include({
      guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
      noExecutedStepText: 'No executed step for challenge() in this trace.',
      actionLabel: '',
      actionStep: null
    });
    expect(workspace.frameModel.debug).to.include({
      requestedFunction: 'challenge',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });
  });

  it('uses source C functions for the dynamic .text list and hides ELF boilerplate symbols', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [],
      snapshots: [
        { step: 1, func: 'main' },
        { step: 2, func: 'main' }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3.elf',
        functions: [
          { name: '_init', addr: '0x401000', type: 'T' },
          { name: '_start', addr: '0x401050', type: 'T' },
          { name: 'win', addr: '0x401136', type: 'T' },
          { name: 'main', addr: '0x401147', type: 'T' },
          { name: '_fini', addr: '0x40118c', type: 'T' }
        ],
        source_enrichment: {
          enabled: true,
          status: 'matched',
          functions: [
            { index: 0, name: 'win', normalizedName: 'win' },
            { index: 1, name: 'main', normalizedName: 'main' }
          ]
        }
      },
      currentStep: 1,
      selectedFunction: '',
      snapshot: { func: 'main' }
    });

    expect(workspace.functionList.map((entry) => entry.displayName)).to.deep.equal(['win', 'main']);
    expect(workspace.functionList.find((entry) => entry.displayName === 'win')).to.include({
      addressLabel: '0x401136',
      stepCount: 0,
      sourceBacked: true
    });
    expect(workspace.functionList.find((entry) => entry.displayName === 'main')).to.include({
      addressLabel: '0x401147',
      stepCount: 2,
      sourceBacked: true
    });
    expect(workspace.panelMode).to.equal('functions');
    expect(workspace.panelSubtitle).to.equal('2 fonctions du code');
  });

  it('does not create ghost positive arguments on x64 and keeps only the real negative spill', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'ghost-arg',
          technicalLabel: 'arg_10h',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: 16,
          offsetFromBpLabel: 'RBP +0x10',
          addressLabel: '0x7fffffffdff0',
          displayValue: '0x41414141',
          source: 'static'
        },
        {
          key: 'spill',
          technicalLabel: 'arg_rsi',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: -96,
          offsetFromBpLabel: 'RBP -0x60',
          addressLabel: '0x7fffffffdf98',
          displayValue: '0x7fffffffe120',
          pointerKind: 'stack',
          source: 'auto'
        }
      ],
      snapshots: [{ step: 1, func: 'vuln' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf'
      },
      currentStep: 1,
      selectedFunction: 'vuln',
      snapshot: { func: 'vuln' },
      analysis: {
        frame: {
          frameSize: 128,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdf80',
          registerArguments: [
            { location: 'rsi', name: 'argv', offset: null, size: 8, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      }
    });

    const names = workspace.frameModel.entries.map((entry) => entry.name);
    const offsets = workspace.frameModel.entries.map((entry) => entry.offsetLabel);
    expect(names).to.not.include('arg_10h');
    expect(offsets).to.not.include('rbp+0x10');
    expect(workspace.frameModel.entries.find((entry) => entry.offsetLabel === 'rbp-0x60').name).to.equal('arg_0');
  });

  it('normalizes and compacts the static x64 main frame before runtime matching', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x401234',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'local',
          technicalLabel: 'main_local',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdff4',
          displayValue: '0x1',
          source: 'auto'
        },
        {
          key: 'buf-runtime',
          technicalLabel: 'main_buf',
          semanticRole: 'buffer',
          size: 40,
          offsetFromBp: -48,
          offsetFromBpLabel: 'RBP -0x30',
          addressLabel: '0x7fffffffdfc8',
          displayValue: '"AAAA"',
          ascii: 'AAAA',
          bytesHex: '41 41 41 41',
          recentWrite: true,
          source: 'auto'
        },
        {
          key: 'argc-runtime',
          technicalLabel: 'argc',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: -52,
          offsetFromBpLabel: 'RBP -0x34',
          addressLabel: '0x7fffffffdfc4',
          displayValue: '0x2',
          source: 'auto'
        },
        {
          key: 'argv-runtime',
          technicalLabel: 'arg_rsi',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: -64,
          offsetFromBpLabel: 'RBP -0x40',
          addressLabel: '0x7fffffffdfb8',
          displayValue: '0x7fffffffe120',
          rawValue: '0x7fffffffe120',
          pointerKind: 'stack',
          source: 'auto'
        }
      ],
      snapshots: [{ step: 1, func: 'main' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/test2.elf'
      },
      currentStep: 1,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 72,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdfb0'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      },
      mcp: {
        model: {
          name: 'main',
          locals: [
            { offset: -4, name: 'main_local', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -48, name: 'main_buf', role: 'buffer', cType: 'char[32]', size: 32, source: 'mcp', confidence: 0.92 },
            { offset: -52, name: 'argc', role: 'argument', cType: 'int', size: 4, source: 'mcp', confidence: 0.91 },
            { offset: -64, name: 'argv', role: 'argument', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.91 },
            { offset: -96, name: 'var_60', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.4 },
            { offset: -128, name: 'stack_80h', role: 'local', cType: 'char[16]', size: 16, source: 'mcp', confidence: 0.4 }
          ]
        }
      }
    });

    expect(workspace.frameModel.entries.map((entry) => `${entry.name}:${entry.offsetLabel}:${entry.size}`)).to.deep.equal([
      'return address:rbp+0x8:8',
      'saved rbp:rbp+0x0:8',
      'main_local:rbp-0x4:4',
      'main_buf:rbp-0x30:40',
      'argc:rbp-0x34:4',
      'argv:rbp-0x40:8'
    ]);
    expect(workspace.frameModel.entries.some((entry) => entry.offset === -96 || entry.offset === -128)).to.equal(false);
    expect(workspace.frameModel.entries.some((entry) => entry.isSynthetic)).to.equal(false);
  });

  it('recovers a concrete local buffer extent from memset snapshots and suppresses inner fragments', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x401234',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'local',
          technicalLabel: 'main_local',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdff4',
          displayValue: '0x1',
          source: 'auto'
        },
        {
          key: 'buf-frag-head',
          technicalLabel: 'stack_30h',
          semanticRole: 'unknown',
          size: 16,
          offsetFromBp: -48,
          offsetFromBpLabel: 'RBP -0x30',
          addressLabel: '0x7fffffffdfc8',
          displayValue: '"MMMM"',
          ascii: 'MMMM',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'buf-frag-tail',
          technicalLabel: 'stack_20h',
          semanticRole: 'unknown',
          size: 16,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffdfd8',
          displayValue: '"MMMM"',
          ascii: 'MMMM',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'argc-runtime',
          technicalLabel: 'argc',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: -52,
          offsetFromBpLabel: 'RBP -0x34',
          addressLabel: '0x7fffffffdfc4',
          displayValue: '0x2',
          source: 'auto'
        },
        {
          key: 'argv-runtime',
          technicalLabel: 'arg_rsi',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: -64,
          offsetFromBpLabel: 'RBP -0x40',
          addressLabel: '0x7fffffffdfb8',
          displayValue: '0x7fffffffe120',
          rawValue: '0x7fffffffe120',
          pointerKind: 'stack',
          source: 'auto'
        }
      ],
      snapshots: [
        {
          step: 1,
          func: 'main',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdff8',
                rdi: '0x7fffffffdfc8',
                rdx: '0x28'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdfc8', size: 40 }
            ]
          }
        },
        { step: 2, func: 'main' }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/test2.elf'
      },
      currentStep: 2,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 72,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdfb0'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      },
      mcp: {
        model: {
          name: 'main',
          locals: [
            { offset: -4, name: 'main_local', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -48, name: 'main_buf', role: 'buffer', cType: 'char[32]', size: 32, source: 'mcp', confidence: 0.92 },
            { offset: -52, name: 'argc', role: 'argument', cType: 'int', size: 4, source: 'mcp', confidence: 0.91 },
            { offset: -64, name: 'argv', role: 'argument', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.91 }
          ]
        }
      }
    });

    expect(workspace.frameModel.entries.map((entry) => `${entry.name}:${entry.offsetLabel}:${entry.size}`)).to.deep.equal([
      'return address:rbp+0x8:8',
      'saved rbp:rbp+0x0:8',
      'main_local:rbp-0x4:4',
      'main_buf:rbp-0x30:40',
      'argc:rbp-0x34:4',
      'argv:rbp-0x40:8'
    ]);
    expect(workspace.frameModel.entries.some((entry) => entry.offset > -48 && entry.offset < -8)).to.equal(false);
    expect(workspace.frameModel.entries.some((entry) => entry.name === 'unknown_0')).to.equal(false);
  });

  it('creates synthetic seeds only for real structural holes after compaction', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffdef0',
          displayValue: '0x401999',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdee8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'buf-a',
          technicalLabel: 'outer_buf',
          semanticRole: 'buffer',
          size: 16,
          offsetFromBp: -80,
          offsetFromBpLabel: 'RBP -0x50',
          addressLabel: '0x7fffffffde98',
          displayValue: '"A"',
          ascii: 'A',
          recentWrite: true,
          source: 'static'
        },
        {
          key: 'buf-b',
          technicalLabel: 'outer_buf',
          semanticRole: 'buffer',
          size: 48,
          offsetFromBp: -64,
          offsetFromBpLabel: 'RBP -0x40',
          addressLabel: '0x7fffffffdea8',
          displayValue: '"AAAA"',
          ascii: 'AAAA',
          recentWrite: true,
          source: 'auto'
        },
        {
          key: 'huge-unknown',
          technicalLabel: 'stack_90h',
          semanticRole: 'unknown',
          size: 96,
          offsetFromBp: -96,
          offsetFromBpLabel: 'RBP -0x60',
          addressLabel: '0x7fffffffde88',
          displayValue: '"..."',
          source: 'heuristic'
        }
      ],
      snapshots: [{ step: 1, func: 'outer_function' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/test2.elf'
      },
      currentStep: 1,
      selectedFunction: 'outer_function',
      snapshot: { func: 'outer_function' },
      analysis: {
        frame: {
          frameSize: 96,
          basePointer: '0x7fffffffdee8',
          stackPointer: '0x7fffffffde80'
        },
        control: {
          savedBpAddr: '0x7fffffffdee8',
          retAddrAddr: '0x7fffffffdef0'
        }
      },
      mcp: {
        model: {
          name: 'outer_function',
          locals: [
            { offset: -80, name: 'outer_buf', role: 'buffer', cType: 'char[64]', size: 16, source: 'mcp', confidence: 0.8 },
            { offset: -64, name: 'outer_buf', role: 'buffer', cType: 'char[64]', size: 48, source: 'mcp', confidence: 0.9 }
          ]
        }
      }
    });

    expect(workspace.frameModel.entries.map((entry) => `${entry.name}:${entry.size}`)).to.deep.equal([
      'return address:8',
      'saved rbp:8',
      'outer_buf:64'
    ]);
    expect(workspace.frameModel.entries.some((entry) => entry.isSynthetic)).to.equal(false);
    expect(workspace.frameModel.debug.items.some((item) => item.source === 'synthetic')).to.equal(false);
  });

  it('recovers separate concrete buffers in inner_function from call extents without synthetic unknown noise', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdde8',
          displayValue: '0x7fffffffde88',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffddf0',
          displayValue: '0x401493',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'small-frag',
          technicalLabel: 'stack_20h',
          semanticRole: 'unknown',
          size: 16,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffddc8',
          displayValue: '"AAAA"',
          ascii: 'AAAA',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'large-frag-a',
          technicalLabel: 'stack_80h',
          semanticRole: 'unknown',
          size: 48,
          offsetFromBp: -128,
          offsetFromBpLabel: 'RBP -0x80',
          addressLabel: '0x7fffffffdd68',
          displayValue: '"BBBB"',
          ascii: 'BBBB',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'large-frag-b',
          technicalLabel: 'stack_60h',
          semanticRole: 'unknown',
          size: 32,
          offsetFromBp: -96,
          offsetFromBpLabel: 'RBP -0x60',
          addressLabel: '0x7fffffffdd88',
          displayValue: '"BBBB"',
          ascii: 'BBBB',
          recentWrite: true,
          source: 'heuristic'
        }
      ],
      snapshots: [
        {
          step: 116,
          func: 'inner_function',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdde8',
                rdi: '0x7fffffffddc8',
                rdx: '0x20'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffddc8', size: 32 }
            ]
          }
        },
        {
          step: 121,
          func: 'inner_function',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdde8',
                rdi: '0x7fffffffdd68',
                rdx: '0x60'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdd68', size: 96 }
            ]
          }
        },
        {
          step: 129,
          func: 'inner_function',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdde8',
                rdi: '0x7fffffffdd68'
              }
            }
          },
          effects: {
            external_symbol: 'strcpy'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdd68', size: 65 }
            ]
          }
        }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/test2.elf'
      },
      currentStep: 129,
      selectedFunction: 'inner_function',
      snapshot: { func: 'inner_function' },
      analysis: {
        frame: {
          frameSize: 192,
          basePointer: '0x7fffffffdde8',
          stackPointer: '0x7fffffffdd38'
        },
        control: {
          savedBpAddr: '0x7fffffffdde8',
          retAddrAddr: '0x7fffffffddf0'
        }
      },
      mcp: {
        model: {
          name: 'inner_function',
          locals: [
            { offset: -32, name: 'small_buf', role: 'buffer', cType: 'char[16]', size: 16, source: 'mcp', confidence: 0.9 },
            { offset: -128, name: 'large_buf', role: 'buffer', cType: 'char[48]', size: 48, source: 'mcp', confidence: 0.9 }
          ]
        }
      }
    });

    expect(workspace.frameModel.entries.map((entry) => `${entry.name}:${entry.offsetLabel}:${entry.size}`)).to.deep.equal([
      'return address:rbp+0x8:8',
      'saved rbp:rbp+0x0:8',
      'small_buf:rbp-0x20:32',
      'large_buf:rbp-0x80:96'
    ]);
    expect(workspace.frameModel.entries.filter((entry) => entry.offset === -32 || entry.offset === -24)).to.have.length(1);
    expect(workspace.frameModel.entries.some((entry) => entry.isSynthetic)).to.equal(false);
    expect(workspace.frameModel.entries.some((entry) => entry.name.startsWith('unknown_'))).to.equal(false);
    assertControlSlotsProtected(workspace);
    assertNoDuplicateOverlaps(workspace);
  });

  it('reclassifies strong negative x64 argument spills as arguments without reintroducing ghost positive args', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdee8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffdef0',
          displayValue: '0x401507',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'argv-spill',
          technicalLabel: 'var_b0',
          semanticRole: 'local',
          size: 8,
          offsetFromBp: -176,
          offsetFromBpLabel: 'RBP -0xb0',
          addressLabel: '0x7fffffffde38',
          displayValue: '0x7fffffffded0',
          rawValue: '0x7fffffffded0',
          pointerKind: 'stack',
          source: 'auto'
        },
        {
          key: 'argc-spill',
          technicalLabel: 'var_a4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -164,
          offsetFromBpLabel: 'RBP -0xa4',
          addressLabel: '0x7fffffffde44',
          displayValue: '0x2',
          rawValue: '0x2',
          source: 'auto'
        }
      ],
      snapshots: [{ step: 1, func: 'outer_function' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/test2.elf'
      },
      currentStep: 1,
      selectedFunction: 'outer_function',
      snapshot: {
        func: 'outer_function',
        cpu: {
          before: {
            registers: {
              rdi: '0x2',
              rsi: '0x7fffffffded0'
            }
          }
        }
      },
      analysis: {
        frame: {
          frameSize: 192,
          basePointer: '0x7fffffffdee8',
          stackPointer: '0x7fffffffde20',
          registerArguments: [
            { location: 'rdi', name: 'arg_rdi', offset: null, size: 8, source: 'abi' },
            { location: 'rsi', name: 'arg_rsi', offset: null, size: 8, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffdee8',
          retAddrAddr: '0x7fffffffdef0'
        }
      },
      mcp: {
        model: {
          name: 'outer_function',
          locals: [
            { offset: -32, name: 'zone1', role: 'buffer', cType: 'char[24]', size: 24, source: 'mcp', confidence: 0.95 },
            { offset: -96, name: 'zone2', role: 'buffer', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.95 }
          ]
        }
      }
    });

    const argcSpill = workspace.frameModel.entries.find((entry) => entry.offset === -164);
    const argvSpill = workspace.frameModel.entries.find((entry) => entry.offset === -176);
    expect(argcSpill.kind).to.equal('argument');
    expect(argvSpill.kind).to.equal('argument');
    expect(argcSpill.name).to.match(/^arg_/);
    expect(argvSpill.name).to.match(/^arg_/);
    expect(workspace.frameModel.entries.some((entry) => entry.offset > 0 && /^arg_[0-9a-z]+h?$/i.test(entry.name))).to.equal(false);
  });

  it('keeps return_address protected from approximate overlap and only marks corruption on exact slot evidence', () => {
    // CORROMPU is a backend-only verdict: raw slot signals (pointerKind,
    // changed, recentWrite, even the backend's own per-slot "corrupted"
    // flag) are informative at most. Only a matching backend diagnostic
    // (return_address_corrupted here) may promote the badge to CORROMPU --
    // see stackWorkspaceCorruption.js::annotateEntriesWithDiagnostics.
    const exactWorkspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x4141414141414141',
          rawValue: '0x4141414141414141',
          pointerKind: 'stack',
          source: 'control',
          flags: ['corrupted'],
          changed: true,
          recentWrite: true
        },
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        }
      ],
      snapshots: [{ step: 1, func: 'inner_function' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf'
      },
      currentStep: 1,
      selectedFunction: 'inner_function',
      snapshot: { func: 'inner_function' },
      analysis: {
        frame: {
          frameSize: 32,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdfd0'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      },
      diagnostics: [
        {
          kind: 'return_address_corrupted',
          severity: 'error',
          step: 1,
          slot: { kind: 'return_address', address: '0x7fffffffe000' }
        }
      ]
    });

    const approxWorkspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'wide-overlap',
          technicalLabel: 'stack_10h',
          semanticRole: 'unknown',
          size: 16,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x4141414141414141',
          source: 'heuristic',
          flags: ['corrupted'],
          changed: true,
          recentWrite: true
        },
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x401234',
          pointerKind: 'code',
          source: 'control'
        }
      ],
      snapshots: [{ step: 1, func: 'inner_function' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf'
      },
      currentStep: 1,
      selectedFunction: 'inner_function',
      snapshot: { func: 'inner_function' },
      analysis: {
        frame: {
          frameSize: 32,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdfd0'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      }
    });

    expect(exactWorkspace.frameModel.entries.find((entry) => entry.kind === 'return_address').badges).to.include('CORROMPU');
    expect(approxWorkspace.frameModel.entries.find((entry) => entry.kind === 'return_address').badges).to.deep.equal(['RET']);
    expect(approxWorkspace.frameModel.entries).to.have.length(2);
    assertControlSlotsProtected(approxWorkspace);
  });

  it('keeps controlled ret2win diagnostics separate from fatal A*80 crashes', () => {
    const baseFrame = {
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x401156',
          pointerKind: 'code',
          source: 'control',
          changed: true,
          recentWrite: true
        }
      ],
      snapshots: [{ step: 80, func: 'main' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/ret2win.elf'
      },
      currentStep: 80,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 96,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdf98'
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      }
    };

    const ret2win = buildStackWorkspaceModel({
      ...baseFrame,
      diagnostics: [{
        kind: 'ret2win_success',
        severity: 'info',
        confidence: 0.99,
        message: 'Controlled return to win().',
        slot: { kind: 'return_address', address: '0x7fffffffe000' }
      }]
    });
    const fatal = buildStackWorkspaceModel({
      ...baseFrame,
      diagnostics: [{
        kind: 'fatal_crash',
        severity: 'error',
        confidence: 0.99,
        message: 'A*80 reached an unmapped return target.',
        bytes: '41 '.repeat(8).trim(),
        slot: { kind: 'return_address', address: '0x7fffffffe000' }
      }]
    });

    const retEntry = ret2win.frameModel.entries.find((entry) => entry.kind === 'return_address');
    const fatalEntry = fatal.frameModel.entries.find((entry) => entry.kind === 'return_address');
    expect(retEntry.diagnostic.kind).to.equal('ret2win_success');
    expect(retEntry.diagnosticCorrupted).to.equal(false);
    expect(retEntry.diagnostic.kind).to.not.equal('fatal_crash');
    expect(fatalEntry.diagnostic.kind).to.equal('fatal_crash');
    assertControlSlotsProtected(ret2win);
    assertControlSlotsProtected(fatal);
  });

  it('keeps an argv spill as a pointer slot and separates pointed data in the detail drawer', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdff8',
          displayValue: '0x7fffffffef10',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x401234',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'argv-spill',
          technicalLabel: 'arg_rsi',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: -96,
          offsetFromBpLabel: 'RBP -0x60',
          addressLabel: '0x7fffffffdf98',
          displayValue: '0x7fffffffded0',
          rawValue: '0x7fffffffded0',
          pointerKind: 'stack',
          source: 'auto'
        },
        {
          key: 'buffer-target',
          technicalLabel: 'buffer',
          semanticRole: 'buffer',
          size: 32,
          offsetFromBp: -296,
          offsetFromBpLabel: 'RBP -0x128',
          addressLabel: '0x7fffffffded0',
          displayValue: '"AAAA"',
          ascii: 'AAAA',
          bytesHex: '41 41 41 41',
          source: 'mcp'
        }
      ],
      snapshots: [{ step: 1, func: 'inner_function' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/stack3str2.elf'
      },
      currentStep: 1,
      selectedFunction: 'inner_function',
      selectedSlotKey: 'inner_function:rbp:argument:-96:8:frame',
      snapshot: { func: 'inner_function' },
      analysis: {
        frame: {
          frameSize: 128,
          basePointer: '0x7fffffffdff8',
          stackPointer: '0x7fffffffdf80',
          registerArguments: [
            { location: 'rsi', name: 'argv', offset: null, size: 8, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffdff8',
          retAddrAddr: '0x7fffffffe000'
        }
      }
    });

    const spill = workspace.frameModel.entries.find((entry) => entry.offsetLabel === 'rbp-0x60');
    expect(spill.kind).to.equal('argument');
    expect(spill.name).to.equal('arg_0');
    const labels = workspace.detailModel.rows.map((row) => row.label);
    expect(labels).to.include('Valeur du slot');
    expect(labels).to.include('Pointeur');
    expect(labels).to.include('Memoire pointee');
    expect(labels).to.include('Texte pointe');
    expect(labels).to.not.include('Texte du slot');
  });

  it('does not present a raw scalar payload suffix as a pointer and keeps the byte-oriented hex view', () => {
    const baseArgs = {
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_ebp',
          semanticRole: 'saved_bp',
          size: 4,
          offsetFromBp: 0,
          offsetFromBpLabel: 'EBP +0x0',
          addressLabel: '0xbff1ff50',
          displayValue: '0xbff1ff68',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 4,
          offsetFromBp: 4,
          offsetFromBpLabel: 'EBP +0x4',
          addressLabel: '0xbff1ff54',
          displayValue: '0x80491f0',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'payload-tail',
          technicalLabel: 'modified',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'EBP -0x4',
          addressLabel: '0xbff1ff4c',
          displayValue: '0xefbeadde',
          rawValue: '0xefbeadde',
          bytesHex: 'de ad be ef',
          source: 'auto'
        }
      ],
      snapshots: [{ step: 1, func: 'main' }],
      meta: {
        arch_bits: 32,
        binary: 'examples/rootme1.elf'
      },
      currentStep: 1,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 64,
          basePointer: '0xbff1ff50',
          stackPointer: '0xbff1ff1c'
        },
        control: {
          savedBpAddr: '0xbff1ff50',
          retAddrAddr: '0xbff1ff54'
        }
      }
    };

    const preview = buildStackWorkspaceModel(baseArgs);
    const selected = preview.frameModel.entries.find((entry) => entry.offsetLabel === 'ebp-0x4');
    const workspace = buildStackWorkspaceModel({
      ...baseArgs,
      selectedSlotKey: selected.key
    });

    const rows = workspace.detailModel.rows;
    const labels = rows.map((row) => row.label);
    expect(labels).to.include('Valeur du slot');
    expect(labels).to.include('Hex');
    expect(labels).to.not.include('Pointeur');
    expect(labels).to.not.include('Memoire pointee');
    expect(rows.find((row) => row.label === 'Hex').value).to.equal('de ad be ef');
  });

  it('keeps main compact at a call site even when visible memory contains sink frame offsets', () => {
    const workspace = buildMainCallSiteWorkspace();

    expect(summarizeEntries(workspace)).to.deep.equal([
      { name: 'return address', kind: 'return_address', offset: 8, size: 8 },
      { name: 'saved rbp', kind: 'saved_bp', offset: 0, size: 8 },
      { name: 'main_local', kind: 'local', offset: -4, size: 4 },
      { name: 'main_buf', kind: 'buffer', offset: -32, size: 24 },
      { name: 'arg_0', kind: 'argument', offset: -36, size: 4 },
      { name: 'arg_1', kind: 'argument', offset: -48, size: 8 }
    ]);
    assertControlSlotsProtected(workspace);
    assertNoDuplicateOverlaps(workspace);
    assertNoUnexpectedSynthetic(workspace);
    expect(workspace.frameModel.entries.some((entry) => entry.offset <= -72)).to.equal(false);
    expect(workspace.frameModel.entries.some((entry) => entry.name.startsWith('unknown_'))).to.equal(false);
  });

  it('does not let sink runtime writes create or extend objects inside main frame recovery', () => {
    const workspace = buildMainCallSiteWorkspace();
    const buffer = workspace.frameModel.entries.find((entry) => entry.name === 'main_buf');

    expect(buffer).to.exist;
    expect(buffer.size).to.equal(24);
    expect(buffer.offset).to.equal(-32);
    expect(workspace.frameModel.entries.find((entry) => entry.offset === -72)).to.equal(undefined);
    expect(workspace.frameModel.entries.find((entry) => entry.offset === -80)).to.equal(undefined);
    expect(workspace.frameModel.entries.find((entry) => entry.offset === -84)).to.equal(undefined);
  });

  it('exposes logical argc and argv above return address while keeping negative spills as storage slots in main', () => {
    const workspace = buildMainCallSiteWorkspace();

    expect(workspace.frameModel.logicalArguments.map((entry) => ({
      name: entry.name,
      offset: entry.offsetLabel,
      storage: entry.storageOffsetLabel
    }))).to.deep.equal([
      { name: 'argv', offset: 'rbp+0x18', storage: 'rbp-0x30' },
      { name: 'argc', offset: 'rbp+0x10', storage: 'rbp-0x24' }
    ]);
    expect(workspace.frameModel.entries.find((entry) => entry.offset === -48).name).to.equal('arg_1');
    expect(workspace.frameModel.entries.find((entry) => entry.offset === -36).name).to.equal('arg_0');
    expect(workspace.frameModel.entries.some((entry) => entry.offset === -40 && entry.kind === 'buffer')).to.equal(false);
  });

  it('reconstructs sink independently without losing its own local frame objects', () => {
    const workspace = buildSinkWorkspace();

    expect(summarizeEntries(workspace)).to.deep.equal([
      { name: 'return address', kind: 'return_address', offset: 8, size: 8 },
      { name: 'saved rbp', kind: 'saved_bp', offset: 0, size: 8 },
      { name: 'x', kind: 'local', offset: -4, size: 4 },
      { name: 'y', kind: 'local', offset: -8, size: 4 },
      { name: 'small', kind: 'buffer', offset: -32, size: 16 },
      { name: 'big', kind: 'buffer', offset: -80, size: 48 },
      { name: 'guard', kind: 'local', offset: -84, size: 4 },
      { name: 'arg_0', kind: 'argument', offset: -104, size: 8 },
      { name: 'arg_1', kind: 'argument', offset: -108, size: 4 }
    ]);
    assertControlSlotsProtected(workspace);
    assertNoDuplicateOverlaps(workspace);
    assertNoUnexpectedSynthetic(workspace);
  });

  it('keeps sink geometry stable across noisy steps and does not let runtime slot noise resize small and big buffers', () => {
    const buildNoisySinkWorkspace = ({ currentStep, slots }) => buildStackWorkspaceModel({
      slots,
      snapshots: [
        {
          step: 70,
          func: 'sink',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdf90',
                rdi: '0x7fffffffdf70',
                rdx: '0x10'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdf70', size: 16 }
            ]
          }
        },
        {
          step: 71,
          func: 'sink',
          cpu: {
            before: {
              registers: {
                rbp: '0x7fffffffdf90',
                rdi: '0x7fffffffdf40',
                rdx: '0x30'
              }
            }
          },
          effects: {
            external_symbol: 'memset'
          },
          memory: {
            writes: [
              { addr: '0x7fffffffdf40', size: 48 }
            ]
          }
        }
      ],
      meta: {
        arch_bits: 64,
        binary: 'examples/test3.elf'
      },
      currentStep,
      selectedFunction: 'sink',
      snapshot: {
        func: 'sink',
        cpu: {
          before: {
            registers: {
              rdi: '0x7fffffffdfb0',
              rsi: '0x7'
            }
          }
        }
      },
      analysis: {
        frame: {
          frameSize: 112,
          basePointer: '0x7fffffffdf90',
          stackPointer: '0x7fffffffdf20',
          registerArguments: [
            { location: 'rdi', name: 'input', offset: null, size: 8, source: 'abi' },
            { location: 'rsi', name: 'n', offset: null, size: 4, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffdf90',
          retAddrAddr: '0x7fffffffdf98'
        }
      },
      mcp: {
        model: {
          name: 'sink',
          locals: [
            { offset: -104, name: 'input', role: 'argument', cType: 'char *', size: 8, source: 'mcp', confidence: 0.95 },
            { offset: -108, name: 'n', role: 'argument', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -80, name: 'big', role: 'buffer', cType: 'char[48]', size: 48, source: 'mcp', confidence: 0.95 },
            { offset: -32, name: 'small', role: 'buffer', cType: 'char[16]', size: 16, source: 'mcp', confidence: 0.95 },
            { offset: -84, name: 'guard', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -8, name: 'y', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 },
            { offset: -4, name: 'x', role: 'local', cType: 'int', size: 4, source: 'mcp', confidence: 0.95 }
          ]
        }
      }
    });

    const early = buildNoisySinkWorkspace({
      currentStep: 70,
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdf90',
          displayValue: '0x7fffffffe000',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffdf98',
          displayValue: '0x401251',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'x',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdf8c',
          displayValue: '0x8',
          source: 'auto'
        },
        {
          key: 'y',
          technicalLabel: 'var_8',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -8,
          offsetFromBpLabel: 'RBP -0x8',
          addressLabel: '0x7fffffffdf88',
          displayValue: '0x9',
          source: 'auto'
        },
        {
          key: 'small-noisy',
          technicalLabel: 'stack_20h',
          semanticRole: 'unknown',
          size: 8,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffdf70',
          displayValue: '"SSSS"',
          ascii: 'SSSS',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'big-noisy',
          technicalLabel: 'stack_50h',
          semanticRole: 'unknown',
          size: 80,
          offsetFromBp: -80,
          offsetFromBpLabel: 'RBP -0x50',
          addressLabel: '0x7fffffffdf40',
          displayValue: '"BBBB"',
          ascii: 'BBBB',
          recentWrite: true,
          source: 'heuristic'
        }
      ]
    });

    const late = buildNoisySinkWorkspace({
      currentStep: 71,
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffdf90',
          displayValue: '0x7fffffffe000',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffdf98',
          displayValue: '0x401251',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'x',
          technicalLabel: 'var_4',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'RBP -0x4',
          addressLabel: '0x7fffffffdf8c',
          displayValue: '0x8',
          source: 'auto'
        },
        {
          key: 'y',
          technicalLabel: 'var_8',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -8,
          offsetFromBpLabel: 'RBP -0x8',
          addressLabel: '0x7fffffffdf88',
          displayValue: '0x9',
          source: 'auto'
        },
        {
          key: 'small-noisy',
          technicalLabel: 'stack_20h',
          semanticRole: 'unknown',
          size: 16,
          offsetFromBp: -32,
          offsetFromBpLabel: 'RBP -0x20',
          addressLabel: '0x7fffffffdf70',
          displayValue: '"SSSS"',
          ascii: 'SSSS',
          recentWrite: true,
          source: 'heuristic'
        },
        {
          key: 'big-noisy',
          technicalLabel: 'stack_50h',
          semanticRole: 'unknown',
          size: 56,
          offsetFromBp: -80,
          offsetFromBpLabel: 'RBP -0x50',
          addressLabel: '0x7fffffffdf40',
          displayValue: '"BBBB"',
          ascii: 'BBBB',
          recentWrite: true,
          source: 'heuristic'
        }
      ]
    });

    expect(summarizeEntries(early)).to.deep.equal([
      { name: 'return address', kind: 'return_address', offset: 8, size: 8 },
      { name: 'saved rbp', kind: 'saved_bp', offset: 0, size: 8 },
      { name: 'x', kind: 'local', offset: -4, size: 4 },
      { name: 'y', kind: 'local', offset: -8, size: 4 },
      { name: 'small', kind: 'buffer', offset: -32, size: 16 },
      { name: 'big', kind: 'buffer', offset: -80, size: 48 },
      { name: 'guard', kind: 'local', offset: -84, size: 4 },
      { name: 'arg_0', kind: 'argument', offset: -104, size: 8 },
      { name: 'arg_1', kind: 'argument', offset: -108, size: 4 }
    ]);
    expect(summarizeEntries(late)).to.deep.equal(summarizeEntries(early));
    expect(early.frameModel.entries.some((entry) => entry.isSynthetic && entry.kind === 'buffer')).to.equal(false);
    expect(late.frameModel.entries.some((entry) => entry.isSynthetic && entry.kind === 'buffer')).to.equal(false);
  });

  it('keeps frame signatures and rebuilt caller frames scoped across main -> sink -> main', () => {
    const firstMain = buildMainCallSiteWorkspace({ currentStep: 40 });
    const sink = buildSinkWorkspace({ currentStep: 42 });
    const secondMain = buildMainCallSiteWorkspace({ currentStep: 40 });

    expect(firstMain.frameModel.frameSignature).to.equal(secondMain.frameModel.frameSignature);
    expect(firstMain.frameModel.frameSignature).to.not.equal(sink.frameModel.frameSignature);
    expect(summarizeEntries(firstMain)).to.deep.equal(summarizeEntries(secondMain));
    expect(secondMain.frameModel.entries.some((entry) => entry.offset <= -72)).to.equal(false);
  });

  it('promotes source-enriched logical arguments above return address while keeping negative spills as storage', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'saved',
          technicalLabel: 'saved_rbp',
          semanticRole: 'saved_bp',
          size: 8,
          offsetFromBp: 0,
          offsetFromBpLabel: 'RBP +0x0',
          addressLabel: '0x7fffffffe000',
          displayValue: '0x7fffffffe020',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 8,
          offsetFromBp: 8,
          offsetFromBpLabel: 'RBP +0x8',
          addressLabel: '0x7fffffffe008',
          displayValue: '0x401262',
          pointerKind: 'code',
          source: 'control'
        },
        {
          key: 'spill-input',
          technicalLabel: 'var_30',
          semanticRole: 'argument',
          size: 8,
          offsetFromBp: -48,
          offsetFromBpLabel: 'RBP -0x30',
          addressLabel: '0x7fffffffdfd0',
          displayValue: '0x7fffffffdf60',
          rawValue: '0x7fffffffdf60',
          pointerKind: 'stack',
          source: 'auto'
        },
        {
          key: 'spill-n',
          technicalLabel: 'var_24',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: -36,
          offsetFromBpLabel: 'RBP -0x24',
          addressLabel: '0x7fffffffdfdc',
          displayValue: '0x7',
          rawValue: '0x7',
          source: 'auto'
        }
      ],
      snapshots: [{ step: 12, func: 'sink' }],
      meta: {
        arch_bits: 64,
        binary: 'examples/test3.elf'
      },
      currentStep: 12,
      selectedFunction: 'sink',
      snapshot: { func: 'sink' },
      analysis: {
        frame: {
          frameSize: 64,
          basePointer: '0x7fffffffe000',
          stackPointer: '0x7fffffffdf90',
          registerArguments: [
            { location: 'rdi', name: 'arg_0', offset: null, size: 8, source: 'abi' },
            { location: 'rsi', name: 'arg_1', offset: null, size: 4, source: 'abi' }
          ]
        },
        control: {
          savedBpAddr: '0x7fffffffe000',
          retAddrAddr: '0x7fffffffe008'
        }
      },
      mcp: {
        model: {
          name: 'sink',
          locals: [],
          parameters: [
            { name: 'input', cType: 'char *', byteSize: 8, kind: 'argument' },
            { name: 'n', cType: 'int', byteSize: 4, kind: 'argument' }
          ]
        }
      }
    });

    expect(workspace.frameModel.logicalArguments.map((entry) => ({
      name: entry.name,
      offsetLabel: entry.offsetLabel,
      storageOffsetLabel: entry.storageOffsetLabel,
      registerLocation: entry.registerLocation,
      cType: entry.cType,
      source: entry.source
    }))).to.deep.equal([
      {
        name: 'n',
        offsetLabel: 'rbp+0x18',
        storageOffsetLabel: 'rbp-0x24',
        registerLocation: 'rsi',
        cType: 'int',
        source: 'source_c'
      },
      {
        name: 'input',
        offsetLabel: 'rbp+0x10',
        storageOffsetLabel: 'rbp-0x30',
        registerLocation: 'rdi',
        cType: 'char *',
        source: 'source_c'
      }
    ]);
  });

  it('exposes additive debug metadata for the canonical builder without changing the main model', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'argc-raw',
          technicalLabel: 'arg_8',
          semanticRole: 'argument',
          size: 4,
          offsetFromBp: 8,
          offsetFromBpLabel: 'EBP +0x8',
          addressLabel: '0xffffd038',
          displayValue: '0x2',
          source: 'static'
        },
        {
          key: 'saved-raw',
          technicalLabel: 'saved_ebp',
          semanticRole: 'saved_bp',
          size: 4,
          offsetFromBp: 0,
          offsetFromBpLabel: 'EBP +0x0',
          addressLabel: '0xffffd030',
          displayValue: '0xffffd090',
          source: 'control'
        }
      ],
      snapshots: [{ step: 1, func: 'main' }],
      meta: {
        arch_bits: 32,
        binary: 'examples/stack3.elf'
      },
      currentStep: 1,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 16,
          basePointer: '0xffffd030',
          stackPointer: '0xffffcfd0'
        },
        control: {
          savedBpAddr: '0xffffd030',
          retAddrAddr: '0xffffd034'
        }
      }
    });

    expect(workspace.frameModel.entries[0].debug.identityKey).to.equal(workspace.frameModel.entries[0].key);
    expect(workspace.frameModel.entries[0].debug.primarySource).to.equal('static');
    expect(workspace.frameModel.entries[0].debug.mergedObservationCount).to.equal(1);
    expect(workspace.frameModel.debug.items[0].name).to.equal('argc');
    expect(workspace.frameModel.debug.seeds.some((seed) => seed.stage === 'control')).to.equal(true);
  });

  it('keeps source-backed simple frames focused on C variables and control slots', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [
        {
          key: 'call-arg',
          technicalLabel: 'stack_44h',
          semanticRole: 'unknown',
          size: 4,
          offsetFromBp: -68,
          offsetFromBpLabel: 'EBP -0x44',
          addressLabel: '0xbff1fe74',
          displayValue: '0x2d',
          source: 'heuristic'
        },
        {
          key: 'buf-start',
          technicalLabel: 'var_34',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -52,
          offsetFromBpLabel: 'EBP -0x34',
          addressLabel: '0xbff1fe84',
          displayValue: '"AAAA"',
          source: 'auto'
        },
        {
          key: 'buf-tail',
          technicalLabel: 'stack_30h',
          semanticRole: 'unknown',
          size: 36,
          offsetFromBp: -48,
          offsetFromBpLabel: 'EBP -0x30',
          addressLabel: '0xbff1fe88',
          displayValue: '"AAAAAAAA"',
          source: 'heuristic'
        },
        {
          key: 'check',
          technicalLabel: 'var_c',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -12,
          offsetFromBpLabel: 'EBP -0xc',
          addressLabel: '0xbff1feac',
          displayValue: '0xdeadbeef',
          source: 'auto'
        },
        {
          key: 'saved-ecx',
          technicalLabel: 'var_8',
          semanticRole: 'local',
          size: 4,
          offsetFromBp: -8,
          offsetFromBpLabel: 'EBP -0x8',
          addressLabel: '0xbff1feb0',
          displayValue: '0xbff1ff00',
          source: 'auto'
        },
        {
          key: 'saved-ebx',
          technicalLabel: 'stack_4h',
          semanticRole: 'unknown',
          size: 4,
          offsetFromBp: -4,
          offsetFromBpLabel: 'EBP -0x4',
          addressLabel: '0xbff1feb4',
          displayValue: '0x0',
          source: 'heuristic'
        },
        {
          key: 'saved-ebp',
          technicalLabel: 'saved_ebp',
          semanticRole: 'saved_bp',
          size: 4,
          offsetFromBp: 0,
          offsetFromBpLabel: 'EBP +0x0',
          addressLabel: '0xbff1feb8',
          displayValue: '0xbff1fffc',
          source: 'control'
        },
        {
          key: 'ret',
          technicalLabel: 'ret_addr',
          semanticRole: 'return_address',
          size: 4,
          offsetFromBp: 4,
          offsetFromBpLabel: 'EBP +0x4',
          addressLabel: '0xbff1febc',
          displayValue: '0x8049000',
          source: 'control'
        }
      ],
      snapshots: [{ step: 14, func: 'main' }],
      meta: { arch_bits: 32 },
      currentStep: 14,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        frame: {
          frameSize: 80,
          basePointer: '0xbff1feb8',
          stackPointer: '0xbff1fe74'
        },
        control: {
          savedBpAddr: '0xbff1feb8',
          retAddrAddr: '0xbff1febc'
        }
      },
      mcp: {
        model: {
          name: 'main',
          sourceFunction: { name: 'main', returnType: 'int' },
          locals: [
            { name: 'saved ebx', offset: -4, size: 4, role: 'padding', confidence: 0.94 },
            { name: 'saved ecx', offset: -8, size: 4, role: 'padding', confidence: 0.94 },
            { name: 'check', offset: -12, size: 4, role: 'local', cType: 'int', source: 'source_c', confidence: 0.93 },
            { name: 'buf', offset: -52, size: 40, role: 'buffer', cType: 'char[40]', source: 'source_c', confidence: 0.93 }
          ]
        }
      }
    });

    expect(summarizeEntries(workspace)).to.deep.equal([
      { name: 'argv', kind: 'argument', offset: 12, size: 4 },
      { name: 'argc', kind: 'argument', offset: 8, size: 4 },
      { name: 'return address', kind: 'return_address', offset: 4, size: 4 },
      { name: 'saved ebp', kind: 'saved_bp', offset: 0, size: 4 },
      { name: 'check', kind: 'local', offset: -12, size: 4 },
      { name: 'buf', kind: 'buffer', offset: -52, size: 40 }
    ]);
    expect(workspace.frameModel.entries.find((entry) => entry.name === 'buf')).to.include({
      source: 'source_c',
      provenance: 'source_c',
      confidence: 0.93
    });
    expect(workspace.frameModel.entries.find((entry) => entry.name === 'check')).to.include({
      source: 'source_c',
      provenance: 'source_c',
      confidence: 0.93
    });
    assertControlSlotsProtected(workspace);
    assertNoDuplicateOverlaps(workspace);
    assertNoSyntheticInsideAnchoredRanges(workspace);
  });

  describe('function catalog from symbol table (no C source)', () => {
    let buildFunctionList;
    let isInternalSymbol;

    before(async () => {
      const modulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceCore.js');
      ({ buildFunctionList, isInternalSymbol } = await import(pathToFileURL(modulePath).href));
    });

    const makeSymbols = (entries) =>
      entries.map(([name, addr]) => ({ name, addr, type: 'T' }));

    it('shows main and CallMeMaybe from symbols when no C source is provided', () => {
      const symbols = makeSymbols([
        ['_start', '0x401020'],
        ['main', '0x401147'],
        ['CallMeMaybe', '0x401100'],
        ['_init', '0x401000'],
        ['_fini', '0x401200'],
      ]);
      const result = buildFunctionList({
        snapshots: [],
        meta: { functions: symbols },
        selectedFunction: '',
        currentFunction: '',
      });
      const names = result.map((e) => e.displayName);
      expect(names).to.include('main');
      expect(names).to.include('CallMeMaybe');
    });

    it('hides dynamic loader runtime symbols after merging sources', () => {
      const symbols = makeSymbols([
        ['main', '0x401147'],
        ['_dl_relocate_static_pie', '0x401080'],
      ]);
      const result = buildFunctionList({
        snapshots: [
          { step: 1, func: 'main' },
          { step: 2, func: '_dl_relocate_static_pie' },
        ],
        meta: { functions: symbols },
        selectedFunction: '',
        currentFunction: '',
      });
      const names = result.map((e) => e.displayName);
      expect(names).to.include('main');
      expect(names).to.not.include('_dl_relocate_static_pie');
    });

    it('keeps hidden metadata available for debug function lists', () => {
      const result = buildFunctionList({
        snapshots: [{ step: 1, func: '_dl_relocate_static_pie' }],
        meta: { functions: makeSymbols([['_dl_relocate_static_pie', '0x401080']]) },
        selectedFunction: '',
        currentFunction: '',
        includeHidden: true,
      });
      const hidden = result.find((e) => e.hidden);
      expect(hidden).to.include({
        hidden: true,
        hiddenReason: 'internal_runtime_or_linker_symbol'
      });
    });

    it('keeps source C functions visible even when symbol filtering is active', () => {
      const result = buildFunctionList({
        snapshots: [
          { step: 1, func: 'main' },
          { step: 2, func: '_dl_relocate_static_pie' },
        ],
        meta: {
          source_enrichment: {
            enabled: true,
            functions: [
              { name: 'main', normalizedName: 'main', index: 0 },
              { name: 'user_func', normalizedName: 'user_func', index: 1 },
            ]
          },
          functions: makeSymbols([
            ['main', '0x401147'],
            ['user_func', '0x401180'],
            ['_dl_relocate_static_pie', '0x401080'],
          ])
        },
        selectedFunction: '',
        currentFunction: '',
      });
      const names = result.map((e) => e.displayName);
      expect(names).to.deep.equal(['main', 'user_func']);
    });

    it('hides _start, _init, _fini, and __libc_csu_* by default', () => {
      const symbols = makeSymbols([
        ['_start', '0x401020'],
        ['_init', '0x401000'],
        ['_fini', '0x401200'],
        ['__libc_csu_init', '0x401300'],
        ['__libc_csu_fini', '0x401350'],
        ['register_tm_clones', '0x401400'],
        ['deregister_tm_clones', '0x401450'],
        ['frame_dummy', '0x401500'],
        ['__do_global_dtors_aux', '0x401550'],
        ['main', '0x401147'],
      ]);
      const result = buildFunctionList({
        snapshots: [],
        meta: { functions: symbols },
        selectedFunction: '',
        currentFunction: '',
      });
      const names = result.map((e) => e.displayName);
      expect(names).to.deep.equal(['main']);
    });

    it('hides plt and got entries by default', () => {
      const symbols = makeSymbols([
        ['puts@plt', '0x401030'],
        ['printf@plt', '0x401040'],
        ['main', '0x401147'],
        ['win', '0x401136'],
      ]);
      const result = buildFunctionList({
        snapshots: [],
        meta: { functions: symbols },
        selectedFunction: '',
        currentFunction: '',
      });
      const names = result.map((e) => e.displayName);
      expect(names).to.not.include('puts@plt');
      expect(names).to.not.include('printf@plt');
      expect(names).to.include('main');
      expect(names).to.include('win');
    });

    it('merges duplicate entries when same function appears in symbols and snapshots', () => {
      const symbols = makeSymbols([
        ['main', '0x401147'],
        ['CallMeMaybe', '0x401100'],
      ]);
      const result = buildFunctionList({
        snapshots: [
          { step: 1, func: 'main' },
          { step: 2, func: 'main' },
        ],
        meta: { functions: symbols },
        selectedFunction: '',
        currentFunction: '',
      });
      const mainEntries = result.filter((e) => e.displayName === 'main');
      expect(mainEntries).to.have.length(1);
      expect(mainEntries[0].stepCount).to.equal(2);
      expect(mainEntries[0].addressLabel).to.equal('0x401147');
    });

    it('assigns source metadata correctly', () => {
      const symbols = makeSymbols([
        ['main', '0x401147'],
        ['CallMeMaybe', '0x401100'],
      ]);
      const result = buildFunctionList({
        snapshots: [{ step: 1, func: 'main' }],
        meta: { functions: symbols },
        selectedFunction: '',
        currentFunction: '',
      });
      const mainEntry = result.find((e) => e.displayName === 'main');
      const callEntry = result.find((e) => e.displayName === 'CallMeMaybe');
      expect(mainEntry.source).to.equal('runtime');
      expect(callEntry.source).to.equal('symbol');
    });

    it('isInternalSymbol correctly classifies symbols', () => {
      expect(isInternalSymbol('_start')).to.equal(true);
      expect(isInternalSymbol('_init')).to.equal(true);
      expect(isInternalSymbol('_fini')).to.equal(true);
      expect(isInternalSymbol('register_tm_clones')).to.equal(true);
      expect(isInternalSymbol('frame_dummy')).to.equal(true);
      expect(isInternalSymbol('puts@plt')).to.equal(true);
      expect(isInternalSymbol('printf@plt')).to.equal(true);
      expect(isInternalSymbol('__libc_csu_init')).to.equal(true);
      expect(isInternalSymbol('__libc_start_main')).to.equal(true);
      expect(isInternalSymbol('_dl_relocate_static_pie')).to.equal(true);
      expect(isInternalSymbol('main')).to.equal(false);
      expect(isInternalSymbol('CallMeMaybe')).to.equal(false);
      expect(isInternalSymbol('win')).to.equal(false);
      expect(isInternalSymbol('pwn_func')).to.equal(false);
    });
  });
});
