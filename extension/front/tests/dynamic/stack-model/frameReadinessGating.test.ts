const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stack-model frame-readiness gating for model.locals', () => {
  let buildStackWorkspaceModel: Function;
  let buildSemanticStackItems: Function;
  let injectControlSlots: Function;
  let buildSimpleSourceItems: Function;
  let compareStackItemsByAddrDesc: Function;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../dynamic/app/stackWorkspaceCore.js');
    ({ buildStackWorkspaceModel } = await import(pathToFileURL(modulePath).href));
    const formattingPath = path.resolve(__dirname, '../../../dynamic/app/stack/stackFormatting.js');
    ({
      buildSemanticStackItems,
      injectControlSlots,
      buildSimpleSourceItems,
      compareStackItemsByAddrDesc
    } = await import(pathToFileURL(formattingPath).href));
  });

  const model = {
    name: 'main',
    locals: [
      { offset: -0x70, name: 'buffer', role: 'buffer', cType: 'char[64]', size: 64, source: 'mcp', confidence: 0.95 }
    ]
  };

  function buildWorkspace({ slots, frameReady }: { slots: unknown[]; frameReady?: boolean }) {
    const frame: Record<string, unknown> = {
      basePointer: '0x1000',
      stackPointer: '0xf90',
      frameSize: 0x70
    };
    if (typeof frameReady === 'boolean') frame.frameReady = frameReady;
    return buildStackWorkspaceModel({
      slots,
      snapshots: [{ step: 1, func: 'main' }],
      meta: { arch_bits: 64 },
      currentStep: 1,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        function: { name: 'main' },
        frame,
        control: { savedBpAddr: '0x1000', retAddrAddr: '0x1008' }
      },
      mcp: { model }
    });
  }

  it('buffer84 step 1 (push rbp, frame not ready): only saved rbp / return address, no future buffer', () => {
    const workspace = buildWorkspace({ slots: [] });
    const kinds = workspace.frameModel.entries.map((entry: any) => entry.kind);
    expect(kinds).to.include('saved_bp');
    expect(kinds).to.include('return_address');
    expect(kinds).to.not.include('buffer');
    expect(workspace.frameModel.entries.some((entry: any) => entry.offset === -0x70)).to.equal(false);
  });

  it('after sub rsp,0x70 (frame ready, proven by a real non-control slot): buffer from model.locals appears', () => {
    const workspace = buildWorkspace({
      slots: [
        {
          key: 'buffer-obs',
          technicalLabel: 'buffer',
          semanticRole: 'buffer',
          size: 64,
          offsetFromBp: -0x70,
          offsetFromBpLabel: 'RBP -0x70',
          addressLabel: '0xf90',
          displayValue: '""',
          source: 'auto'
        }
      ]
    });
    const kinds = workspace.frameModel.entries.map((entry: any) => entry.kind);
    expect(kinds).to.include('saved_bp');
    expect(kinds).to.include('return_address');
    expect(kinds).to.include('buffer');
    const buffer = workspace.frameModel.entries.find((entry: any) => entry.kind === 'buffer');
    expect(buffer.offset).to.equal(-0x70);
    expect(buffer.size).to.equal(64);
  });

  it('a backend frameReady=true signal also allows model.locals through with no raw slots', () => {
    const workspace = buildWorkspace({ slots: [], frameReady: true });
    expect(workspace.frameModel.entries.some((entry: any) => entry.kind === 'buffer')).to.equal(true);
  });

  describe('real snapshot.stack raw dump (buffer84, push rbp step 1)', () => {
    // Replays the real pipeline: snapshot.stack is always populated (one
    // raw {id, addr, pos, size, value} word per memory slot, regardless of
    // Evidence/frame_ready -- see backends/dynamic/engine/unicorn/hooks.py
    // ::_legacy_stack_items). At step 1, analysis.frame.slots is a real,
    // empty array (the backend already gates rbp-relative Evidence out).
    // Before this fix, that emptiness made buildSemanticStackItems bail out
    // and the legacy injectControlSlots(stackItems, ...) fallback rendered
    // all 34 raw words as unlabeled #33..#0 synthetic entries.
    const wordSize = 8n;
    const rbp = 0x1000n;
    const rsp = 0xff8n;
    const windowStart = 0xf90n;
    const wordCount = 34;

    function buildRawStackItems() {
      const items: any[] = [];
      for (let i = 0; i < wordCount; i += 1) {
        const addr = windowStart + BigInt(i) * wordSize;
        items.push({
          id: i,
          addr: `0x${addr.toString(16)}`,
          pos: Number(addr - rsp),
          size: 8,
          value: `0x${(BigInt(i) * 17n).toString(16)}`
        });
      }
      return items;
    }

    function buildRealisticWorkspace(analysisFrameSlots: unknown[]) {
      const analysis = {
        function: { name: 'main' },
        frame: {
          slots: analysisFrameSlots,
          basePointer: `0x${rbp.toString(16)}`,
          stackPointer: `0x${rsp.toString(16)}`,
          frameSize: 0x70
        },
        control: {
          savedBpAddr: `0x${rbp.toString(16)}`,
          retAddrAddr: `0x${(rbp + wordSize).toString(16)}`
        }
      };
      const semanticSlots = buildSemanticStackItems(analysis);
      const stackWithControl = semanticSlots.length
        ? semanticSlots
        : injectControlSlots(buildRawStackItems(), {
            rsp,
            savedBpAddr: rbp,
            retAddrAddr: rbp + wordSize,
            wordSize,
            retValue: '0x400000',
            modifiedAddr: null,
            modifiedValue: '(unavailable)'
          });
      const sorted = [...stackWithControl].sort((a, b) => compareStackItemsByAddrDesc(a, b, rsp));
      const sourceSlots = buildSimpleSourceItems(sorted, {
        options: {},
        rsp,
        rbp,
        retAddrAddr: rbp + wordSize,
        bufferStart: null,
        bufferEnd: null,
        analysisStackRoles: {},
        modelRegions: [],
        diagnostics: [],
        payloadText: '',
        payloadHex: '',
        spName: 'RSP',
        bpName: 'RBP'
      });
      return buildStackWorkspaceModel({
        slots: sourceSlots,
        snapshots: [{ step: 1, func: 'main' }],
        meta: { arch_bits: 64, word_size: 8 },
        currentStep: 1,
        selectedFunction: 'main',
        snapshot: { func: 'main' },
        analysis,
        mcp: { model }
      });
    }

    it('step 1 (analysis.frame.slots=[]): only saved rbp / return address, no #33/#32/#31 synthetic dump', () => {
      const workspace = buildRealisticWorkspace([]);
      const entries = workspace.frameModel.entries;
      expect(entries).to.have.length(2);
      const kinds = entries.map((entry: any) => entry.kind);
      expect(kinds).to.include('saved_bp');
      expect(kinds).to.include('return_address');
      expect(entries.some((entry: any) => entry.isSynthetic)).to.equal(false);
      expect(entries.some((entry: any) => /^#\d+$/.test(String(entry.name)))).to.equal(false);
    });

    it('after frame ready (analysis.frame.slots has real backend content): locals/buffers reappear', () => {
      const workspace = buildRealisticWorkspace([
        {
          role: 'buffer',
          label: 'buffer',
          offsetFromBp: -0x70,
          size: 64,
          confidence: 0.9,
          source: 'auto'
        }
      ]);
      const kinds = workspace.frameModel.entries.map((entry: any) => entry.kind);
      expect(kinds).to.include('saved_bp');
      expect(kinds).to.include('return_address');
      expect(kinds).to.include('buffer');
    });
  });
});
