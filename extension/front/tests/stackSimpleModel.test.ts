const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('stackSimpleModel', () => {
  let buildSimplifiedStackViewModel;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../webview/dynamic/app/stackSimpleModel.js');
    const source = fs.readFileSync(modulePath, 'utf8');
    const dataUrl = `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;
    ({ buildSimplifiedStackViewModel } = await import(dataUrl));
  });

  it('projects canonical frame entries into simple linear rows with polished titles', () => {
    const viewModel = buildSimplifiedStackViewModel({
      statusText: 'main() • etape 3 • 6 elements',
      detailModel: { key: 'slot-buffer' },
      frameModel: {
        bpRegister: 'ebp',
        registerArguments: [],
        spMarker: { register: 'ESP', addressLabel: '0xffffcfd0' },
        entries: [
          {
            key: 'slot-argv',
            name: 'argv',
            offset: 12,
            offsetLabel: 'ebp+0xc',
            badges: [],
            offsetBand: 'positive',
            isSensitive: false
          },
          {
            key: 'slot-buffer',
            name: 'buffer_0',
            kind: 'buffer',
            size: 24,
            offset: -80,
            offsetLabel: 'ebp-0x50',
            badges: ['WRITE'],
            offsetBand: 'negative',
            isSensitive: true,
            valuePreview: '"AAAA..."'
          }
        ]
      }
    });

    expect(viewModel.statusText).to.equal('main() • etape 3 • 6 elements');
    expect(viewModel.spMarker).to.deep.equal({ register: 'ESP', addressLabel: '0xffffcfd0' });
    expect(viewModel.items.map((item) => ({
      key: item.key,
      selectionKey: item.selectionKey,
      title: item.title,
      subtitle: item.subtitle,
      badges: item.badges,
      isSelected: item.isSelected,
      valuePreview: item.valuePreview,
      offsetBand: item.offsetBand,
      isSensitive: item.isSensitive
    }))).to.deep.equal([
      {
        key: 'slot-argv',
        selectionKey: 'slot-argv',
        title: 'argv',
        subtitle: 'ebp+0xc',
        badges: [],
        isSelected: false,
        valuePreview: '',
        offsetBand: 'positive',
        isSensitive: false
      },
      {
        key: 'slot-buffer',
        selectionKey: 'slot-buffer',
        title: 'buffer (24B)',
        subtitle: 'ebp-0x50',
        badges: ['WRITE'],
        isSelected: true,
        valuePreview: '"AAAA..."',
        offsetBand: 'negative',
        isSensitive: true
      }
    ]);
  });

  it('injects visual argc and argv above return address and keeps spill selection bound to source entries', () => {
    const viewModel = buildSimplifiedStackViewModel({
      detailModel: { key: 'slot-argc-spill' },
      frameModel: {
        bpRegister: 'rbp',
        registerArguments: [
          { location: 'rdi', name: 'argc', size: 4 },
          { location: 'rsi', name: 'argv', size: 8 }
        ],
        entries: [
          {
            key: 'slot-ret',
            name: 'return address',
            kind: 'return_address',
            offset: 8,
            offsetLabel: 'rbp+0x8',
            badges: ['RET'],
            offsetBand: 'positive',
            isSensitive: true,
            detailPayload: { rows: [] }
          },
          {
            key: 'slot-saved',
            name: 'saved rbp',
            kind: 'saved_bp',
            offset: 0,
            offsetLabel: 'rbp+0x0',
            badges: [],
            offsetBand: 'base',
            isSensitive: true,
            detailPayload: { rows: [] }
          },
          {
            key: 'slot-argc-spill',
            name: 'arg_0',
            kind: 'argument',
            size: 4,
            offset: -36,
            offsetLabel: 'rbp-0x24',
            badges: [],
            offsetBand: 'negative',
            isSensitive: false,
            detailPayload: { rows: [{ label: 'Offset', value: 'rbp-0x24' }] }
          },
          {
            key: 'slot-argv-spill',
            name: 'arg_1',
            kind: 'argument',
            size: 8,
            offset: -48,
            offsetLabel: 'rbp-0x30',
            badges: [],
            offsetBand: 'negative',
            isSensitive: false,
            detailPayload: { rows: [{ label: 'Offset', value: 'rbp-0x30' }] }
          }
        ]
      }
    });

    expect(viewModel.items.map((item) => `${item.title}:${item.subtitle}`)).to.deep.equal([
      'argv:rbp+0x18',
      'argc:rbp+0x10',
      'return address:rbp+0x8',
      'saved rbp:rbp+0x0'
    ]);
    expect(viewModel.items[1].selectionKey).to.equal('slot-argc-spill');
    expect(viewModel.items[1].isSelected).to.equal(true);
    expect(viewModel.items[1].badges).to.deep.equal(['ABI']);
  });

  it('prefers logical argument metadata from the canonical model when available', () => {
    const viewModel = buildSimplifiedStackViewModel({
      detailModel: { key: 'slot-argv-spill' },
      frameModel: {
        bpRegister: 'rbp',
        registerArguments: [
          { location: 'rdi', name: 'argc', size: 4 },
          { location: 'rsi', name: 'argv', size: 8 }
        ],
        logicalArguments: [
          {
            key: 'main:rbp:logical_argument:argv',
            name: 'argv',
            offset: 24,
            offsetLabel: 'rbp+0x18',
            storageKey: 'slot-argv-spill',
            storageOffsetLabel: 'rbp-0x30',
            registerLocation: 'rsi',
            cType: 'char **',
            source: 'source_c'
          },
          {
            key: 'main:rbp:logical_argument:argc',
            name: 'argc',
            offset: 16,
            offsetLabel: 'rbp+0x10',
            storageKey: 'slot-argc-spill',
            storageOffsetLabel: 'rbp-0x24',
            registerLocation: 'rdi',
            cType: 'int',
            source: 'source_c'
          }
        ],
        entries: [
          {
            key: 'slot-ret',
            name: 'return address',
            kind: 'return_address',
            offset: 8,
            offsetLabel: 'rbp+0x8',
            badges: ['RET'],
            offsetBand: 'positive',
            isSensitive: true,
            detailPayload: { rows: [] }
          },
          {
            key: 'slot-saved',
            name: 'saved rbp',
            kind: 'saved_bp',
            offset: 0,
            offsetLabel: 'rbp+0x0',
            badges: [],
            offsetBand: 'base',
            isSensitive: true,
            detailPayload: { rows: [] }
          },
          {
            key: 'slot-argc-spill',
            name: 'arg_0',
            kind: 'argument',
            size: 4,
            offset: -36,
            offsetLabel: 'rbp-0x24',
            badges: [],
            offsetBand: 'negative',
            isSensitive: false,
            detailPayload: { rows: [{ label: 'Offset', value: 'rbp-0x24' }] }
          },
          {
            key: 'slot-argv-spill',
            name: 'arg_1',
            kind: 'argument',
            size: 8,
            offset: -48,
            offsetLabel: 'rbp-0x30',
            badges: [],
            offsetBand: 'negative',
            isSensitive: false,
            detailPayload: { rows: [{ label: 'Offset', value: 'rbp-0x30' }] }
          }
        ]
      }
    });

    expect(viewModel.items.map((item) => `${item.title}:${item.subtitle}`)).to.deep.equal([
      'argv:rbp+0x18',
      'argc:rbp+0x10',
      'return address:rbp+0x8',
      'saved rbp:rbp+0x0'
    ]);
    expect(viewModel.items[0].key).to.equal('main:rbp:logical_argument:argv');
    expect(viewModel.items[0].selectionKey).to.equal('slot-argv-spill');
    expect(viewModel.items[0].isSelected).to.equal(true);
    expect(viewModel.items[0].detailPayload.rows).to.deep.include({ label: 'Type', value: 'char **' });
    expect(viewModel.items[0].detailPayload.rows).to.deep.include({ label: 'Source du nom', value: 'C' });
  });
});
