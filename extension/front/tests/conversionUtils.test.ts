const { expect } = require('chai');

const conversionUtils = require('../webview/shared/conversionUtils.js');

describe('pwn conversion utils', () => {
  it('normalizes the supported pwn input formats', () => {
    const cases = [
      ['0x401176', '0x401176', '4198774', '@.v', 'p64(0x401176)'],
      ['ABCD', '0x41424344', '1094861636', 'ABCD', 'p64(0x41424344)'],
      ['7611400000000000', '0x401176', '4198774', 'v.@.....', 'p64(0x401176)'],
      ['41424344004142', '0x41424344004142', '18368730157302082', 'ABCD.AB', 'p64(0x41424344004142)'],
      [String.raw`\x48\x31\xc0\x50`, '0x4831c050', '1211220048', 'H1.P', 'p64(0x4831c050)'],
    ];

    for (const [input, hex, decimal, ascii, p64] of cases) {
      const result = conversionUtils.convertPwnValue(input);
      expect(result.ok, input).to.equal(true);
      expect(result.outputs.hex, input).to.equal(hex);
      expect(result.outputs.decimal, input).to.equal(decimal);
      expect(result.outputs.ascii, input).to.equal(ascii);
      expect(result.outputs.p64, input).to.equal(p64);
    }
  });

  it('keeps little-endian bytes displayable as compact or spaced output', () => {
    const result = conversionUtils.convertPwnValue('7611400000000000');

    expect(result.meta).to.deep.equal({
      usefulBytes: 8,
      fits32: true,
      fits64: true,
      recommendation: 'p64 recommandé',
    });
    expect(conversionUtils.formatDisplayBytes(result.byteFields.little64, 'compact')).to.equal('7611400000000000');
    expect(conversionUtils.formatDisplayBytes(result.byteFields.little64, 'spaced')).to.equal('76 11 40 00 00 00 00 00');
    expect(conversionUtils.formatDisplayBytes(result.byteFields.big64, 'compact')).to.equal('0000000000401176');
  });

  it('computes signed and unsigned 32-bit and 64-bit interpretations', () => {
    const result = conversionUtils.convertPwnValue('ffffffffffffffff');

    expect(result.outputs.unsigned32).to.equal('4294967295');
    expect(result.outputs.signed32).to.equal('-1');
    expect(result.outputs.unsigned64).to.equal('18446744073709551615');
    expect(result.outputs.signed64).to.equal('-1');
    expect(result.meta.fits32).to.equal(false);
    expect(result.meta.fits64).to.equal(true);
  });

  it('renders a bounded hexdump with printable ASCII and dot placeholders', () => {
    const result = conversionUtils.convertPwnValue('41424344004142');

    expect(result.outputs.hexdump).to.equal('0000  41 42 43 44 00 41 42     ABCD.AB');
    expect(conversionUtils.buildHexdump(new Array(66).fill(0x41))).to.contain('... 2 byte(s) masqué(s)');
  });
});

describe('pwn conversion controller', () => {
  const controllerPath = require.resolve('../webview/shared/conversionController.js');
  let originalWindow;
  let originalDocument;
  let copied;

  function createElement(id, elements) {
    if (!elements.has(id)) {
      const listeners = {};
      elements.set(id, {
        id,
        textContent: '',
        value: id === 'pwnConverterInput' ? 'ffffffffffffffff' : '',
        hidden: false,
        dataset: {},
        children: [],
        classList: { add() {}, remove() {}, toggle() {} },
        setAttribute() {},
        replaceChildren() { this.children = []; },
        appendChild(node) { this.children.push(node); },
        addEventListener(type, fn) { listeners[type] = fn; },
        _listeners: listeners,
      });
    }
    return elements.get(id);
  }

  beforeEach(() => {
    delete require.cache[controllerPath];
    originalWindow = global.window;
    originalDocument = global.document;
    copied = '';

    const elements = new Map();
    [
      'pwnConverterInput',
      'pwnConverterStatus',
      'pwnConverterMeta',
      'pwnConverterWarnings',
      'pwnConverterHex',
      'pwnConverterDecimal',
      'pwnConverterAscii',
      'pwnConverterEscaped',
      'pwnConverterLittle32',
      'pwnConverterLittle64',
      'pwnConverterBig32',
      'pwnConverterBig64',
      'pwnConverterP32',
      'pwnConverterP64',
      'pwnConverterU32',
      'pwnConverterU64',
      'pwnConverterUnsigned32',
      'pwnConverterSigned32',
      'pwnConverterUnsigned64',
      'pwnConverterSigned64',
      'pwnConverterHexdump',
    ].forEach((id) => createElement(id, elements));

    global.window = global;
    global.POFHubConversionUtils = conversionUtils;
    global.document = {
      readyState: 'complete',
      getElementById: (id) => createElement(id, elements),
      querySelectorAll: (selector) => {
        if (selector === '[data-copy-conversion]' || selector === '[data-byte-display]') return [];
        if (selector === '.pwn-converter-output code') {
          return Array.from(elements.values()).filter((el) => (
            el.id.startsWith('pwnConverter')
            && !/Input|Status|Meta|Warnings/.test(el.id)
          ));
        }
        return [];
      },
      createElement: () => ({ textContent: '' }),
      addEventListener() {},
    };
    global.navigator = global.navigator || {};
    global.navigator.clipboard = {
      writeText(value) {
        copied = value;
        return Promise.resolve();
      },
    };
  });

  afterEach(() => {
    global.window = originalWindow;
    global.document = originalDocument;
    delete global.POFHubConversionUtils;
    delete require.cache[controllerPath];
  });

  it('copies an output value when the value itself is clicked', async () => {
    require('../webview/shared/conversionController.js');

    const signed64 = global.document.getElementById('pwnConverterSigned64');
    expect(signed64.textContent).to.equal('-1');

    await signed64._listeners.click();

    expect(copied).to.equal('-1');
    expect(global.document.getElementById('pwnConverterStatus').textContent).to.equal('Copied');
  });
});
