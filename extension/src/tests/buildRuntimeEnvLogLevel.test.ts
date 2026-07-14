const { expect } = require('chai');
const utils = require('../shared/utils');
const logger = require('../shared/logger');

describe('buildRuntimeEnv — propagation BINHOST_LOG_LEVEL', () => {
  afterEach(() => {
    logger.setLevel(logger.DEFAULT_LEVEL);
  });

  it('injecte BINHOST_LOG_LEVEL mappé depuis le niveau courant du logger', () => {
    logger.setLevel('debug');
    const env = utils.buildRuntimeEnv('/workspace');
    expect(env).to.have.property('BINHOST_LOG_LEVEL', 'DEBUG');
  });

  it('reflète un changement de niveau à chaud', () => {
    logger.setLevel('error');
    expect(utils.buildRuntimeEnv('/workspace')).to.have.property('BINHOST_LOG_LEVEL', 'ERROR');
    logger.setLevel('info');
    expect(utils.buildRuntimeEnv('/workspace')).to.have.property('BINHOST_LOG_LEVEL', 'INFO');
  });

  it('un override explicite dans extraEnv est respecté', () => {
    logger.setLevel('warning');
    const env = utils.buildRuntimeEnv('/workspace', {}, { BINHOST_LOG_LEVEL: 'CUSTOM' });
    expect(env).to.have.property('BINHOST_LOG_LEVEL', 'CUSTOM');
  });

  it('défaut à WARNING si le logger n\'a pas été configuré', () => {
    expect(utils.buildRuntimeEnv('/workspace')).to.have.property('BINHOST_LOG_LEVEL', 'WARNING');
  });
});

describe('buildDecompilerImageEnv', () => {
  let utils;

  beforeEach(() => {
    delete require.cache[require.resolve('../shared/utils')];
    utils = require('../shared/utils');
  });

  it('maps official decompiler image selections to versioned GHCR env vars', () => {
    const env = utils.buildDecompilerImageEnv({
      decompilerImages: {
        ghidra: { source: 'ours' },
        retdec: { source: 'ours', version: '1.2.3' },
      },
    }, {
      ghidra: ['1.1.0', '1.0.0'],
      retdec: ['1.0.0'],
    });

    expect(env).to.include({
      POF_DECOMPILER_IMAGE_GHIDRA: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-ghidra:1.1.0',
      POF_DECOMPILER_IMAGE_RETDEC: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-retdec:1.2.3',
    });
  });

  it('maps custom images and omits local or empty selections', () => {
    const env = utils.buildDecompilerImageEnv({
      decompilerImages: {
        ghidra: { source: 'local' },
        retdec: { source: 'custom', custom: 'registry.example/retdec:test' },
        angr: { source: 'custom', custom: '' },
      },
    }, {
      ghidra: '1.0.0',
      angr: '1.0.0',
    });

    expect(env).to.deep.equal({
      POF_DECOMPILER_IMAGE_RETDEC: 'registry.example/retdec:test',
    });
  });
});
