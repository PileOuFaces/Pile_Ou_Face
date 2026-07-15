const path = require('path');
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
    const env = utils.buildRuntimeEnv('/workspace', '', { BINHOST_LOG_LEVEL: 'CUSTOM' });
    expect(env).to.have.property('BINHOST_LOG_LEVEL', 'CUSTOM');
  });

  it('injecte les chemins de stockage quand storageDir est fourni', () => {
    const env = utils.buildRuntimeEnv('/workspace', '/tmp/pof-storage');
    expect(env).to.have.property('POF_STORAGE_DIR', '/tmp/pof-storage');
    expect(env).to.have.property('DECOMPILERS_CONFIG', path.join('/tmp/pof-storage', 'decompilers.json'));
    expect(env).to.have.property('COMPILERS_CONFIG', path.join('/tmp/pof-storage', 'compilers.json'));
  });

  it('défaut à WARNING si le logger n\'a pas été configuré', () => {
    expect(utils.buildRuntimeEnv('/workspace')).to.have.property('BINHOST_LOG_LEVEL', 'WARNING');
  });
});
