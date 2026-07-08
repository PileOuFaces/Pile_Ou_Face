const { expect } = require('chai');
const logger = require('../shared/logger');

describe('logger — niveaux, format, redaction', () => {
  afterEach(() => {
    logger.setLevel(logger.DEFAULT_LEVEL);
  });

  it('défaut à warning', () => {
    expect(logger.getLevel()).to.equal('warning');
  });

  it('shouldLog filtre par niveau courant', () => {
    logger.setLevel('warning');
    expect(logger.shouldLog('debug')).to.equal(false);
    expect(logger.shouldLog('info')).to.equal(false);
    expect(logger.shouldLog('warning')).to.equal(true);
    expect(logger.shouldLog('error')).to.equal(true);
  });

  it('shouldLog laisse tout passer en debug', () => {
    logger.setLevel('debug');
    expect(logger.shouldLog('debug')).to.equal(true);
    expect(logger.shouldLog('info')).to.equal(true);
    expect(logger.shouldLog('warning')).to.equal(true);
    expect(logger.shouldLog('error')).to.equal(true);
  });

  it('setLevel retombe sur le défaut si valeur inconnue', () => {
    logger.setLevel('bogus');
    expect(logger.getLevel()).to.equal('warning');
  });

  it('formatLine produit [HH:MM:SS] [LEVEL] message', () => {
    const line = logger.formatLine('info', 'hello');
    expect(line).to.match(/^\[\d{2}:\d{2}:\d{2}\] \[INFO\] hello$/);
  });

  it('mapLevelToEnv renvoie la valeur en majuscules', () => {
    expect(logger.mapLevelToEnv('debug')).to.equal('DEBUG');
    expect(logger.mapLevelToEnv('bogus')).to.equal('WARNING');
  });

  describe('redact', () => {
    it('masque un JWT', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      expect(logger.redact(`token reçu: ${jwt}`)).to.not.include(jwt);
      expect(logger.redact(`token reçu: ${jwt}`)).to.include('[REDACTED_JWT]');
    });

    it('masque un bloc PEM', () => {
      const pem = '-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQ\n-----END PRIVATE KEY-----';
      const result = logger.redact(`clé: ${pem}`);
      expect(result).to.not.include('MIIBVgIBADANBgkqhkiG9w0BAQ');
      expect(result).to.include('[REDACTED_PEM]');
    });

    it('masque password/token/secret/content_key en key=value', () => {
      expect(logger.redact('password=hunter2')).to.equal('password=[REDACTED]');
      expect(logger.redact('content_key: abc123')).to.equal('content_key: [REDACTED]');
      expect(logger.redact('POF_CONTENT_KEY_FOO=deadbeef')).to.include('[REDACTED]');
    });

    it('laisse les messages sans secret inchangés', () => {
      expect(logger.redact('démarrage du backend')).to.equal('démarrage du backend');
    });
  });
});
