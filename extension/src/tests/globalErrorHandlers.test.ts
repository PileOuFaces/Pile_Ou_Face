const { expect } = require('chai');
const sinon = require('sinon');
const extension = require('../extension');
const utils = require('../shared/utils');

describe('global error handlers — filet de sécurité unhandledRejection', () => {
  afterEach(() => {
    extension._unregisterGlobalErrorHandlers();
    sinon.restore();
  });

  // _handleGlobalError est la logique invoquée par le listener process.on(...) ;
  // on l'appelle directement pour rester déterministe (émettre un vrai événement
  // process 'unhandledRejection' interfère avec le handler global du test runner
  // lui-même).
  it('_handleGlobalError logue une erreur au niveau error, avec prefixe', () => {
    const appendLine = sinon.stub(utils.logChannel, 'appendLine');

    extension._handleGlobalError('unhandledRejection', new Error('boom'));

    expect(appendLine.calledOnce).to.equal(true);
    const line = appendLine.getCall(0).args[0];
    expect(line).to.include('[ERROR]');
    expect(line).to.include('unhandledRejection');
    expect(line).to.include('boom');
  });

  it('_formatUnhandledError inclut le prefixe et la stack/message', () => {
    const formatted = extension._formatUnhandledError('unhandledRejection', new Error('kaboom'));
    expect(formatted).to.include('[unhandledRejection]');
    expect(formatted).to.include('kaboom');
  });

  it('_formatUnhandledError gère une valeur rejetée qui n\'est pas une Error', () => {
    const formatted = extension._formatUnhandledError('unhandledRejection', 'just a string');
    expect(formatted).to.equal('[unhandledRejection] just a string');
  });

  it('register ajoute un listener unhandledRejection, une seule fois', () => {
    const before = process.listenerCount('unhandledRejection');

    extension._registerGlobalErrorHandlers();
    extension._registerGlobalErrorHandlers();

    expect(process.listenerCount('unhandledRejection')).to.equal(before + 1);
  });

  it('unregister retire le listener', () => {
    const before = process.listenerCount('unhandledRejection');

    extension._registerGlobalErrorHandlers();
    extension._unregisterGlobalErrorHandlers();

    expect(process.listenerCount('unhandledRejection')).to.equal(before);
  });

  it('ne touche pas au listener uncaughtException de Node/Mocha', () => {
    const before = process.listenerCount('uncaughtException');

    extension._registerGlobalErrorHandlers();

    expect(process.listenerCount('uncaughtException')).to.equal(before);
  });
});
