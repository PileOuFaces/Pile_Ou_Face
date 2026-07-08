const { expect } = require('chai');
const sinon = require('sinon');
const extension = require('../extension');
const utils = require('../shared/utils');

describe('global error handlers — filet de sécurité unhandledRejection/uncaughtException', () => {
  afterEach(() => {
    extension._unregisterGlobalErrorHandlers();
    sinon.restore();
  });

  // _handleGlobalError est la logique invoquée par les listeners process.on(...) ;
  // on l'appelle directement pour rester déterministe (émettre de vrais événements
  // process 'uncaughtException'/'unhandledRejection' interfère avec le handler
  // global du test runner lui-même).
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
    const formatted = extension._formatUnhandledError('uncaughtException', new Error('kaboom'));
    expect(formatted).to.include('[uncaughtException]');
    expect(formatted).to.include('kaboom');
  });

  it('_formatUnhandledError gère une valeur rejetée qui n\'est pas une Error', () => {
    const formatted = extension._formatUnhandledError('unhandledRejection', 'just a string');
    expect(formatted).to.equal('[unhandledRejection] just a string');
  });

  it('register ajoute un listener process pour chaque événement, une seule fois', () => {
    const beforeRejection = process.listenerCount('unhandledRejection');
    const beforeException = process.listenerCount('uncaughtException');

    extension._registerGlobalErrorHandlers();
    extension._registerGlobalErrorHandlers();

    expect(process.listenerCount('unhandledRejection')).to.equal(beforeRejection + 1);
    expect(process.listenerCount('uncaughtException')).to.equal(beforeException + 1);
  });

  it('unregister retire les listeners', () => {
    const beforeRejection = process.listenerCount('unhandledRejection');
    const beforeException = process.listenerCount('uncaughtException');

    extension._registerGlobalErrorHandlers();
    extension._unregisterGlobalErrorHandlers();

    expect(process.listenerCount('unhandledRejection')).to.equal(beforeRejection);
    expect(process.listenerCount('uncaughtException')).to.equal(beforeException);
  });
});
