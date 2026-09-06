// SPDX-License-Identifier: AGPL-3.0-only

const { expect } = require('chai');
const {
  mapArch,
  mapBinaryFormat,
  mapPanel,
  mapPayloadMode,
  mapPlatform,
  mapTarget,
} = require('../shared/telemetry/telemetryMappings');

describe('telemetry mappings', () => {
  it('maps supported platforms and falls back safely', () => {
    expect(mapPlatform('win32')).to.equal('windows');
    expect(mapPlatform('darwin')).to.equal('macos');
    expect(mapPlatform('linux')).to.equal('linux');
    expect(mapPlatform('freebsd')).to.equal('other');
  });

  it('normalizes panel names and aliases', () => {
    expect(mapPanel(' Outils ')).to.equal('tools');
    expect(mapPanel('options')).to.equal('settings');
    expect(mapPanel('dynamic')).to.equal('dynamic');
    expect(mapPanel('unknown')).to.equal('dashboard');
  });

  it('normalizes binary formats', () => {
    expect(mapBinaryFormat('Mach-O')).to.equal('macho');
    expect(mapBinaryFormat('RAW')).to.equal('raw');
    expect(mapBinaryFormat('unknown format')).to.equal('unknown');
  });

  it('normalizes architectures and uses bitness fallbacks', () => {
    expect(mapArch('AMD64')).to.equal('x64');
    expect(mapArch('thumb')).to.equal('arm');
    expect(mapArch('', 64)).to.equal('x64');
    expect(mapArch('', 32)).to.equal('x86');
    expect(mapArch('mips')).to.equal('other');
    expect(mapArch('')).to.equal('unknown');
  });

  it('normalizes payload modes', () => {
    expect(mapPayloadMode('file')).to.equal('file');
    expect(mapPayloadMode('pwntools_script')).to.equal('pwntools');
    expect(mapPayloadMode('exploit_helper')).to.equal('exploit_helper');
    expect(mapPayloadMode('unknown')).to.equal('builder');
  });

  it('normalizes targets and gives file mode precedence', () => {
    expect(mapTarget('stdin')).to.equal('stdin');
    expect(mapTarget('argv1')).to.equal('argv1');
    expect(mapTarget('invalid')).to.equal('auto');
    expect(mapTarget('stdin', 'file')).to.equal('file');
  });
});
