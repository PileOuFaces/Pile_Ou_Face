// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function mapPlatform(value) {
  if (value === 'win32') return 'windows';
  if (value === 'darwin') return 'macos';
  if (value === 'linux') return 'linux';
  return 'other';
}

function mapPanel(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'outils') return 'tools';
  if (normalized === 'options') return 'settings';
  if (['dashboard', 'static', 'dynamic', 'runtime', 'tools', 'settings'].includes(normalized)) {
    return normalized;
  }
  return 'dashboard';
}

function mapBinaryFormat(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[-_\s]/g, '');
  if (normalized === 'elf') return 'elf';
  if (normalized === 'pe') return 'pe';
  if (normalized === 'macho') return 'macho';
  if (normalized === 'raw') return 'raw';
  return 'unknown';
}

function mapArch(value, bits = null) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[-_\s]/g, '');
  if (['x8664', 'amd64', 'i386:x8664'].includes(normalized)) return 'x64';
  if (['x86', 'i386', 'i686'].includes(normalized)) return 'x86';
  if (['arm64', 'aarch64'].includes(normalized)) return 'arm64';
  if (['arm', 'arm32', 'thumb'].includes(normalized)) return 'arm';
  if (!normalized && Number(bits) === 64) return 'x64';
  if (!normalized && Number(bits) === 32) return 'x86';
  return normalized ? 'other' : 'unknown';
}

function mapPayloadMode(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'file') return 'file';
  if (normalized === 'pwntools_script' || normalized === 'pwntools') return 'pwntools';
  if (normalized === 'exploit_helper') return 'exploit_helper';
  return 'builder';
}

function mapTarget(value, payloadMode = '') {
  if (mapPayloadMode(payloadMode) === 'file') return 'file';
  const normalized = String(value || '').trim().toLowerCase();
  if (['stdin', 'argv1', 'both', 'auto'].includes(normalized)) return normalized;
  return 'auto';
}

module.exports = {
  mapArch,
  mapBinaryFormat,
  mapPanel,
  mapPayloadMode,
  mapPlatform,
  mapTarget,
};
