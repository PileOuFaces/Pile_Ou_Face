// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file scriptStorage.ts
 * @brief Name and content of a script saved from the hub editor (untrusted webview).
 *
 * `hubSaveScript` used to join the webview-provided name to the scripts folder, so
 * `../../.bashrc` wrote outside it. The name is now a plain file name in that folder.
 */
const path = require('path');
const { writeFileAtomic } = require('../shared/privateTempDir');

const SCRIPT_NAME = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$/;
const SCRIPT_EXTENSION = '.py';
const MAX_SCRIPT_BYTES = 1024 * 1024;

type Result<T> = { ok: true; value: T } | { ok: false; reason: string };

/** Plain file name (no folder, no `..`), with the .py extension added when missing. */
function scriptFileName(name: unknown): Result<string> {
  const trimmed = typeof name === 'string' ? name.trim() : '';
  if (!SCRIPT_NAME.test(trimmed) || trimmed.includes('..')) {
    return { ok: false, reason: 'use a simple file name (letters, digits, . _ - and spaces)' };
  }
  return { ok: true, value: trimmed.toLowerCase().endsWith(SCRIPT_EXTENSION) ? trimmed : `${trimmed}${SCRIPT_EXTENSION}` };
}

/** Writes the script in `scriptsDir` without following a symlink planted at its name. */
function saveScript(scriptsDir: string, name: unknown, content: unknown, fsApi = require('fs')): Result<string> {
  const fileName = scriptFileName(name);
  if (fileName.ok === false) return fileName;
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf8') > MAX_SCRIPT_BYTES) {
    return { ok: false, reason: 'the script must be text of at most 1 MiB' };
  }
  fsApi.mkdirSync(scriptsDir, { recursive: true });
  const target = path.join(scriptsDir, fileName.value);
  writeFileAtomic(target, content, fsApi);
  return { ok: true, value: target };
}

module.exports = { scriptFileName, saveScript, MAX_SCRIPT_BYTES };
