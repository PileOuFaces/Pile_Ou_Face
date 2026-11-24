// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file decompilerPathsSchema.ts
 * @brief Rules for `decompilerLocalPaths` (#531): local decompiler installation folders
 *        that the backend runs programs from (e.g. Ghidra via GHIDRA_INSTALL_DIR).
 *
 * Trust model, same as pythonPath (POF-P1-002):
 * - a folder is trusted only because the user picked it in the extension host's native
 *   dialog; the host then records it (attestation, separate globalState key);
 * - the webview can only send back the current value or clear an entry ('');
 * - stored values that no attestation covers are dropped by the migration.
 * Structural checks (decompilerLocalPaths.ts) only catch a wrong folder: they do not prove
 * that the folder holds a genuine, unmodified installation.
 */

const path = require('path');

// Attestation map { decompilerId: path | [path, previousPath] }, written by the host only.
const DECOMPILER_PATHS_ATTESTATION_KEY = 'pof-decompiler-paths-selected';

// Decompilers whose local path is used to run a program. Any other id is refused.
const LOCAL_PATH_DECOMPILER_IDS: readonly string[] = Object.freeze(['ghidra']);
const MAX_LOCAL_PATH_LENGTH = 4096;

type Paths = Record<string, string>;
type Check = { ok: boolean; value?: Paths; reason?: string };

const isPlainObject = (value: unknown): boolean => !!value && typeof value === 'object'
  && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;

function isSupportedDecompilerId(id: unknown): id is string {
  return typeof id === 'string' && LOCAL_PATH_DECOMPILER_IDS.includes(id);
}

function pathShapeProblem(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return 'expected a non-empty string';
  if (value.length > MAX_LOCAL_PATH_LENGTH) return `expected at most ${MAX_LOCAL_PATH_LENGTH} characters`;
  if (value.includes('\0')) return 'unexpected NUL character';
  // Both styles: a Windows path stored on Windows, a POSIX one elsewhere.
  if (!path.posix.isAbsolute(value) && !path.win32.isAbsolute(value)) return 'expected an absolute path';
  return null;
}

/** Shape only (stored settings): supported ids, absolute bounded paths. */
function validateLocalPathsShape(value: unknown): Check {
  if (!isPlainObject(value)) return { ok: false, reason: 'expected an object' };
  const paths: Paths = {};
  for (const [id, localPath] of Object.entries(value as Paths)) {
    if (!isSupportedDecompilerId(id)) return { ok: false, reason: `unsupported decompiler ${JSON.stringify(id)}` };
    const problem = pathShapeProblem(localPath);
    if (problem) return { ok: false, reason: `${id}: ${problem}` };
    paths[id] = localPath;
  }
  return { ok: true, value: paths };
}

/** Attested paths per decompiler id (string, or [new, previous] during a change). */
function normalizeAttestedPaths(attested: unknown): Record<string, string[]> {
  if (!isPlainObject(attested)) return {};
  const result: Record<string, string[]> = {};
  for (const [id, value] of Object.entries(attested as Record<string, unknown>)) {
    if (!isSupportedDecompilerId(id)) continue;
    const values = (Array.isArray(value) ? value : [value]).filter((v) => typeof v === 'string' && v !== '');
    if (values.length) result[id] = values as string[];
  }
  return result;
}

/** Migration: keeps only the entries a host attestation covers; reports the others. */
function keepAttestedPaths(stored: Paths, attested: unknown): { paths: Paths; dropped: string[] } {
  const attestedById = normalizeAttestedPaths(attested);
  const paths: Paths = {};
  const dropped: string[] = [];
  for (const [id, localPath] of Object.entries(stored)) {
    if ((attestedById[id] || []).includes(localPath)) paths[id] = localPath;
    else dropped.push(`decompilerLocalPaths.${id}`);
  }
  return { paths, dropped };
}

/**
 * A `hubSaveSettings` value from the webview: each entry must be '' (explicit clear) or the
 * current value; omitted entries are kept. Anything else is refused.
 */
function mergeWebviewUpdate(incoming: unknown, current: Paths = {}): { ok: boolean; value?: Paths; errors?: string[] } {
  if (!isPlainObject(incoming)) return { ok: false, errors: ['decompilerLocalPaths: expected an object'] };
  const merged: Paths = { ...current };
  const errors: string[] = [];
  for (const [id, value] of Object.entries(incoming as Record<string, unknown>)) {
    if (!isSupportedDecompilerId(id)) {
      errors.push(`decompilerLocalPaths.${id}: unsupported decompiler`);
    } else if (value === '') {
      delete merged[id];
    } else if (value !== current[id]) {
      errors.push(`decompilerLocalPaths.${id}: can only be set by the extension host`);
    }
  }
  return errors.length ? { ok: false, errors } : { ok: true, value: merged };
}

module.exports = {
  DECOMPILER_PATHS_ATTESTATION_KEY,
  LOCAL_PATH_DECOMPILER_IDS,
  isSupportedDecompilerId,
  pathShapeProblem,
  validateLocalPathsShape,
  normalizeAttestedPaths,
  keepAttestedPaths,
  mergeWebviewUpdate,
};
