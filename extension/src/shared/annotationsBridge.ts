// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Bridge from the VS Code extension's webview handlers to the annotations
 * CLI (backends/static/annotations/annotations.py). Each method spawns the
 * CLI via pythonRunner and parses its grouped-by-address JSON output —
 * callers get back the same {[addr]: {...}} shape the webview expects, no
 * kind-grouping logic needs to be duplicated on the TS side.
 *
 * Les mutations passent --overlay-mapping : la CLI arbitre la fraîcheur du
 * .asm (patch en place des commentaires via le mapping SQLite) et renvoie
 * {"annotations", "overlay"} — le verdict est relayé tel quel au webview.
 */
const { makeRunPython } = require('./pythonRunner');

const SCRIPT = 'backends/static/annotations/annotations.py';

function makeAnnotationsBridge(ctx) {
  const runPython = ctx.runPython || makeRunPython(ctx);
  const dbArgs = ctx.dbPathOverride ? ['--cache-db', ctx.dbPathOverride] : [];
  const getOverlayMappingPath = typeof ctx.getOverlayMappingPath === 'function'
    ? ctx.getOverlayMappingPath
    : () => '';

  async function invoke(binaryPath, args) {
    const { stdout } = await runPython([SCRIPT, '--binary', binaryPath, ...dbArgs, ...args]);
    return JSON.parse(stdout);
  }

  async function invokeMutation(binaryPath, args) {
    const mappingPath = String(getOverlayMappingPath(binaryPath) || '');
    const overlayArgs = mappingPath ? ['--overlay-mapping', mappingPath] : [];
    const parsed = await invoke(binaryPath, [...overlayArgs, ...args]);
    if (parsed && typeof parsed === 'object' && 'annotations' in parsed && 'overlay' in parsed) {
      return { annotations: parsed.annotations || {}, overlay: String(parsed.overlay || '') };
    }
    return { annotations: parsed || {}, overlay: '' };
  }

  return {
    loadAnnotations: (binaryPath) => invoke(binaryPath, ['list', '--grouped']),
    saveAnnotation: (binaryPath, addr, { comment, name }: { comment?: string; name?: string } = {}) => {
      const args = ['annotate', '--addr', addr];
      if (comment !== undefined) args.push('--comment', comment);
      if (name !== undefined) args.push('--name', name);
      return invokeMutation(binaryPath, args);
    },
    saveFunctionReview: (binaryPath, addr, { reviewStatus, reviewNotes }: { reviewStatus?: string; reviewNotes?: string } = {}) =>
      invokeMutation(binaryPath, ['review', '--addr', addr, '--status', reviewStatus || '', '--notes', reviewNotes || '']),
    saveBookmark: (binaryPath, addr, { label, color }: { label?: string; color?: string } = {}) =>
      invokeMutation(binaryPath, ['bookmark', '--addr', addr, '--label', label || '', '--color', color || '#4ec9b0']),
    deleteBookmark: (binaryPath, addr) => invokeMutation(binaryPath, ['delete-bookmark', '--addr', addr]),
    clearBookmarks: (binaryPath) => invokeMutation(binaryPath, ['clear-bookmarks']),
    deleteAnnotation: (binaryPath, addr) => invokeMutation(binaryPath, ['delete-annotation', '--addr', addr]),
  };
}

module.exports = { makeAnnotationsBridge };
