// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Bridge from the VS Code extension's webview handlers to the annotations
 * CLI (backends/static/annotations/annotations.py). Each method spawns the
 * CLI via pythonRunner and parses its grouped-by-address JSON output —
 * callers get back the same {[addr]: {...}} shape the webview expects, no
 * kind-grouping logic needs to be duplicated on the TS side.
 */
const { makeRunPython } = require('./pythonRunner');

const SCRIPT = 'backends/static/annotations/annotations.py';

function makeAnnotationsBridge(ctx) {
  const runPython = ctx.runPython || makeRunPython(ctx);
  const dbArgs = ctx.dbPathOverride ? ['--cache-db', ctx.dbPathOverride] : [];

  async function invoke(binaryPath, args) {
    const { stdout } = await runPython([SCRIPT, '--binary', binaryPath, ...dbArgs, ...args]);
    return JSON.parse(stdout);
  }

  return {
    loadAnnotations: (binaryPath) => invoke(binaryPath, ['list', '--grouped']),
    saveAnnotation: (binaryPath, addr, { comment, name } = {}) => {
      const args = ['annotate', '--addr', addr];
      if (comment !== undefined) args.push('--comment', comment);
      if (name !== undefined) args.push('--name', name);
      return invoke(binaryPath, args);
    },
    saveFunctionReview: (binaryPath, addr, { reviewStatus, reviewNotes } = {}) =>
      invoke(binaryPath, ['review', '--addr', addr, '--status', reviewStatus || '', '--notes', reviewNotes || '']),
    saveBookmark: (binaryPath, addr, { label, color } = {}) =>
      invoke(binaryPath, ['bookmark', '--addr', addr, '--label', label || '', '--color', color || '#4ec9b0']),
    deleteBookmark: (binaryPath, addr) => invoke(binaryPath, ['delete-bookmark', '--addr', addr]),
    clearBookmarks: (binaryPath) => invoke(binaryPath, ['clear-bookmarks']),
    deleteAnnotation: (binaryPath, addr) => invoke(binaryPath, ['delete-annotation', '--addr', addr]),
    migrateLegacyJson: (binaryPath, legacyAnnotations) =>
      invoke(binaryPath, ['migrate-legacy', '--json', JSON.stringify(legacyAnnotations)]),
  };
}

module.exports = { makeAnnotationsBridge };
