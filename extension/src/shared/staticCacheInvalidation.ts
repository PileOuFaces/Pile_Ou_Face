// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Ordering between the queued async cache writes and the sync maintenance paths
 * (clear, delete-binary), which do not go through the queue.
 *
 * Each invalidation records a sequence number per database (and per binary for
 * delete-binary). A write captures the current number at submission; if an
 * invalidation is recorded afterwards, the write must not leave its entry behind.
 */

const fs = require('fs');
const path = require('path');

let invalidationSeq = 0;
const states = new Map();

function getState(dbPath) {
  let state = states.get(dbPath);
  if (!state) {
    state = { all: 0, binaries: new Map() };
    states.set(dbPath, state);
  }
  return state;
}

/** Sequence number to capture when a write is submitted. */
function currentInvalidationSeq() {
  return invalidationSeq;
}

/** Records an invalidation of the whole database, or of one binary when identity is given. */
function markInvalidated(dbPath, identity: string | null = null) {
  invalidationSeq += 1;
  const state = getState(dbPath);
  if (identity === null) {
    state.all = invalidationSeq;
    state.binaries.clear();
  } else {
    state.binaries.set(identity, invalidationSeq);
  }
}

function isInvalidatedSince(dbPath, identity, seq) {
  const state = states.get(dbPath);
  if (!state) return false;
  return state.all > seq || (state.binaries.get(identity) || 0) > seq;
}

// Both mirror the backend's Path.resolve(): symlinks are followed when the path exists.
function binaryIdentitySync(binaryPath) {
  try {
    return fs.realpathSync(binaryPath);
  } catch {
    return path.resolve(binaryPath);
  }
}

async function binaryIdentity(binaryPath) {
  try {
    return await fs.promises.realpath(binaryPath);
  } catch {
    return path.resolve(binaryPath);
  }
}

module.exports = {
  currentInvalidationSeq,
  markInvalidated,
  isInvalidatedSince,
  binaryIdentity,
  binaryIdentitySync,
};
