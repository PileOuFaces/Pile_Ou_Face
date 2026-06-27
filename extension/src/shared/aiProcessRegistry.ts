// SPDX-License-Identifier: AGPL-3.0-only

const activeRequests = new Map();

function registerAiProcess(requestId, cancel) {
  const id = String(requestId || '').trim();
  if (!id || typeof cancel !== 'function') return;
  const previous = activeRequests.get(id);
  if (previous) previous();
  activeRequests.set(id, cancel);
}

function clearAiProcess(requestId) {
  const id = String(requestId || '').trim();
  if (id) activeRequests.delete(id);
}

function cancelAiProcess(requestId) {
  const id = String(requestId || '').trim();
  const cancel = activeRequests.get(id);
  if (!cancel) return false;
  activeRequests.delete(id);
  cancel();
  return true;
}

module.exports = {
  cancelAiProcess,
  clearAiProcess,
  registerAiProcess,
};
