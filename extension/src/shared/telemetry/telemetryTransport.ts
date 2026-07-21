// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const DEFAULT_TIMEOUT_MS = 1500;
const DEFAULT_MAX_IN_FLIGHT = 4;

function normalizeTelemetryEndpoint(endpoint) {
  try {
    const url = new URL(String(endpoint || '').trim());
    return url.protocol === 'https:' ? url.toString() : '';
  } catch (_) {
    return '';
  }
}

function createTelemetryTransport({
  endpoint = '',
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxInFlight = DEFAULT_MAX_IN_FLIGHT,
} = {}) {
  const normalizedEndpoint = normalizeTelemetryEndpoint(endpoint);
  const controllers = new Set();
  let disposed = false;

  async function sendBody(body) {
    if (disposed || !normalizedEndpoint || typeof fetchImpl !== 'function') return false;
    if (controllers.size >= maxInFlight) return false;

    const controller = new AbortController();
    controllers.add(controller);
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
    try {
      const response = await fetchImpl(normalizedEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
        signal: controller.signal,
      });
      return response?.ok === true;
    } catch (_) {
      return false;
    } finally {
      clearTimeout(timer);
      controllers.delete(controller);
    }
  }

  function abortInFlight() {
    controllers.forEach((controller) => controller.abort());
    controllers.clear();
  }

  function dispose() {
    disposed = true;
    abortInFlight();
  }

  return {
    abortInFlight,
    dispose,
    isConfigured: () => Boolean(normalizedEndpoint),
    sendBody,
  };
}

module.exports = {
  DEFAULT_MAX_IN_FLIGHT,
  DEFAULT_TIMEOUT_MS,
  createTelemetryTransport,
  normalizeTelemetryEndpoint,
};
