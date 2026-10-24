// SPDX-License-Identifier: AGPL-3.0-only
const DEFAULT_TIMEOUT_MS = 1500;
const DEFAULT_MAX_IN_FLIGHT = 4;
const DEFAULT_EVENTS_PATH = '/v1/events';

function normalizeTelemetryEndpoint(endpoint) {
  try {
    const url = new URL(String(endpoint || '').trim());
    if (url.protocol !== 'https:') return '';
    if (url.pathname === '/') url.pathname = DEFAULT_EVENTS_PATH;
    return url.toString();
  } catch (_) {
    return '';
  }
}

function createTelemetryTransport({
  endpoint = '',
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxInFlight = DEFAULT_MAX_IN_FLIGHT,
  onDiagnostic = (_status) => {},
} = {}) {
  const normalizedEndpoint = normalizeTelemetryEndpoint(endpoint);
  const controllers = new Set<AbortController>();
  let disposed = false;
  const reportedDiagnostics = new Set();

  function reportDiagnostic(status) {
    if (reportedDiagnostics.has(status)) return;
    reportedDiagnostics.add(status);
    try {
      onDiagnostic(status);
    } catch (_) {
      // Diagnostics must not affect best-effort telemetry delivery.
    }
  }

  async function sendBody(body) {
    if (disposed || !normalizedEndpoint || typeof fetchImpl !== 'function') {
      reportDiagnostic('disabled');
      return false;
    }
    if (controllers.size >= maxInFlight) {
      reportDiagnostic('rejected');
      return false;
    }

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
      if (response?.ok === true) return true;
      reportDiagnostic('rejected');
      return false;
    } catch (_) {
      reportDiagnostic('failed');
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
