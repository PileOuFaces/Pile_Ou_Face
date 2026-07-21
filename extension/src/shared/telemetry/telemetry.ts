// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const { sanitizeTelemetryEvent } = require('./telemetrySanitizer');
const { createTelemetryTransport } = require('./telemetryTransport');

function createSender(activeTransport) {
  return {
    sendEventData(eventName, data) {
      const sanitized = sanitizeTelemetryEvent(eventName, data || {});
      if (!sanitized.ok) return;
      try {
        const pending = activeTransport.sendBody(sanitized.body);
        pending?.catch?.(() => {});
      } catch (_) {
        // Telemetry is best effort and never reaches the product error path.
      }
    },
    sendErrorData() {},
    flush() {},
  };
}

function createLogger(vscode, activeTransport) {
  if (!vscode?.env?.createTelemetryLogger || !activeTransport.isConfigured?.()) return null;
  try {
    return vscode.env.createTelemetryLogger(createSender(activeTransport), {
      ignoreBuiltInCommonProperties: true,
      ignoreUnhandledErrors: true,
    });
  } catch (_) {
    return null;
  }
}

function createTelemetryService({ vscode, context = null, endpoint = '', transport = null } = {}) {
  const activeTransport = transport || createTelemetryTransport({ endpoint });
  const subscriptions = [];
  let disposed = false;
  const logger = createLogger(vscode, activeTransport);

  function isProductTelemetryEnabled() {
    try {
      return vscode?.workspace?.getConfiguration?.('pileOuFace')?.get?.('telemetry.enabled', true) === true;
    } catch (_) {
      return false;
    }
  }

  function isEnabled() {
    return !disposed
      && vscode?.env?.isTelemetryEnabled === true
      && isProductTelemetryEnabled()
      && Boolean(logger)
      && activeTransport.isConfigured?.() === true;
  }

  function trackEvent(eventName, properties = {}) {
    if (!isEnabled()) return false;
    const sanitized = sanitizeTelemetryEvent(eventName, properties);
    if (!sanitized.ok) return false;
    try {
      logger.logUsage(sanitized.event.eventName, sanitized.event.properties);
      return true;
    } catch (_) {
      return false;
    }
  }

  function trackOperation(eventName, properties = {}) {
    return trackEvent(eventName, properties);
  }

  function trackFailure(eventName, properties = {}) {
    return trackEvent(eventName, properties);
  }

  function handleEnablementChange() {
    if (!isEnabled()) activeTransport.abortInFlight?.();
  }

  if (typeof vscode?.env?.onDidChangeTelemetryEnabled === 'function') {
    subscriptions.push(vscode.env.onDidChangeTelemetryEnabled(handleEnablementChange));
  }
  if (typeof vscode?.workspace?.onDidChangeConfiguration === 'function') {
    subscriptions.push(vscode.workspace.onDidChangeConfiguration((event) => {
      if (event?.affectsConfiguration?.('pileOuFace.telemetry.enabled')) handleEnablementChange();
    }));
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    subscriptions.forEach((subscription) => subscription?.dispose?.());
    logger?.dispose?.();
    activeTransport.dispose?.();
  }

  const service = {
    dispose,
    isEnabled,
    trackEvent,
    trackFailure,
    trackOperation,
  };
  context?.subscriptions?.push?.(service);
  return service;
}

function durationBucket(durationMs) {
  const value = Number(durationMs);
  if (!Number.isFinite(value) || value < 1000) return '<1s';
  if (value < 5000) return '1-5s';
  if (value < 15000) return '5-15s';
  if (value < 60000) return '15-60s';
  return '>60s';
}

module.exports = { createTelemetryService, durationBucket };
