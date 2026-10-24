// SPDX-License-Identifier: AGPL-3.0-only
const { sanitizeTelemetryEvent } = require('./telemetrySanitizer');
const { createTelemetryTransport } = require('./telemetryTransport');
const { EVENT_NAMES } = require('./telemetryEvents');
const { mapPlatform } = require('./telemetryMappings');

function normalizeTelemetryEventName(eventName, extensionId) {
  if (typeof eventName !== 'string' || typeof extensionId !== 'string' || extensionId.length === 0) {
    return eventName;
  }
  const expectedPrefix = `${extensionId}/`;
  return eventName.startsWith(expectedPrefix) ? eventName.slice(expectedPrefix.length) : eventName;
}

function createSender(activeTransport, reportDiagnostic, extensionId) {
  return {
    sendEventData(eventName, data) {
      const canonicalEventName = normalizeTelemetryEventName(eventName, extensionId);
      const sanitized = sanitizeTelemetryEvent(canonicalEventName, data || {});
      if (!sanitized.ok) {
        reportDiagnostic('rejected');
        return;
      }
      try {
        const pending = activeTransport.sendBody(sanitized.body);
        pending?.catch?.(() => reportDiagnostic('failed'));
      } catch (_) {
        reportDiagnostic('failed');
      }
    },
    sendErrorData() {},
    flush() {},
  };
}

function createLogger(vscode, activeTransport, reportDiagnostic, extensionId) {
  if (!vscode?.env?.createTelemetryLogger || !activeTransport.isConfigured?.()) return null;
  try {
    return vscode.env.createTelemetryLogger(createSender(activeTransport, reportDiagnostic, extensionId), {
      ignoreBuiltInCommonProperties: true,
      ignoreUnhandledErrors: true,
    });
  } catch (_) {
    reportDiagnostic('failed');
    return null;
  }
}

function createTelemetryService({
  vscode = null,
  context = null,
  endpoint = '',
  transport = null,
  onDiagnostic = (_status) => {},
} = {}) {
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

  const activeTransport = transport || createTelemetryTransport({ endpoint, onDiagnostic: reportDiagnostic });
  const subscriptions = [];
  let disposed = false;
  const extensionId = context?.extension?.id || '';
  const logger = createLogger(vscode, activeTransport, reportDiagnostic, extensionId);

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
      && logger.isUsageEnabled === true
      && activeTransport.isConfigured?.() === true;
  }

  function trackEvent(eventName, properties = {}) {
    if (!isEnabled()) {
      reportDiagnostic('disabled');
      return false;
    }
    const sanitized = sanitizeTelemetryEvent(eventName, properties);
    if (!sanitized.ok) {
      reportDiagnostic('rejected');
      return false;
    }
    try {
      logger.logUsage(sanitized.event.eventName, sanitized.event.properties);
      return true;
    } catch (_) {
      reportDiagnostic('failed');
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
  if (typeof logger?.onDidChangeEnableStates === 'function') {
    subscriptions.push(logger.onDidChangeEnableStates(handleEnablementChange));
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

function initializeExtensionTelemetry(options: {
  vscode?: any;
  context?: any;
  productConfig?: any;
  transport?: any;
  onDiagnostic?: (status: string) => void;
  platform?: string;
} = {}) {
  const {
    vscode,
    context,
    productConfig,
    transport = null,
    onDiagnostic,
    platform = process.platform,
  } = options;
  const telemetry = createTelemetryService({
    vscode,
    context,
    endpoint: productConfig?.telemetryProviderUrl || '',
    transport,
    onDiagnostic,
  });
  telemetry.trackEvent(EVENT_NAMES.EXTENSION_ACTIVATED, {
    extensionVersion: String(context?.extension?.packageJSON?.version || '0.0.0'),
    vscodeVersionMajor: String(vscode?.version || '0').split('.')[0],
    platform: mapPlatform(platform),
  });
  return telemetry;
}

function durationBucket(durationMs) {
  const value = Number(durationMs);
  if (!Number.isFinite(value) || value < 1000) return '<1s';
  if (value < 5000) return '1-5s';
  if (value < 15000) return '5-15s';
  if (value < 60000) return '15-60s';
  return '>60s';
}

module.exports = {
  createTelemetryService,
  durationBucket,
  initializeExtensionTelemetry,
  normalizeTelemetryEventName,
};
