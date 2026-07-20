// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

function createTelemetryHandlers(telemetry) {
  return {
    'pof.telemetry': async (message) => {
      telemetry?.trackEvent?.(message?.eventName, message?.properties);
    },
  };
}

module.exports = { createTelemetryHandlers };
