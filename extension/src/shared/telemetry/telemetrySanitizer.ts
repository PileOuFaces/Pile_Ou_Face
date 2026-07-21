// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const { validateTelemetryEvent } = require('./telemetrySchema');

const TELEMETRY_SCHEMA_VERSION = 1;
const MAX_TELEMETRY_BODY_BYTES = 4 * 1024;

function sanitizeTelemetryEvent(eventName, properties) {
  const validation = validateTelemetryEvent(eventName, properties);
  if (!validation.ok) return validation;

  const event = {
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    eventName,
    properties: { ...properties },
  };
  const body = JSON.stringify(event);
  if (Buffer.byteLength(body, 'utf8') > MAX_TELEMETRY_BODY_BYTES) {
    return { ok: false, reason: 'body_too_large' };
  }
  return { ok: true, event, body };
}

module.exports = {
  MAX_TELEMETRY_BODY_BYTES,
  TELEMETRY_SCHEMA_VERSION,
  sanitizeTelemetryEvent,
};
