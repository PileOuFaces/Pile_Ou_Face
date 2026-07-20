// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const { EVENT_SCHEMAS } = require('./telemetryEvents');

const VALIDATION_ERRORS = Object.freeze({
  UNKNOWN_EVENT: 'unknown_event',
  INVALID_PROPERTIES: 'invalid_properties',
  UNKNOWN_PROPERTY: 'unknown_property',
  MISSING_PROPERTY: 'missing_property',
  INVALID_TYPE: 'invalid_type',
  INVALID_VALUE: 'invalid_value',
});

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateProperty(value, descriptor) {
  if (descriptor.type === 'boolean') return typeof value === 'boolean';
  if (descriptor.type === 'enum') return descriptor.values.includes(value);
  if (descriptor.type !== 'string' || typeof value !== 'string') return false;
  if (value.length > descriptor.maxLength) return false;
  return descriptor.pattern.test(value);
}

function validateTelemetryEvent(eventName, properties) {
  const schema = EVENT_SCHEMAS[eventName];
  if (!schema) return { ok: false, reason: VALIDATION_ERRORS.UNKNOWN_EVENT };
  if (!isPlainObject(properties)) {
    return { ok: false, reason: VALIDATION_ERRORS.INVALID_PROPERTIES };
  }

  const propertyKeys = Object.keys(properties);
  for (const key of propertyKeys) {
    if (!Object.prototype.hasOwnProperty.call(schema, key)) {
      return { ok: false, reason: VALIDATION_ERRORS.UNKNOWN_PROPERTY };
    }
  }

  for (const [key, descriptor] of Object.entries(schema)) {
    if (!Object.prototype.hasOwnProperty.call(properties, key)) {
      if (descriptor.required) {
        return { ok: false, reason: VALIDATION_ERRORS.MISSING_PROPERTY };
      }
      continue;
    }
    const value = properties[key];
    const expectedType = descriptor.type === 'enum' ? 'string' : descriptor.type;
    if (typeof value !== expectedType) {
      return { ok: false, reason: VALIDATION_ERRORS.INVALID_TYPE };
    }
    if (!validateProperty(value, descriptor)) {
      return { ok: false, reason: VALIDATION_ERRORS.INVALID_VALUE };
    }
  }

  return { ok: true };
}

module.exports = { VALIDATION_ERRORS, validateTelemetryEvent };
