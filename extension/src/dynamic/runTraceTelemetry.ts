// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const { durationBucket } = require('../shared/telemetry/telemetry');
const { EVENT_NAMES, ENUMS } = require('../shared/telemetry/telemetryEvents');

const FAILURE_CATEGORIES = new Set(ENUMS.errorCategory);

function createRunTraceTelemetry({
  telemetry,
  arch = 'unknown',
  payloadMode = 'builder',
  target = 'auto',
  sourceProvided = false,
  now = Date.now,
} = {}) {
  const startedProperties = Object.freeze({
    arch,
    payloadMode,
    target,
    sourceProvided: sourceProvided === true,
  });
  let startedAt = null;
  let outcome = null;

  function start() {
    if (startedAt !== null || outcome) return false;
    startedAt = now();
    telemetry?.trackOperation?.(EVENT_NAMES.RUN_TRACE_STARTED, startedProperties);
    return true;
  }

  function elapsedBucket() {
    const started = startedAt === null ? now() : startedAt;
    return durationBucket(Math.max(0, now() - started));
  }

  function complete(crashDetected = false) {
    if (outcome) return false;
    outcome = 'completed';
    telemetry?.trackOperation?.(EVENT_NAMES.RUN_TRACE_COMPLETED, {
      payloadMode,
      durationBucket: elapsedBucket(),
      crashDetected: crashDetected === true,
    });
    return true;
  }

  function cancel() {
    if (outcome) return false;
    outcome = 'cancelled';
    return true;
  }

  function fail(errorCategory = 'unknown') {
    if (outcome) return false;
    outcome = 'failed';
    telemetry?.trackFailure?.(EVENT_NAMES.RUN_TRACE_FAILED, {
      payloadMode,
      durationBucket: elapsedBucket(),
      errorCategory: FAILURE_CATEGORIES.has(errorCategory) ? errorCategory : 'unknown',
    });
    return true;
  }

  return Object.freeze({
    cancel,
    complete,
    fail,
    getOutcome: () => outcome,
    start,
  });
}

module.exports = { createRunTraceTelemetry };
