// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const { durationBucket } = require('../shared/telemetry/telemetry');
const { EVENT_NAMES, ENUMS } = require('../shared/telemetry/telemetryEvents');

const FAILURE_CATEGORIES = new Set(ENUMS.errorCategory);
const TERMINATION_CATEGORIES = new Set(ENUMS.terminationCategory);
const CPU_BUCKETS = new Set(ENUMS.cpuBucket);
const RSS_BUCKETS = new Set(ENUMS.rssBucket);

function cpuBucket(cpuTimeMs) {
  if (cpuTimeMs === null || cpuTimeMs === undefined) return 'unavailable';
  const value = Number(cpuTimeMs);
  if (!Number.isFinite(value) || value < 0) return 'unavailable';
  if (value < 100) return '<100ms';
  if (value < 1000) return '100ms-1s';
  if (value < 5000) return '1-5s';
  if (value < 15000) return '5-15s';
  if (value < 60000) return '15-60s';
  return '>60s';
}

function rssBucket(peakRssBytes) {
  if (peakRssBytes === null || peakRssBytes === undefined) return 'unavailable';
  const value = Number(peakRssBytes);
  if (!Number.isFinite(value) || value < 0) return 'unavailable';
  if (value < 64 * 1024 * 1024) return '<64MiB';
  if (value < 256 * 1024 * 1024) return '64-256MiB';
  if (value < 512 * 1024 * 1024) return '256-512MiB';
  if (value < 1024 * 1024 * 1024) return '512MiB-1GiB';
  return '>1GiB';
}

function createRunTraceTelemetry({
  telemetry,
  extensionVersion = '0.0.0',
  binaryFormat = 'unknown',
  arch = 'unknown',
  payloadMode = 'builder',
  target = 'auto',
  sourceProvided = false,
  now = Date.now,
} = {}) {
  const startedProperties = Object.freeze({
    extensionVersion,
    binaryFormat,
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

  function complete({
    terminationCategory = 'normal',
    cpuBucket: observedCpuBucket = 'unavailable',
    rssBucket: observedRssBucket = 'unavailable',
  } = {}) {
    if (outcome) return false;
    outcome = 'completed';
    telemetry?.trackOperation?.(EVENT_NAMES.RUN_TRACE_COMPLETED, {
      extensionVersion,
      binaryFormat,
      arch,
      payloadMode,
      durationBucket: elapsedBucket(),
      terminationCategory: TERMINATION_CATEGORIES.has(terminationCategory)
        ? terminationCategory : 'emulator_stop',
      cpuBucket: CPU_BUCKETS.has(observedCpuBucket) ? observedCpuBucket : 'unavailable',
      rssBucket: RSS_BUCKETS.has(observedRssBucket) ? observedRssBucket : 'unavailable',
    });
    return true;
  }

  function cancel() {
    if (outcome) return false;
    outcome = 'cancelled';
    telemetry?.trackFailure?.(EVENT_NAMES.RUN_TRACE_FAILED, {
      extensionVersion,
      binaryFormat,
      arch,
      payloadMode,
      durationBucket: elapsedBucket(),
      errorCategory: 'cancelled',
      cpuBucket: 'unavailable',
      rssBucket: 'unavailable',
    });
    return true;
  }

  function fail(errorCategory = 'unknown', {
    cpuBucket: observedCpuBucket = 'unavailable',
    rssBucket: observedRssBucket = 'unavailable',
  } = {}) {
    if (outcome) return false;
    outcome = 'failed';
    telemetry?.trackFailure?.(EVENT_NAMES.RUN_TRACE_FAILED, {
      extensionVersion,
      binaryFormat,
      arch,
      payloadMode,
      durationBucket: elapsedBucket(),
      errorCategory: FAILURE_CATEGORIES.has(errorCategory) ? errorCategory : 'unknown',
      cpuBucket: CPU_BUCKETS.has(observedCpuBucket) ? observedCpuBucket : 'unavailable',
      rssBucket: RSS_BUCKETS.has(observedRssBucket) ? observedRssBucket : 'unavailable',
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

module.exports = { cpuBucket, createRunTraceTelemetry, rssBucket };
