const { expect } = require('chai');

const { EVENT_NAMES, EVENT_SCHEMAS } = require('../shared/telemetry/telemetryEvents');
const { validateTelemetryEvent } = require('../shared/telemetry/telemetrySchema');
const { sanitizeTelemetryEvent } = require('../shared/telemetry/telemetrySanitizer');

const VALID_EVENTS = Object.freeze({
  [EVENT_NAMES.EXTENSION_ACTIVATED]: {
    extensionVersion: '0.2.0', vscodeVersionMajor: '120', platform: 'linux',
  },
  [EVENT_NAMES.HUB_OPENED]: { state: 'created', initialPanel: 'dashboard' },
  [EVENT_NAMES.PANEL_OPENED]: { panel: 'static' },
  [EVENT_NAMES.BINARY_LOADED]: { binaryFormat: 'elf', arch: 'x64' },
  [EVENT_NAMES.STATIC_FEATURE_USED]: { feature: 'disassembly' },
  [EVENT_NAMES.STATIC_INTERFACE_MODE_CHANGED]: { mode: 'simple' },
  [EVENT_NAMES.PAYLOAD_MODE_USED]: { payloadMode: 'builder' },
  [EVENT_NAMES.PAYLOAD_BUILDER_LEVEL_CHANGED]: { level: 'beginner' },
  [EVENT_NAMES.RUN_TRACE_STARTED]: {
    arch: 'x64', payloadMode: 'builder', target: 'stdin', sourceProvided: false,
  },
  [EVENT_NAMES.RUN_TRACE_COMPLETED]: {
    payloadMode: 'builder', durationBucket: '1-5s', crashDetected: false,
  },
  [EVENT_NAMES.RUN_TRACE_FAILED]: {
    payloadMode: 'builder', durationBucket: '<1s', errorCategory: 'invalid_input',
  },
  [EVENT_NAMES.VISUALIZER_OPENED]: { origin: 'fresh_run', surface: 'embedded' },
  [EVENT_NAMES.STACK_MODE_CHANGED]: { stackMode: 'simple', surface: 'embedded' },
});

const SENSITIVE_VALUES = Object.freeze([
  '/home/alice/challenge',
  'C:\\Users\\Alice\\exploit.exe',
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  'p64(0x401234)',
  '0x7fffffffe000',
  'int main(void) { return 0; }',
  '4141414142424242',
]);

describe('privacy telemetry schema', () => {
  it('contains exactly the validated V1 registry', () => {
    expect(Object.keys(EVENT_SCHEMAS)).to.have.length(13);
    expect(Object.keys(EVENT_SCHEMAS)).to.have.members(Object.values(EVENT_NAMES));
    expect(EVENT_SCHEMAS).to.not.have.property('dynamic.history.opened');
  });

  for (const [eventName, properties] of Object.entries(VALID_EVENTS)) {
    it(`accepts ${eventName} with its exact schema`, () => {
      expect(validateTelemetryEvent(eventName, properties)).to.deep.equal({ ok: true });
    });
  }

  it('rejects unknown events and unknown properties', () => {
    expect(validateTelemetryEvent('dynamic.history.opened', {})).to.include({ ok: false, reason: 'unknown_event' });
    expect(validateTelemetryEvent(EVENT_NAMES.PANEL_OPENED, {
      panel: 'static', path: '/home/alice/challenge',
    })).to.include({ ok: false, reason: 'unknown_property' });
  });

  it('rejects missing properties, wrong types, and values outside enums', () => {
    expect(validateTelemetryEvent(EVENT_NAMES.PANEL_OPENED, {})).to.include({ ok: false, reason: 'missing_property' });
    expect(validateTelemetryEvent(EVENT_NAMES.PANEL_OPENED, { panel: 1 })).to.include({ ok: false, reason: 'invalid_type' });
    expect(validateTelemetryEvent(EVENT_NAMES.PANEL_OPENED, { panel: 'account' })).to.include({ ok: false, reason: 'invalid_value' });
    expect(validateTelemetryEvent(EVENT_NAMES.RUN_TRACE_FAILED, {
      ...VALID_EVENTS[EVENT_NAMES.RUN_TRACE_FAILED],
      errorCategory: 'cancelled',
    })).to.include({ ok: false, reason: 'invalid_value' });
  });

  it('never accepts the sensitive corpus as an extra property', () => {
    for (const [eventName, properties] of Object.entries(VALID_EVENTS)) {
      for (const sensitive of SENSITIVE_VALUES) {
        const result = sanitizeTelemetryEvent(eventName, { ...properties, detail: sensitive });
        expect(result.ok, `${eventName} accepted ${sensitive}`).to.equal(false);
      }
    }
  });

  it('never accepts sensitive strings in controlled string properties', () => {
    for (const [eventName, properties] of Object.entries(VALID_EVENTS)) {
      for (const [key, value] of Object.entries(properties)) {
        if (typeof value !== 'string') continue;
        for (const sensitive of SENSITIVE_VALUES) {
          const result = sanitizeTelemetryEvent(eventName, { ...properties, [key]: sensitive });
          expect(result.ok, `${eventName}.${key} accepted ${sensitive}`).to.equal(false);
        }
      }
    }
  });
});

module.exports = { VALID_EVENTS };
