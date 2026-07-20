// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const EVENT_NAMES = Object.freeze({
  EXTENSION_ACTIVATED: 'extension.activated',
  HUB_OPENED: 'hub.opened',
  PANEL_OPENED: 'panel.opened',
  BINARY_LOADED: 'binary.loaded',
  STATIC_FEATURE_USED: 'static.feature.used',
  STATIC_INTERFACE_MODE_CHANGED: 'static.interface_mode.changed',
  PAYLOAD_MODE_USED: 'payload.mode.used',
  PAYLOAD_BUILDER_LEVEL_CHANGED: 'payload.builder_level.changed',
  RUN_TRACE_STARTED: 'dynamic.run_trace.started',
  RUN_TRACE_COMPLETED: 'dynamic.run_trace.completed',
  RUN_TRACE_FAILED: 'dynamic.run_trace.failed',
  VISUALIZER_OPENED: 'dynamic.visualizer.opened',
  STACK_MODE_CHANGED: 'dynamic.stack_mode.changed',
});

const ENUMS = Object.freeze({
  platform: Object.freeze(['windows', 'linux', 'macos', 'other']),
  panel: Object.freeze(['dashboard', 'static', 'dynamic', 'runtime', 'tools', 'settings']),
  hubState: Object.freeze(['created', 'revealed']),
  binaryFormat: Object.freeze(['elf', 'pe', 'macho', 'raw', 'unknown']),
  arch: Object.freeze(['x86', 'x64', 'arm', 'arm64', 'other', 'unknown']),
  staticFeature: Object.freeze([
    'disassembly', 'functions', 'cfg', 'call_graph', 'decompiler',
    'stack_frame', 'hex', 'script', 'binary_info', 'sections', 'imports',
    'symbols', 'strings', 'typed_data', 'search', 'pe_resources', 'exceptions',
  ]),
  staticInterfaceMode: Object.freeze(['simple', 'advanced']),
  payloadMode: Object.freeze(['builder', 'file', 'pwntools', 'exploit_helper']),
  payloadBuilderLevel: Object.freeze(['beginner', 'advanced']),
  target: Object.freeze(['stdin', 'argv1', 'both', 'file', 'auto']),
  durationBucket: Object.freeze(['<1s', '1-5s', '5-15s', '15-60s', '>60s']),
  errorCategory: Object.freeze([
    'invalid_input', 'unsupported_binary', 'compilation_failed',
    'backend_failed', 'timeout', 'unknown',
  ]),
  visualizerOrigin: Object.freeze(['fresh_run', 'history']),
  visualizerSurface: Object.freeze(['embedded', 'standalone']),
  stackMode: Object.freeze(['simple', 'expert', 'advanced']),
});

const enumProperty = (values) => Object.freeze({ type: 'enum', values, required: true });
const booleanProperty = Object.freeze({ type: 'boolean', required: true });
const versionProperty = Object.freeze({
  type: 'string',
  required: true,
  maxLength: 64,
  pattern: /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/,
});
const majorVersionProperty = Object.freeze({
  type: 'string',
  required: true,
  maxLength: 3,
  pattern: /^\d{1,3}$/,
});

const EVENT_SCHEMAS = Object.freeze({
  [EVENT_NAMES.EXTENSION_ACTIVATED]: Object.freeze({
    extensionVersion: versionProperty,
    vscodeVersionMajor: majorVersionProperty,
    platform: enumProperty(ENUMS.platform),
  }),
  [EVENT_NAMES.HUB_OPENED]: Object.freeze({
    state: enumProperty(ENUMS.hubState),
    initialPanel: enumProperty(ENUMS.panel),
  }),
  [EVENT_NAMES.PANEL_OPENED]: Object.freeze({
    panel: enumProperty(ENUMS.panel),
  }),
  [EVENT_NAMES.BINARY_LOADED]: Object.freeze({
    binaryFormat: enumProperty(ENUMS.binaryFormat),
    arch: enumProperty(ENUMS.arch),
  }),
  [EVENT_NAMES.STATIC_FEATURE_USED]: Object.freeze({
    feature: enumProperty(ENUMS.staticFeature),
  }),
  [EVENT_NAMES.STATIC_INTERFACE_MODE_CHANGED]: Object.freeze({
    mode: enumProperty(ENUMS.staticInterfaceMode),
  }),
  [EVENT_NAMES.PAYLOAD_MODE_USED]: Object.freeze({
    payloadMode: enumProperty(ENUMS.payloadMode),
  }),
  [EVENT_NAMES.PAYLOAD_BUILDER_LEVEL_CHANGED]: Object.freeze({
    level: enumProperty(ENUMS.payloadBuilderLevel),
  }),
  [EVENT_NAMES.RUN_TRACE_STARTED]: Object.freeze({
    arch: enumProperty(ENUMS.arch),
    payloadMode: enumProperty(ENUMS.payloadMode),
    target: enumProperty(ENUMS.target),
    sourceProvided: booleanProperty,
  }),
  [EVENT_NAMES.RUN_TRACE_COMPLETED]: Object.freeze({
    payloadMode: enumProperty(ENUMS.payloadMode),
    durationBucket: enumProperty(ENUMS.durationBucket),
    crashDetected: booleanProperty,
  }),
  [EVENT_NAMES.RUN_TRACE_FAILED]: Object.freeze({
    payloadMode: enumProperty(ENUMS.payloadMode),
    durationBucket: enumProperty(ENUMS.durationBucket),
    errorCategory: enumProperty(ENUMS.errorCategory),
  }),
  [EVENT_NAMES.VISUALIZER_OPENED]: Object.freeze({
    origin: enumProperty(ENUMS.visualizerOrigin),
    surface: enumProperty(ENUMS.visualizerSurface),
  }),
  [EVENT_NAMES.STACK_MODE_CHANGED]: Object.freeze({
    stackMode: enumProperty(ENUMS.stackMode),
    surface: enumProperty(ENUMS.visualizerSurface),
  }),
});

module.exports = { ENUMS, EVENT_NAMES, EVENT_SCHEMAS };
