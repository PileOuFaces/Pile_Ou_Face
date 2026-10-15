/**
 * Narrow webview bridge. The Extension Host owns the authoritative schema and
 * rejects every event or property not present in the V1 registry.
 */
(function initTelemetryClient(global) {
  const STATIC_FEATURES = Object.freeze({
    disasm: 'disassembly',
    discovered: 'functions',
    cfg: 'cfg',
    callgraph: 'call_graph',
    decompile: 'decompiler',
    stack: 'stack_frame',
    hex: 'hex',
    script: 'script',
    info: 'binary_info',
    sections: 'sections',
    imports: 'imports',
    symbols: 'symbols',
    strings: 'strings',
    typed_data: 'typed_data',
    recherche: 'search',
    pe_resources: 'pe_resources',
    exceptions: 'exceptions',
  });

  function mapPanel(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'outils') return 'tools';
    if (normalized === 'options') return 'settings';
    return ['dashboard', 'static', 'dynamic', 'runtime'].includes(normalized)
      ? normalized
      : null;
  }

  function mapBinaryFormat(value) {
    const normalized = String(value || '').trim().toLowerCase().replace(/[-_\s]/g, '');
    if (['elf', 'pe', 'macho', 'raw'].includes(normalized)) return normalized;
    return 'unknown';
  }

  function mapArch(value) {
    const normalized = String(value || '').trim().toLowerCase().replace(/[-_\s]/g, '');
    if (['x8664', 'amd64', 'i386:x8664'].includes(normalized)) return 'x64';
    if (['x86', 'i386', 'i686'].includes(normalized)) return 'x86';
    if (['arm64', 'aarch64'].includes(normalized)) return 'arm64';
    if (['arm', 'arm32', 'thumb'].includes(normalized)) return 'arm';
    return normalized ? 'other' : 'unknown';
  }

  function mapPayloadMode(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'payload_builder') return 'builder';
    if (normalized === 'pwntools_script') return 'pwntools';
    return ['file', 'exploit_helper'].includes(normalized) ? normalized : null;
  }

  function mapStaticFeature(value) {
    return STATIC_FEATURES[String(value || '').trim()] || null;
  }

  function create(postMessage) {
    function trackEvent(eventName, properties) {
      if (typeof postMessage !== 'function') return false;
      if (typeof eventName !== 'string' || !eventName) return false;
      if (!properties || typeof properties !== 'object' || Array.isArray(properties)) return false;
      postMessage({ type: 'pof.telemetry', eventName, properties: { ...properties } });
      return true;
    }
    return Object.freeze({ trackEvent });
  }

  global.POFTelemetryClient = Object.freeze({
    create,
    mapArch,
    mapBinaryFormat,
    mapPanel,
    mapPayloadMode,
    mapStaticFeature,
  });
  if (global.POFHubMessageBus?.postMessage) {
    global.POFTelemetry = create((message) => global.POFHubMessageBus.postMessage(message));
  }
})(window);
