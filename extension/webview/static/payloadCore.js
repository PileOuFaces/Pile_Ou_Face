// @ts-nocheck
/* global module, TextEncoder */

/**
 * @typedef {{ sourcePath?: string, sourceEnrichmentEnabled?: boolean, sourceEnrichmentStatus?: string, sourceEnrichmentMessage?: string }} SourceHintOptions
 * @typedef {{ hex?: string, data?: number[] | Uint8Array | string }} CaptureEntry
 * @typedef {{ bytes: number, preview: string }} PayloadExpressionPreview
 */

(function initHubPayloadCore(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.POFHubPayloadCore = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function buildHubPayloadCore() {
  /**
   * @param {SourceHintOptions} [options]
   * @returns {string}
   */
  function buildSourceHintText({
    sourcePath = '',
    sourceEnrichmentEnabled = false,
    sourceEnrichmentStatus = '',
    sourceEnrichmentMessage = ''
  } = {}) {
    const normalizedPath = String(sourcePath || '').trim();
    const message = String(sourceEnrichmentMessage || '').trim();
    const status = String(sourceEnrichmentStatus || '').trim();

    if (normalizedPath && message) return message;
    if (sourceEnrichmentEnabled && normalizedPath) return 'Code source détecté — analyse enrichie activée.';
    if (normalizedPath && status === 'missing') return 'Code source fourni introuvable ; analyse binaire seule.';
    if (normalizedPath) return `Code source sélectionné — enrichissement prêt au prochain run.`;
    return 'Pour une meilleure analyse, ajoutez le code source C du programme.';
  }

  /**
   * @param {string | null | undefined} value
   * @returns {'auto' | 'argv1' | 'stdin' | 'both'}
   */
  function normalizePayloadTargetMode(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return ['auto', 'argv1', 'stdin', 'both'].includes(normalized) ? normalized : 'auto';
  }

  /**
   * @param {string | null | undefined} value
   * @returns {'argv1' | 'stdin' | 'both'}
   */
  function normalizeEffectiveTarget(value) {
    const normalized = String(value || '').trim().toLowerCase();
    return ['argv1', 'stdin', 'both'].includes(normalized) ? normalized : 'argv1';
  }

  /**
   * @param {string | null | undefined} target
   * @returns {string}
   */
  function payloadTargetLabel(target) {
    const normalized = normalizeEffectiveTarget(target);
    if (normalized === 'stdin') return 'stdin';
    if (normalized === 'both') return 'stdin + argv[1]';
    return 'argv[1]';
  }

  /**
   * @param {string | null | undefined} input
   * @returns {PayloadExpressionPreview}
   */
  function parsePayloadExpressionPreview(input) {
    const text = String(input || '').trim();
    if (!text) return { bytes: 0, preview: '' };
    if (!/[+*\\]/.test(text)) return { bytes: text.length, preview: text };

    const parts = text.split('+').map((part) => part.trim()).filter(Boolean);
    if (!parts.length) return { bytes: 0, preview: '' };
    let preview = '';
    let bytes = 0;
    const decodedLength = (value) => {
      let count = 0;
      for (let index = 0; index < value.length; index += 1) {
        if (value[index] === '\\' && value[index + 1] === 'x' && /^[0-9a-fA-F]{2}$/.test(value.slice(index + 2, index + 4))) {
          count += 1;
          index += 3;
        } else if (value[index] === '\\' && ['n', 'r', 't', '0', '\\'].includes(value[index + 1])) {
          count += 1;
          index += 1;
        } else {
          count += new TextEncoder().encode(value[index]).length;
        }
      }
      return count;
    };
    for (const part of parts) {
      const match = part.match(/^(.+?)\*(\d+)$/);
      if (match) {
        const count = parseInt(match[2], 10);
        if (!Number.isFinite(count) || count < 0) throw new Error('compteur invalide');
        bytes += decodedLength(match[1]) * count;
        preview += match[1].repeat(Math.min(count, 16));
      } else {
        bytes += decodedLength(part);
        preview += part;
      }
    }
    return { bytes, preview };
  }

  /**
   * @param {number[]} bytes
   * @returns {string}
   */
  function bytesToCompactHex(bytes) {
    return `0x${(Array.isArray(bytes) ? bytes : [])
      .map((value) => Number(value).toString(16).padStart(2, '0'))
      .join('')}`;
  }

  function bytesToSpacedHex(bytes) {
    return (Array.isArray(bytes) ? bytes : [])
      .map((value) => Number(value).toString(16).padStart(2, '0'))
      .join(' ');
  }

  function bytesToEscapedHex(bytes) {
    return (Array.isArray(bytes) ? bytes : [])
      .map((value) => `\\x${Number(value).toString(16).padStart(2, '0').toUpperCase()}`)
      .join('');
  }

  /**
   * @param {string | null | undefined} input
   * @returns {string}
   */
  function buildPayloadEndianHint(input) {
    const text = String(input || '').trim();
    if (!text) return '';
    const escapedDword = text.match(/(?:\\x[0-9a-fA-F]{2}){4}/);
    if (!escapedDword) return '';
    const bytes = Array.from(
      escapedDword[0].matchAll(/\\x([0-9a-fA-F]{2})/g),
      (match) => parseInt(match[1], 16)
    );
    if (bytes.length !== 4) return '';
    const littleEndianRead = [...bytes].reverse();
    const writtenHex = bytesToCompactHex(bytes);
    const readHex = bytesToCompactHex(littleEndianRead);
    if (writtenHex === readHex) return '';
    return `Endian: ${bytesToSpacedHex(bytes)} donne ${readHex} si le programme relit ce dword en little-endian. Pour viser ${writtenHex}, utilise ${bytesToEscapedHex(littleEndianRead)}.`;
  }

  /**
   * @param {string | null | undefined} mode
   * @returns {'payload_builder' | 'file' | 'exploit_helper' | 'pwntools_script'}
   */
  function normalizePayloadMode(mode) {
    const value = String(mode || '').trim().toLowerCase();
    if (value === 'simple' || value === 'python') return 'payload_builder';
    return ['payload_builder', 'file', 'exploit_helper', 'pwntools_script'].includes(value) ? value : 'payload_builder';
  }

  /**
   * @param {string | null | undefined} level
   * @param {'beginner' | 'advanced'} [fallback]
   * @returns {'beginner' | 'advanced'}
   */
  function normalizePayloadBuilderLevel(level, fallback = 'beginner') {
    const value = String(level || '').trim().toLowerCase();
    if (value === 'advanced') return 'advanced';
    if (value === 'beginner') return 'beginner';
    return fallback === 'advanced' ? 'advanced' : 'beginner';
  }

  function formatPayloadSize(size) {
    const count = Math.max(0, Number(size) || 0);
    return `${count} byte${count === 1 ? '' : 's'}`;
  }

  function byteArrayToHex(bytes) {
    return (Array.isArray(bytes) ? bytes : Array.from(bytes || []))
      .map((value) => (Number(value) & 0xff).toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToByteArray(hex) {
    const cleaned = String(hex || '').replace(/\s+/g, '').replace(/^0x/i, '').trim();
    if (!cleaned || cleaned.length % 2 !== 0) return [];
    return cleaned.match(/../g)?.map((part) => Number.parseInt(part, 16) & 0xff) || [];
  }

  /**
   * @param {CaptureEntry} entry
   * @returns {string} lowercase hex without spaces or 0x prefix
   */
  function normalizeCaptureHex(entry) {
    const fromHex = String(entry?.hex || '').replace(/\s+/g, '').replace(/^0x/i, '').trim();
    if (fromHex && /^[0-9a-f]+$/i.test(fromHex) && fromHex.length % 2 === 0) {
      return fromHex.toLowerCase();
    }
    const data = entry?.data;
    if (Array.isArray(data)) return byteArrayToHex(data);
    if (data instanceof Uint8Array) return byteArrayToHex(data);
    if (typeof data === 'string') {
      const cleaned = data.replace(/\s+/g, '').replace(/^0x/i, '').trim();
      if (cleaned && /^[0-9a-f]+$/i.test(cleaned) && cleaned.length % 2 === 0) {
        return cleaned.toLowerCase();
      }
      return byteArrayToHex(new TextEncoder().encode(data));
    }
    return '';
  }

  function hexHasNullByte(hex) {
    const cleaned = String(hex || '').replace(/\s+/g, '').replace(/^0x/i, '').trim().toLowerCase();
    return (cleaned.match(/../g) || []).includes('00');
  }

  return {
    buildPayloadEndianHint,
    buildSourceHintText,
    byteArrayToHex,
    bytesToCompactHex,
    bytesToEscapedHex,
    bytesToSpacedHex,
    formatPayloadSize,
    hexHasNullByte,
    hexToByteArray,
    normalizeCaptureHex,
    normalizeEffectiveTarget,
    normalizePayloadBuilderLevel,
    normalizePayloadMode,
    normalizePayloadTargetMode,
    parsePayloadExpressionPreview,
    payloadTargetLabel,
  };
});
