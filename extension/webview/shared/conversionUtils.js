// @ts-nocheck
/* global module */

(function initPwnConversionUtils(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.POFHubConversionUtils = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function buildPwnConversionUtils() {
  const UINT32_MAX = 0xffffffffn;
  const UINT64_MAX = 0xffffffffffffffffn;

  function normalizeSeparators(value) {
    return String(value || '').trim().replace(/_/g, '').replace(/\s+/g, '');
  }

  function byteToHex(byte) {
    return (Number(byte) & 0xff).toString(16).padStart(2, '0');
  }

  function bytesToHex(bytes) {
    return (Array.isArray(bytes) ? bytes : []).map(byteToHex).join('');
  }

  function bytesToEscaped(bytes) {
    return (Array.isArray(bytes) ? bytes : []).map((byte) => `\\x${byteToHex(byte)}`).join('');
  }

  function bytesToSpacedHex(bytes) {
    return (Array.isArray(bytes) ? bytes : []).map(byteToHex).join(' ');
  }

  function formatDisplayBytes(bytes, mode = 'spaced') {
    return mode === 'compact' ? bytesToHex(bytes) : bytesToSpacedHex(bytes);
  }

  function bytesToBigInt(bytes, endian = 'big') {
    const ordered = endian === 'little' ? [...bytes].reverse() : [...bytes];
    return ordered.reduce((acc, byte) => (acc << 8n) + BigInt(Number(byte) & 0xff), 0n);
  }

  function intToBytes(value, width = null, endian = 'big') {
    let n = BigInt(value || 0);
    if (n < 0n) n = 0n;
    const bytes = [];
    if (n === 0n) bytes.push(0);
    while (n > 0n) {
      bytes.unshift(Number(n & 0xffn));
      n >>= 8n;
    }
    const targetWidth = Number(width || 0);
    const normalized = targetWidth > 0
      ? bytes.slice(-targetWidth)
      : bytes;
    while (targetWidth > 0 && normalized.length < targetWidth) normalized.unshift(0);
    return endian === 'little' ? normalized.reverse() : normalized;
  }

  function asciiToBytes(value) {
    return Array.from(String(value || ''), (char) => char.charCodeAt(0) & 0xff);
  }

  function bytesToReadableAscii(bytes) {
    return (Array.isArray(bytes) ? bytes : [])
      .map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.'))
      .join('');
  }

  function parseEscapedBytes(input) {
    const matches = Array.from(String(input || '').matchAll(/\\x([0-9a-fA-F]{2})/g));
    if (!matches.length) return null;
    const stripped = String(input || '').replace(/\\x[0-9a-fA-F]{2}/g, '').replace(/\s+/g, '');
    if (stripped) return null;
    return matches.map((match) => parseInt(match[1], 16));
  }

  function parseSpacedBytes(input) {
    const tokens = String(input || '').trim().split(/[\s_]+/).filter(Boolean);
    if (tokens.length <= 1) return null;
    if (!tokens.every((token) => /^[0-9a-fA-F]{2}$/.test(token))) return null;
    return tokens.map((token) => parseInt(token, 16));
  }

  function parseHexBytes(input) {
    let cleaned = normalizeSeparators(input).replace(/^0x/i, '');
    if (!cleaned || !/^[0-9a-fA-F]+$/.test(cleaned)) return null;
    const warnings = [];
    if (cleaned.length % 2 !== 0) {
      cleaned = `0${cleaned}`;
      warnings.push('hex impair, padding proposé');
    }
    return {
      bytes: cleaned.match(/../g).map((part) => parseInt(part, 16)),
      warnings,
    };
  }

  function shouldTreatAsAscii(input) {
    const text = String(input || '');
    if (!text) return false;
    if (/^0x/i.test(text.trim())) return false;
    if (/\\x[0-9a-fA-F]{2}/.test(text)) return false;
    if (/[\x00-\x08\x0e-\x1f\x7f]/.test(text)) return false;
    if (/[\s_]+/.test(text.trim()) && parseSpacedBytes(text)) return false;
    if (/^[A-F]{2,8}$/.test(text.trim())) return true;
    return !/^[0-9a-fA-F\s_]+$/.test(text.trim());
  }

  function inferRawHexValue(bytes, warnings) {
    if ((bytes.length === 4 || bytes.length === 8) && !warnings.includes('endianness ambiguous')) {
      warnings.push('endianness ambiguous');
    }
    if (bytes.length === 8 && bytes.slice(3).every((byte) => byte === 0) && bytes.slice(0, 3).some((byte) => byte !== 0)) {
      return bytesToBigInt(bytes, 'little');
    }
    return bytesToBigInt(bytes, 'big');
  }

  function parseConversionInput(input) {
    const raw = String(input || '').trim();
    const warnings = [];
    if (!raw) {
      return { ok: false, error: 'Entrée vide', warnings: [], inputKind: 'empty', bytes: [], value: 0n };
    }

    const escaped = parseEscapedBytes(raw);
    if (escaped) {
      if ((escaped.length === 4 || escaped.length === 8)) warnings.push('endianness ambiguous');
      const value = escaped.length === 8 && escaped.slice(3).every((byte) => byte === 0)
        ? bytesToBigInt(escaped, 'little')
        : bytesToBigInt(escaped, 'big');
      return { ok: true, inputKind: 'escaped', bytes: escaped, value, warnings };
    }

    const spaced = parseSpacedBytes(raw);
    if (spaced) {
      if ((spaced.length === 4 || spaced.length === 8)) warnings.push('endianness ambiguous');
      return { ok: true, inputKind: 'little-bytes', bytes: spaced, value: bytesToBigInt(spaced, 'little'), warnings };
    }

    if (/^0x/i.test(raw.trim())) {
      const parsed = parseHexBytes(raw);
      if (!parsed) return { ok: false, error: 'Hex invalide', warnings: [], inputKind: 'invalid', bytes: [], value: 0n };
      warnings.push(...parsed.warnings);
      return { ok: true, inputKind: 'hex', bytes: parsed.bytes, value: bytesToBigInt(parsed.bytes, 'big'), warnings };
    }

    if (shouldTreatAsAscii(raw)) {
      const bytes = asciiToBytes(raw);
      const hasNonPrintable = bytes.some((byte) => byte < 0x20 || byte > 0x7e);
      if (hasNonPrintable) warnings.push('ASCII contient des bytes non imprimables');
      if ((bytes.length === 4 || bytes.length === 8)) warnings.push('endianness ambiguous');
      return { ok: true, inputKind: 'ascii', bytes, value: bytesToBigInt(bytes, 'big'), warnings };
    }

    const compact = normalizeSeparators(raw);
    const decimalLike = /^[0-9]+$/.test(compact);
    const hexLike = /^[0-9a-fA-F]+$/.test(compact);
    const numericRawHex = decimalLike && compact.length % 2 === 0 && compact.length >= 4 && compact.length !== 10;
    if (decimalLike && !numericRawHex) {
      const value = BigInt(compact);
      return { ok: true, inputKind: 'decimal', bytes: intToBytes(value, null, 'big'), value, warnings };
    }
    if (hexLike) {
      const parsed = parseHexBytes(raw);
      warnings.push(...parsed.warnings);
      return { ok: true, inputKind: 'hex-bytes', bytes: parsed.bytes, value: inferRawHexValue(parsed.bytes, warnings), warnings };
    }

    return { ok: false, error: 'Format non reconnu', warnings: [], inputKind: 'invalid', bytes: [], value: 0n };
  }

  function pythonBytes(bytes) {
    return `b'${bytesToEscaped(bytes)}'`;
  }

  function toSigned(value, bits) {
    const width = BigInt(bits);
    const modulo = 1n << width;
    const signBit = 1n << (width - 1n);
    const masked = BigInt(value || 0) & (modulo - 1n);
    return masked >= signBit ? masked - modulo : masked;
  }

  function buildRecommendation(value, usefulBytes) {
    const fits32 = value <= UINT32_MAX;
    const fits64 = value <= UINT64_MAX;
    if (!fits64) return 'hors p64';
    if (!fits32) return 'p64 recommandé';
    if (usefulBytes > 4) return 'p64 recommandé';
    return 'p32 ou p64 selon cible';
  }

  function buildHexdump(bytes, limit = 64) {
    const normalized = Array.isArray(bytes) ? bytes.map((byte) => Number(byte) & 0xff) : [];
    const visible = normalized.slice(0, limit);
    const lines = [];
    for (let offset = 0; offset < visible.length; offset += 8) {
      const chunk = visible.slice(offset, offset + 8);
      const hex = bytesToSpacedHex(chunk).padEnd(23, ' ');
      const ascii = bytesToReadableAscii(chunk);
      lines.push(`${offset.toString(16).padStart(4, '0')}  ${hex}  ${ascii}`);
    }
    if (normalized.length > limit) lines.push(`... ${normalized.length - limit} byte(s) masqué(s)`);
    return lines.join('\n') || '—';
  }

  function uniqueWarnings(warnings) {
    return Array.from(new Set((warnings || []).filter(Boolean)));
  }

  function convertPwnValue(input) {
    const parsed = parseConversionInput(input);
    if (!parsed.ok) {
      return {
        ok: false,
        error: parsed.error,
        warnings: parsed.warnings,
        inputKind: parsed.inputKind,
        outputs: {},
      };
    }

    const warnings = [...parsed.warnings];
    if (parsed.value > UINT64_MAX) warnings.push('valeur > 64-bit');
    if (parsed.bytes.some((byte) => byte < 0x20 || byte > 0x7e)) warnings.push('ASCII contient des bytes non imprimables');
    const valueHex = `0x${parsed.value.toString(16)}`;
    const le32 = intToBytes(parsed.value, 4, 'little');
    const le64 = intToBytes(parsed.value, 8, 'little');
    const be32 = intToBytes(parsed.value, 4, 'big');
    const be64 = intToBytes(parsed.value, 8, 'big');
    const usefulBytes = parsed.bytes.length;

    return {
      ok: true,
      inputKind: parsed.inputKind,
      value: parsed.value,
      bytes: parsed.bytes,
      warnings: uniqueWarnings(warnings),
      byteFields: {
        little32: le32,
        little64: le64,
        big32: be32,
        big64: be64,
      },
      meta: {
        usefulBytes,
        fits32: parsed.value <= UINT32_MAX,
        fits64: parsed.value <= UINT64_MAX,
        recommendation: buildRecommendation(parsed.value, usefulBytes),
      },
      outputs: {
        hex: valueHex,
        decimal: parsed.value.toString(10),
        ascii: bytesToReadableAscii(parsed.bytes),
        escaped: bytesToEscaped(parsed.bytes),
        little32: bytesToSpacedHex(le32),
        little64: bytesToSpacedHex(le64),
        big32: bytesToSpacedHex(be32),
        big64: bytesToSpacedHex(be64),
        p32: `p32(${valueHex})`,
        p64: `p64(${valueHex})`,
        u32: `u32(${pythonBytes(le32)})`,
        u64: `u64(${pythonBytes(le64)})`,
        unsigned32: (parsed.value & UINT32_MAX).toString(10),
        signed32: toSigned(parsed.value, 32).toString(10),
        unsigned64: (parsed.value & UINT64_MAX).toString(10),
        signed64: toSigned(parsed.value, 64).toString(10),
        hexdump: buildHexdump(parsed.bytes),
      },
    };
  }

  return {
    bytesToEscaped,
    bytesToHex,
    bytesToReadableAscii,
    bytesToSpacedHex,
    buildHexdump,
    convertPwnValue,
    formatDisplayBytes,
    intToBytes,
    parseConversionInput,
  };
});
