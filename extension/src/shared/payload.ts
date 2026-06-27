// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file payload.js
 * @brief Conversion payload (hex, expressions stdin).
 */

function payloadToHex(input) {
  const trimmed = input.trim();
  if (!trimmed) throw new Error('payload vide');
  const hexOnly = trimmed.replace(/\s/g, '').replace(/^0x/i, '');
  if (/^[0-9a-fA-F]+$/.test(hexOnly)) {
    if (hexOnly.length % 2 !== 0) throw new Error('nombre impair de caracteres hex');
    return hexOnly;
  }
  return parsePayloadExpressionToBuffer(trimmed).toString('hex');
}

function parseStdinExpression(input) {
  const text = input.trim();
  if (!text) return '';
  if (!/[+*]/.test(text)) return text;
  const parts = text.split('+').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) throw new Error('expression vide');
  let result = '';
  parts.forEach((part) => {
    const match = part.match(/^(.+?)\*(\d+)$/);
    if (match) {
      const count = parseInt(match[2], 10);
      if (!Number.isFinite(count) || count < 0) throw new Error(`compteur invalide: ${match[2]}`);
      result += match[1].repeat(count);
    } else {
      result += part;
    }
  });
  if (result.length > 1000000) throw new Error('payload trop long');
  return result;
}

function decodeEscapedBytes(input) {
  const text = String(input || '');
  const chunks = [];
  for (let index = 0; index < text.length; index += 1) {
    const ch = text[index];
    const next = text[index + 1];
    if (ch === '\\' && next === 'x') {
      const hex = text.slice(index + 2, index + 4);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        chunks.push(Buffer.from([parseInt(hex, 16)]));
        index += 3;
        continue;
      }
    }
    if (ch === '\\' && next) {
      const escaped = {
        n: 0x0a,
        r: 0x0d,
        t: 0x09,
        0: 0x00,
        '\\': 0x5c,
      }[next];
      if (escaped !== undefined) {
        chunks.push(Buffer.from([escaped]));
        index += 1;
        continue;
      }
    }
    chunks.push(Buffer.from(ch, 'utf8'));
  }
  return Buffer.concat(chunks);
}

function parsePayloadExpressionToBuffer(input) {
  const text = String(input || '').trim();
  if (!text) return Buffer.alloc(0);
  if (!/[+*]/.test(text)) return decodeEscapedBytes(text);
  const parts = text.split('+').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) throw new Error('expression vide');
  const buffers = [];
  parts.forEach((part) => {
    const match = part.match(/^(.+?)\*(\d+)$/);
    if (match) {
      const count = parseInt(match[2], 10);
      if (!Number.isFinite(count) || count < 0) throw new Error(`compteur invalide: ${match[2]}`);
      const chunk = decodeEscapedBytes(match[1]);
      for (let i = 0; i < count; i += 1) buffers.push(chunk);
    } else {
      buffers.push(decodeEscapedBytes(part));
    }
  });
  const result = Buffer.concat(buffers);
  if (result.length > 1000000) throw new Error('payload trop long');
  return result;
}

module.exports = { payloadToHex, parsePayloadExpressionToBuffer, parseStdinExpression };
