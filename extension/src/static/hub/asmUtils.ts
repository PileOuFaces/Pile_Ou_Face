// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file hub/asmUtils.js
 * @brief Utilitaires purs d'analyse ASM : parsing d'adresses, d'instructions CMP,
 *        d'offsets stack, et suggestion de payload automatique.
 *
 * Aucune dépendance sur l'état du hub — toutes les fonctions sont pures.
 */

const parseIntLiteral = (raw) => {
  const text = String(raw || '').trim().toLowerCase();
  if (!text) return null;
  const sign = text.startsWith('-') ? -1 : 1;
  const body = text.replace(/^[-+]/, '');
  if (/^0x[0-9a-f]+$/.test(body)) return sign * parseInt(body.slice(2), 16);
  if (/^\d+$/.test(body)) return sign * parseInt(body, 10);
  return null;
};

const parseBigIntLiteral = (raw) => {
  const text = String(raw || '').trim().toLowerCase();
  if (!text) return null;
  const neg = text.startsWith('-');
  const body = text.replace(/^[-+]/, '');
  if (/^0x[0-9a-f]+$/.test(body)) {
    const val = BigInt(`0x${body.slice(2)}`);
    return neg ? -val : val;
  }
  if (/^\d+$/.test(body)) {
    const val = BigInt(body);
    return neg ? -val : val;
  }
  return null;
};

const extractAsm = (text) => {
  const raw = String(text || '');
  const tab = raw.indexOf('\t');
  const asm = tab >= 0 ? raw.slice(tab + 1) : raw;
  return asm.trim().replace(/\s+/g, ' ');
};

const normalizeAddress = (addrText) => {
  const value = String(addrText || '').trim();
  if (!value) return null;
  const norm = value.toLowerCase().startsWith('0x') ? value : `0x${value}`;
  const parsed = parseInt(norm, 16);
  if (!Number.isFinite(parsed)) return null;
  return { norm: `0x${parsed.toString(16)}`, value: parsed };
};

const extractFrameOffset = (operand) => {
  const op = String(operand || '').toLowerCase();
  const mem = op.match(/\[(?:r|e)bp(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\]/i);
  if (!mem) return null;
  if (!mem[1]) return 0;
  const delta = parseIntLiteral(mem[2]);
  if (delta === null) return null;
  return mem[1] === '-' ? -Math.abs(delta) : Math.abs(delta);
};

const regWidthBytes = (regName) => {
  const reg = String(regName || '').toLowerCase();
  if (/^(al|ah|bl|bh|cl|ch|dl|dh|sil|dil|spl|bpl|r\d+b)$/.test(reg)) return 1;
  if (/^(ax|bx|cx|dx|si|di|sp|bp|r\d+w)$/.test(reg)) return 2;
  if (/^(eax|ebx|ecx|edx|esi|edi|esp|ebp|eip|r\d+d)$/.test(reg)) return 4;
  if (/^(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|rip|r\d+)$/.test(reg)) return 8;
  return null;
};

const parseCmpInfo = (asmText) => {
  const cmp = asmText.match(/^cmp\s+(.+?),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$/i);
  if (!cmp) return null;
  const lhs = cmp[1].trim();
  const rhsToken = cmp[2].trim();
  const rhsValue = parseBigIntLiteral(rhsToken);
  if (rhsValue === null) return null;

  let width = null;
  if (/\bbyte ptr\b/i.test(lhs)) width = 1;
  else if (/\bword ptr\b/i.test(lhs) && !/\bdword ptr\b/i.test(lhs) && !/\bqword ptr\b/i.test(lhs)) width = 2;
  else if (/\bdword ptr\b/i.test(lhs)) width = 4;
  else if (/\bqword ptr\b/i.test(lhs)) width = 8;
  else if (/^[a-z][a-z0-9]*$/i.test(lhs)) width = regWidthBytes(lhs);
  if (!width) return null;

  return {
    lhs,
    rhsToken,
    rhsValue,
    width,
    lhsReg: /^[a-z][a-z0-9]*$/i.test(lhs) ? lhs.toLowerCase() : null,
  };
};

const normalizeCalleeName = (rawName) => {
  if (!rawName) return null;
  let name = String(rawName).trim();
  name = name.replace(/@.*/, '');
  name = name.replace(/^__isoc99_/, '');
  name = name.replace(/^__GI_/, '');
  return name;
};

const detectArchBitsFromLines = (lines) => {
  const scanCount = Math.min(lines.length, 500);
  for (let i = 0; i < scanCount; i += 1) {
    const asm = extractAsm(lines[i]?.text || '').toLowerCase();
    if (/\br(?:ax|bx|cx|dx|si|di|sp|bp|8|9|10|11|12|13|14|15)\b/.test(asm)) return 64;
    if (/\b(?:ebp|esp|eip|eax|ebx|ecx|edx|esi|edi)\b/.test(asm)) return 32;
  }
  return 64;
};

const collectRegOffsets = (lines, fromIdx, toIdx) => {
  const map = {};
  for (let i = fromIdx; i <= toIdx; i += 1) {
    const asm = extractAsm(lines[i]?.text || '');
    let m = asm.match(/^lea\s+([a-z0-9]+)\s*,\s*(?:[a-z]+\s+ptr\s+)?(\[[^\]]+\])$/i);
    if (m) {
      const reg = m[1].toLowerCase();
      const off = extractFrameOffset(m[2]);
      if (off !== null) map[reg] = off;
      continue;
    }
    m = asm.match(/^mov\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)$/i);
    if (m) {
      const dst = m[1].toLowerCase();
      const src = m[2].toLowerCase();
      if (Object.prototype.hasOwnProperty.call(map, src)) map[dst] = map[src];
      continue;
    }
    m = asm.match(/^mov\s+([a-z0-9]+)\s*,\s*(?:0x[0-9a-f]+|\d+)$/i);
    if (m) {
      delete map[m[1].toLowerCase()];
      continue;
    }
    m = asm.match(/^xor\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)$/i);
    if (m && m[1].toLowerCase() === m[2].toLowerCase()) delete map[m[1].toLowerCase()];
  }
  return map;
};

const buildCmpPayloadSuggestion = (lines, cmpAddrInput) => {
  const addr = normalizeAddress(cmpAddrInput);
  if (!addr) throw new Error('Adresse CMP invalide (ex: 0x4011c7).');
  const cmpIndex = lines.findIndex((l) => normalizeAddress(l?.addr || '')?.value === addr.value);
  if (cmpIndex < 0) throw new Error(`Adresse ${addr.norm} absente du désassemblage.`);
  const cmpAsm = extractAsm(lines[cmpIndex]?.text || '');
  const cmpInfo = parseCmpInfo(cmpAsm);
  if (!cmpInfo) throw new Error(`Instruction non supportée à ${addr.norm}: ${cmpAsm}`);

  let varOffset = extractFrameOffset(cmpInfo.lhs);
  if (varOffset === null && cmpInfo.lhsReg) {
    const tracked = new Set([cmpInfo.lhsReg]);
    for (let i = cmpIndex - 1; i >= Math.max(0, cmpIndex - 90); i -= 1) {
      const asm = extractAsm(lines[i]?.text || '');
      const regs = Array.from(tracked);
      for (const reg of regs) {
        const memRead = asm.match(new RegExp(`^(?:mov|movzx|movsxd)\\s+${reg}\\s*,\\s*(?:[a-z]+\\s+ptr\\s+)?(\\[[^\\]]+\\])$`, 'i'));
        if (memRead) {
          const off = extractFrameOffset(memRead[1]);
          if (off !== null) {
            varOffset = off;
            break;
          }
        }
        const alias = asm.match(new RegExp(`^mov\\s+${reg}\\s*,\\s*([a-z0-9]+)$`, 'i'));
        if (alias) tracked.add(alias[1].toLowerCase());
      }
      if (varOffset !== null) break;
    }
  }

  const archBits = detectArchBitsFromLines(lines);
  const vulnCalls = new Set(['strcpy', 'strncpy', 'memcpy', 'memmove', 'gets', 'fgets', 'read', 'scanf', 'sscanf', 'sprintf', 'snprintf']);
  let bufferOffset = null;
  let sourceCall = null;

  for (let i = cmpIndex - 1; i >= Math.max(0, cmpIndex - 140); i -= 1) {
    const asm = extractAsm(lines[i]?.text || '');
    if (!/^call\s+/i.test(asm)) continue;
    const calleeMatch = asm.match(/<([^>]+)>/);
    const callee = normalizeCalleeName(calleeMatch ? calleeMatch[1] : null);
    if (!callee || !vulnCalls.has(callee)) continue;

    const winStart = Math.max(0, i - 16);
    const regOffsets = collectRegOffsets(lines, winStart, i - 1);
    if (archBits === 64) {
      const argReg = callee === 'read' ? 'rsi' : 'rdi';
      if (Object.prototype.hasOwnProperty.call(regOffsets, argReg)) {
        bufferOffset = regOffsets[argReg];
        sourceCall = callee;
        break;
      }
    } else {
      const pushes = [];
      for (let j = i - 1; j >= winStart; j -= 1) {
        const pushAsm = extractAsm(lines[j]?.text || '');
        const pushMatch = pushAsm.match(/^push\s+(.+)$/i);
        if (pushMatch) pushes.push(pushMatch[1].trim());
      }
      if (pushes.length) {
        const arg1 = pushes[0];
        const direct = extractFrameOffset(arg1);
        if (direct !== null) {
          bufferOffset = direct;
          sourceCall = callee;
          break;
        }
        const regName = arg1.toLowerCase();
        if (Object.prototype.hasOwnProperty.call(regOffsets, regName)) {
          bufferOffset = regOffsets[regName];
          sourceCall = callee;
          break;
        }
      }
    }
  }

  if (bufferOffset === null) {
    let best = null;
    for (let i = cmpIndex - 1; i >= Math.max(0, cmpIndex - 120); i -= 1) {
      const asm = extractAsm(lines[i]?.text || '');
      const lea = asm.match(/^lea\s+[a-z0-9]+\s*,\s*(?:[a-z]+\s+ptr\s+)?(\[[^\]]+\])$/i);
      if (!lea) continue;
      const off = extractFrameOffset(lea[1]);
      if (off === null) continue;
      if (varOffset !== null && off === varOffset) continue;
      if (best === null || off < best) best = off;
    }
    bufferOffset = best;
  }

  if (varOffset === null) throw new Error('Variable comparée introuvable (offset stack non résolu).');
  if (bufferOffset === null) throw new Error('Offset buffer introuvable automatiquement près du CMP.');
  const padding = varOffset - bufferOffset;
  if (!Number.isFinite(padding) || padding <= 0) {
    throw new Error(`Padding invalide calculé (${padding}). Vérifiez le CMP choisi.`);
  }

  const bits = cmpInfo.width * 8;
  let masked = BigInt.asUintN(bits, cmpInfo.rhsValue);
  const bytes = [];
  for (let i = 0; i < cmpInfo.width; i += 1) {
    bytes.push(Number(masked & 0xffn));
    masked >>= 8n;
  }
  const suffixSafe = bytes.every((b) => b >= 0x20 && b <= 0x7e && b !== 0x2b && b !== 0x2a);
  const suffix = suffixSafe ? String.fromCharCode(...bytes) : '';
  const fallbackSuffix = 'B'.repeat(Math.max(4, cmpInfo.width));
  const payloadExpr = `A*${padding}+${suffix || fallbackSuffix}`;
  const captureBufferOffset = Math.min(bufferOffset - (archBits === 64 ? 16 : 8), bufferOffset);
  const frameSpan = Math.max(varOffset, bufferOffset + padding + cmpInfo.width) - captureBufferOffset;
  const captureBufferSize = Math.max(96, archBits === 64 ? frameSpan + 32 : frameSpan + 16);

  return {
    cmpAddr: addr.norm,
    cmpInstr: cmpAsm,
    sourceCall,
    archBits,
    bufferOffset,
    varOffset,
    padding,
    cmpWidth: cmpInfo.width,
    cmpImmediate: `0x${BigInt.asUintN(bits, cmpInfo.rhsValue).toString(16).padStart(cmpInfo.width * 2, '0')}`,
    cmpImmediateBytesLe: bytes.map((b) => b.toString(16).padStart(2, '0')).join(''),
    suffix,
    payloadExpr,
    captureBufferOffset,
    captureBufferSize,
    warning: suffix ? null : 'Valeur CMP non printable: suffixe remplacé par des B.'
  };
};

module.exports = {
  parseIntLiteral,
  parseBigIntLiteral,
  extractAsm,
  normalizeAddress,
  extractFrameOffset,
  regWidthBytes,
  parseCmpInfo,
  normalizeCalleeName,
  detectArchBitsFromLines,
  collectRegOffsets,
  buildCmpPayloadSuggestion,
};
