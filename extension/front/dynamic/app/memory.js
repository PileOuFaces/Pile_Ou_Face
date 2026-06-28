/**
 * @file memory.js
 * @brief Helpers de lecture memoire BigInt-safe pour le visualizer dynamic.
 */

export function addrKey(addrBig) {
  if (typeof addrBig !== 'bigint') return null;
  return `0x${addrBig.toString(16)}`;
}

export function toBigIntAddr(value) {
  if (value == null) return null;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
  if (typeof value !== 'string') return null;

  const text = value.trim().toLowerCase();
  if (!text) return null;

  try {
    if (text.startsWith('0x')) return BigInt(text);
    if (/^-?\d+$/.test(text)) return BigInt(text);
    if (/^[0-9a-f]+$/.test(text)) return BigInt(`0x${text}`);
  } catch (_) {
    return null;
  }

  return null;
}

function parseByteString(entry) {
  const bytes = String(entry)
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => Number.parseInt(part, 16))
    .filter((value) => Number.isFinite(value) && value >= 0 && value <= 0xff);
  return bytes.length ? Uint8Array.from(bytes) : null;
}

function readBytesFromMemoryMap(addrBig, n, memoryMap) {
  if (!memoryMap || typeof memoryMap !== 'object') return null;
  const key = addrKey(addrBig);
  if (!key) return null;

  const entry = memoryMap[key];
  if (entry == null) return null;

  let bytes = null;
  if (Array.isArray(entry)) {
    bytes = Uint8Array.from(entry.filter((value) => Number.isFinite(value)).slice(0, n));
  } else if (typeof entry === 'string') {
    bytes = parseByteString(entry);
  }

  if (!bytes || bytes.length < n) return null;
  return bytes.slice(0, n);
}

function buildByteMapFromStackItems(stackItems, rsp) {
  const byteMap = new Map();
  if (!Array.isArray(stackItems)) return byteMap;

  stackItems.forEach((item) => {
    const baseAddr = toBigIntAddr(item?.addr)
      ?? (rsp !== null && Number.isFinite(item?.pos) ? rsp + BigInt(Math.trunc(item.pos)) : null)
      ?? (rsp !== null && Number.isFinite(item?.posi) ? rsp + BigInt(Math.trunc(item.posi)) : null);
    const size = Number(item?.size);
    const value = toBigIntAddr(item?.value ?? item?.val);

    if (baseAddr === null || !Number.isFinite(size) || size <= 0 || value === null) return;

    let raw = BigInt.asUintN(size * 8, value);
    for (let i = 0; i < size; i += 1) {
      byteMap.set(addrKey(baseAddr + BigInt(i)), Number(raw & 0xffn));
      raw >>= 8n;
    }
  });

  return byteMap;
}

function readBytesFromStackItems(addrBig, n, stackItems, rsp) {
  const byteMap = buildByteMapFromStackItems(stackItems, rsp);
  if (!byteMap.size) return null;

  const out = [];
  for (let i = 0; i < n; i += 1) {
    const key = addrKey(addrBig + BigInt(i));
    if (!key || !byteMap.has(key)) return null;
    out.push(byteMap.get(key));
  }
  return Uint8Array.from(out);
}

export function readBytes(addrBig, n, source = {}) {
  const addr = toBigIntAddr(addrBig);
  const size = Number(n);
  if (addr === null || !Number.isFinite(size) || size <= 0) return null;

  const fromMap = readBytesFromMemoryMap(addr, size, source.memoryMap);
  if (fromMap) return fromMap;

  return readBytesFromStackItems(addr, size, source.stackItems, toBigIntAddr(source.rsp));
}

export function readPointer(addrBig, wordSize, source = {}) {
  const bytes = readBytes(addrBig, Number(wordSize), source);
  if (!bytes) return null;

  let value = 0n;
  for (let i = 0; i < bytes.length; i += 1) {
    value |= BigInt(bytes[i]) << (8n * BigInt(i));
  }
  return value;
}

export function readU32(addrBig, source = {}) {
  const value = readPointer(addrBig, 4n, source);
  return value === null ? null : BigInt.asUintN(32, value);
}
