/**
 * @file utils.js
 * @brief Utilitaires partages pour la webview.
 * @details Parsing, calcul d'adresses, et formatage de bytes.
 */
/**
 * @brief Construit un mapping nom->valeur pour les registres.
 * @param registerItems Liste de registres.
 * @return Mapping {name: value}.
 */
export function buildRegisterMap(registerItems) {
  const map = {};
  // Convert "rax: 0x..." into a name->number map for quick lookup.
  registerItems.forEach((reg) => {
    if (!reg || !reg.name) return;
    const value = parseHex(reg.value);
    if (value !== null) {
      map[reg.name.toLowerCase()] = value;
    }
  });
  return map;
}

/**
 * @brief Parse une valeur hex ou decimale.
 * @param value Valeur a parser.
 * @return Nombre ou null.
 */
export function parseHex(value) {
  // Accept numbers, 0x-prefixed strings, or decimal strings.
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== 'string') return null;
  if (value.startsWith('0x')) {
    const parsed = parseInt(value, 16);
    return Number.isFinite(parsed) ? parsed : null;
  }
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * @brief Resolve l'adresse reelle d'un item de pile.
 * @param item Entree de pile.
 * @param rsp Registre SP.
 * @return Adresse ou null.
 */
export function resolveStackAddress(item, rsp) {
  // Prefer explicit addr, fallback to rsp + pos offset.
  if (typeof item.addr === 'string' && item.addr.startsWith('0x')) {
    const parsed = parseInt(item.addr, 16);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (typeof item.addr === 'number') {
    return item.addr;
  }
  const pos = typeof item.pos === 'number' ? item.pos : item.posi ?? null;
  if (rsp !== null && pos !== null) {
    return rsp + pos;
  }
  return null;
}

/**
 * @brief Formate un nombre en hex.
 * @param value Valeur numerique.
 * @return Chaine hex (0x...).
 */
export function toHex(value) {
  return `0x${value.toString(16)}`;
}

/**
 * @brief Formate un offset signe en hex.
 * @param value Valeur numerique.
 * @return Chaine +0x.. ou -0x...
 */
export function formatSignedHex(value) {
  // Render offsets as +0x.. or -0x.. for readability.
  if (value === 0) return '+0x0';
  const sign = value < 0 ? '-' : '+';
  const abs = Math.abs(value);
  return `${sign}0x${abs.toString(16)}`;
}

/**
 * @brief Convertit une valeur en bytes little-endian.
 * @param value Valeur a convertir.
 * @param wordSize Taille de mot (bytes).
 * @return Tableau de bytes.
 */
export function toBytes(value, wordSize) {
  // Convert numeric values into little-endian bytes.
  let bigValue = 0n;
  if (typeof value === 'string' && value.startsWith('0x')) {
    bigValue = BigInt(value);
  } else if (typeof value === 'number' && Number.isFinite(value)) {
    bigValue = BigInt(value);
  } else if (value !== null && value !== undefined) {
    try {
      bigValue = BigInt(value);
    } catch (err) {
      bigValue = 0n;
    }
  }

  const bytes = [];
  const masked = BigInt.asUintN(wordSize * 8, bigValue);
  for (let i = 0; i < wordSize; i++) {
    const shift = BigInt(i * 8);
    const byte = Number((masked >> shift) & 0xffn);
    bytes.push(byte);
  }
  return bytes;
}
