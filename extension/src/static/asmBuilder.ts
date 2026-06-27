// SPDX-License-Identifier: AGPL-3.0-only

/**
 * @deprecated Remplacé par le moteur backends/static/compile/compile.py.
 * Ce module est conservé uniquement comme fallback legacy.
 * Suppression prévue dans la prochaine version majeure.
 */

/**
 * @file asmBuilder.js
 * @brief Génération input.asm depuis source C (heuristique pour mode static).
 */

const fs = require('fs');

/**
 * Trouve l'accolade fermante correspondante à l'indice donné.
 * @param {string} source - Code source
 * @param {number} openIndex - Indice de l'accolade ouvrante
 * @returns {number} Indice de l'accolade fermante ou -1
 */
function findMatchingBrace(source, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Parse le code C et extrait les définitions de fonctions (name, params, body).
 * @param {string} source - Code source C
 * @returns {Map<string, {name, params, body}>}
 */
function parseFunctions(source) {
  const functions = new Map();
  const defRe = /([_a-zA-Z][\w\s]*?)\s+([_a-zA-Z]\w*)\s*\(([^)]*)\)\s*\{/g;
  let match;
  while ((match = defRe.exec(source)) !== null) {
    const name = match[2];
    const params = match[3].split(',').map((p) => p.trim()).filter(Boolean)
      .map((p) => (p.split(/\s+/).filter(Boolean).pop() || '')).filter(Boolean);
    const bodyStart = match.index + match[0].length;
    const bodyEnd = findMatchingBrace(source, bodyStart - 1);
    if (bodyEnd === -1) continue;
    functions.set(name, { name, params, body: source.slice(bodyStart, bodyEnd) });
  }
  return functions;
}

/**
 * Extrait les assignations (var = value) du corps de fonction.
 * @param {string} body - Corps de la fonction
 * @returns {Map<string, string>}
 */
function extractAssignments(body) {
  const assigns = new Map();
  if (!body) return assigns;
  const assignRe = /\b(?:int|long|short|char)\s+([_a-zA-Z]\w*)\s*=\s*([+-]?(?:0x[0-9a-fA-F]+|\d+))\s*;/g;
  let match;
  while ((match = assignRe.exec(body)) !== null) assigns.set(match[1], match[2]);
  return assigns;
}

/**
 * Détecte l'incrément d'une variable (++, +=, = var + N).
 * @param {string} body - Corps de la boucle
 * @param {string} varName - Nom de la variable
 * @returns {number|null} Incrément ou null
 */
function parseIncrement(body, varName) {
  if (new RegExp(`\\b${varName}\\s*\\+\\+\\s*;`).test(body)) return 1;
  let m = body.match(new RegExp(`\\b${varName}\\s*\\+=\\s*([+-]?(?:0x[0-9a-fA-F]+|\\d+))\\s*;`));
  if (m) {
    const val = parseInt(m[1], 0);
    return Number.isFinite(val) ? val : null;
  }
  m = body.match(new RegExp(`\\b${varName}\\s*=\\s*${varName}\\s*\\+\\s*([+-]?(?:0x[0-9a-fA-F]+|\\d+))\\s*;`));
  if (m) {
    const val = parseInt(m[1], 0);
    return Number.isFinite(val) ? val : null;
  }
  return null;
}

/**
 * Transforme les boucles while simples en instructions push/pop asm.
 * @param {string} body - Corps de la fonction
 * @param {Map<string, string>} assigns - Assignations connues
 * @returns {string[]|null} Liste d'instructions asm, ou null si une boucle dépasse 10000 itérations
 */
function applySimpleWhileLoops(body, assigns) {
  const ops = [];
  if (!body) return ops;
  const loopRe = /while\s*\(\s*([_a-zA-Z]\w*)\s*<\s*([+-]?(?:0x[0-9a-fA-F]+|\d+))\s*\)\s*\{([\s\S]*?)\}/g;
  let match;
  while ((match = loopRe.exec(body)) !== null) {
    const [varName, limitText, loopBody] = [match[1], match[2], match[3]];
    if (!assigns.has(varName)) continue;
    const startVal = parseInt(assigns.get(varName), 0);
    const limitVal = parseInt(limitText, 0);
    if (!Number.isFinite(startVal) || !Number.isFinite(limitVal)) continue;
    const step = parseIncrement(loopBody, varName);
    if (step === null) continue;
    let value = startVal;
    let guard = 0;
    while (value < limitVal) {
      if (guard >= 10000) return null;
      value += step;
      guard += 1;
      ops.push(`    push ${value}`, '    pop rax');
    }
    assigns.set(varName, String(value));
  }
  return ops;
}

/**
 * Résout la valeur d'un opérande (variable ou littéral).
 * @param {Map} assigns - Assignations
 * @param {string} token - Token à résoudre
 * @returns {string|null}
 */
function resolveOperandValue(assigns, token) {
  if (assigns.has(token)) return assigns.get(token);
  const literal = token.trim();
  if (/^[+-]?(?:0x[0-9a-fA-F]+|\d+)$/.test(literal)) return literal;
  return null;
}

/**
 * Convertit un opérateur en mnémonique asm.
 * @param {string} op - Opérateur (+, -, *, /)
 * @returns {string}
 */
function opToMnemonic(op) {
  if (op === '+') return 'add';
  if (op === '-') return 'sub';
  if (op === '*') return 'mul';
  if (op === '/') return 'div';
  return 'add';
}

/**
 * Analyse le corps d'une fonction pour extraire l'expression de retour.
 * @param {{name, params, body}} fn - Fonction parsée
 * @returns {{type, left, right, op, leftValue, rightValue}|{type, value}|null}
 */
function analyzeFunctionBody(fn) {
  const body = (fn.body || '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  const returnMatch = body.match(/return\s+([^;]+);/m);
  if (!returnMatch) return null;
  const returnExpr = returnMatch[1].trim();

  const assigns = new Map();
  const assignRe = /\b(?:int|long|short|char)\s+([_a-zA-Z]\w*)\s*=\s*([_a-zA-Z]\w*)\s*([+\-*/])\s*([_a-zA-Z]\w*)\s*;/g;
  const literalRe = /\b(?:int|long|short|char)\s+([_a-zA-Z]\w*)\s*=\s*([+-]?(?:0x[0-9a-fA-F]+|\d+))\s*;/g;
  let match;
  while ((match = assignRe.exec(body)) !== null) assigns.set(match[1], { left: match[2], op: match[3], right: match[4] });
  const literals = new Map();
  while ((match = literalRe.exec(body)) !== null) literals.set(match[1], match[2]);

  const binRe = /^([_a-zA-Z]\w*)\s*([+\-*/])\s*([_a-zA-Z]\w*)$/;
  const binMatch = returnExpr.match(binRe);
  if (binMatch) {
    const [left, right] = [binMatch[1], binMatch[3]];
    return {
      type: 'binary',
      left,
      op: binMatch[2],
      right,
      leftValue: literals.has(left) ? literals.get(left) : null,
      rightValue: literals.has(right) ? literals.get(right) : null
    };
  }
  if (assigns.has(returnExpr)) {
    const expr = assigns.get(returnExpr);
    return {
      type: 'binary',
      left: expr.left,
      op: expr.op,
      right: expr.right,
      leftValue: literals.has(expr.left) ? literals.get(expr.left) : null,
      rightValue: literals.has(expr.right) ? literals.get(expr.right) : null
    };
  }
  if (fn.params.includes(returnExpr)) return { type: 'single', value: returnExpr };
  if (/^[+-]?(?:0x[0-9a-fA-F]+|\d+)$/.test(returnExpr.trim())) {
    return { type: 'single', value: returnExpr, valueLiteral: returnExpr };
  }
  return null;
}

/**
 * Génère un programme asm depuis une source C (heuristique pour mode static).
 * @param {string} sourcePath - Chemin vers le fichier .c
 * @returns {{asm: string}|{error: string}}
 */
function buildStaticAsmFromSource(sourcePath) {
  const header = ['; input.asm (static stack)', '; Generated from C source.', '', 'start:'];
  if (!sourcePath || !fs.existsSync(sourcePath)) {
    return { error: 'Source C introuvable pour le mode static.' };
  }
  const raw = fs.readFileSync(sourcePath, 'utf8');
  const clean = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  const functions = parseFunctions(clean);
  const mainBody = functions.get('main')?.body || '';
  const assigns = extractAssignments(mainBody);
  const loopOps = applySimpleWhileLoops(mainBody, assigns);
  if (loopOps === null) return { error: 'Boucle trop longue (> 10000 iterations).' };

  const returnRe = /return\s+([^;]+);/m;
  const returnMatch = (mainBody || clean).match(returnRe);
  const body = [];
  if (!returnMatch) {
    body.push('    push 0', '    pop rax');
  } else {
    const expr = returnMatch[1].trim();
    const callMatch = expr.match(/^([_a-zA-Z]\w*)\s*\(([^)]*)\)$/);
    if (callMatch) {
      const [fnName, argsRaw] = [callMatch[1], callMatch[2].trim()];
      const args = argsRaw ? argsRaw.split(',').map((a) => a.trim()) : [];
      const fn = functions.get(fnName);
      if (!fn) return { error: `Fonction '${fnName}' introuvable.` };
      const analyzed = analyzeFunctionBody(fn);
      const argValues = args.map((a) => resolveOperandValue(assigns, a));
      if (argValues.some((v) => v === null)) return { error: 'Arguments non resolus.' };
      if (analyzed?.type === 'binary') {
        let leftVal = analyzed.leftValue ?? null;
        let rightVal = analyzed.rightValue ?? null;
        if (leftVal === null || rightVal === null) {
          const li = fn.params.indexOf(analyzed.left);
          const ri = fn.params.indexOf(analyzed.right);
          if (li < 0 || ri < 0) return { error: 'Signature non supportee.' };
          leftVal = argValues[li];
          rightVal = argValues[ri];
        }
        body.push(`    push ${leftVal}`, `    push ${rightVal}`, `    ${opToMnemonic(analyzed.op)}`, '    pop rax');
      } else if (analyzed?.type === 'single') {
        const idx = fn.params.indexOf(analyzed.value);
        const val = analyzed.valueLiteral ?? (idx >= 0 ? argValues[idx] : analyzed.value);
        body.push(`    push ${val}`, '    pop rax');
      } else {
        return { error: 'Fonction trop complexe.' };
      }
    } else {
      const binRe = /^([_a-zA-Z]\w*|[+-]?(?:0x[0-9a-fA-F]+|\d+))\s*([+\-*/])\s*([_a-zA-Z]\w*|[+-]?(?:0x[0-9a-fA-F]+|\d+))$/;
      const binMatch = expr.match(binRe);
      if (binMatch) {
        const left = resolveOperandValue(assigns, binMatch[1]);
        const right = resolveOperandValue(assigns, binMatch[3]);
        if (left !== null && right !== null) {
          body.push(`    push ${left}`, `    push ${right}`, `    ${opToMnemonic(binMatch[2])}`, '    pop rax');
        } else {
          return { error: 'Expression trop complexe.' };
        }
      } else {
        const single = resolveOperandValue(assigns, expr);
        if (single !== null) {
          body.push(`    push ${single}`, '    pop rax');
        } else {
          return { error: 'Expression return non supportee.' };
        }
      }
    }
  }
  return { asm: [...header, ...loopOps, ...body, ''].join('\n') };
}

/**
 * Assure que le fichier asm existe, généré depuis sourcePath si nécessaire.
 * @param {string} asmPath - Chemin du fichier .asm à générer
 * @param {string|null} sourcePath - Chemin du fichier .c (ou null)
 * @param {object} output - Canal de sortie (appendLine)
 * @returns {{ok: boolean, error?: string}}
 */
function ensureStaticAsm(asmPath, sourcePath, output) {
  const result = buildStaticAsmFromSource(sourcePath);
  if (result.error) return { ok: false, error: result.error };
  fs.writeFileSync(asmPath, result.asm, 'utf8');
  output.appendLine(`[static] wrote ${asmPath}`);
  return { ok: true };
}

module.exports = { buildStaticAsmFromSource, ensureStaticAsm };
