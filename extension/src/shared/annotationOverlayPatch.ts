// SPDX-License-Identifier: AGPL-3.0-only
/**
 * In-place patching of the generated .asm/.mapping artifacts when a user
 * annotation mutation only changes a comment. Renames still require a full
 * disasm rebuild (label lines are inserted and branch operands rewritten),
 * but comments are end-of-line suffixes: the mapping gives the physical
 * line per address, so the host can rewrite just that suffix without
 * spawning the disassembler.
 *
 * The .asm comment suffix format is owned by disasm.py (_comment_suffix /
 * _apply_labels): `  ; [dwarf src | ]user comment[ | stack hints][ | struct
 * hints]`. The stack/struct parts are reconstructed from the mapping's
 * stack_hints / typed_struct_hints entries; the dwarf src part is captured
 * verbatim from the existing line. Any mismatch between the reconstructed
 * suffix and the actual line falls back to 'rebuild-required'.
 */

const fs = require('fs');

// Au-delà de cette taille, préférer un rebuild plutôt que de charger le .asm
// entier en mémoire côté host.
const MAX_PATCHABLE_ASM_BYTES = 256 * 1024 * 1024;

function normalizeHexAddress(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  const raw = text.startsWith('0x') || text.startsWith('0X') ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]+$/.test(raw)) return text.toLowerCase();
  return `0x${raw.replace(/^0+/, '') || '0'}`.toLowerCase();
}

// Miroir de disasm.py : ", ".join(f"{kind} {name} @ {location}")
function stackHintsPart(stackHints) {
  const hints = Array.isArray(stackHints) ? stackHints : [];
  if (!hints.length) return '';
  return hints.map((h) => `${h?.kind} ${h?.name} @ ${h?.location}`).join(', ');
}

// Miroir de disasm.py : "struct {2 premiers labels}[, +N]"
function typedStructPart(typedStructHints) {
  const hints = Array.isArray(typedStructHints) ? typedStructHints : [];
  const labels = hints.slice(0, 2)
    .map((h) => String(h?.label || h?.addr || '').trim())
    .filter(Boolean);
  if (!labels.length) return '';
  let text = labels.join(', ');
  if (hints.length > 2) text += `, +${hints.length - 2}`;
  return `struct ${text}`;
}

// Miroir de disasm.py _comment_suffix
function commentSuffix(parts) {
  const clean = parts.map((p) => String(p || '').trim()).filter(Boolean);
  return clean.length ? `  ; ${clean.join(' | ')}` : '';
}

/**
 * Sépare une ligne .asm existante en (instruction, src dwarf capturé) en la
 * validant contre le suffixe attendu reconstruit depuis le mapping.
 * Retourne null si la ligne ne correspond pas (→ rebuild).
 */
function splitAsmLine(line, { oldComment, stackPart, structPart }) {
  const tailParts = [oldComment, stackPart, structPart]
    .map((p) => String(p || '').trim())
    .filter(Boolean);
  const tailJoined = tailParts.join(' | ');
  if (tailJoined) {
    const noSrcSuffix = `  ; ${tailJoined}`;
    if (line.endsWith(noSrcSuffix)) {
      return { instr: line.slice(0, -noSrcSuffix.length), src: '' };
    }
    const withSrcTail = ` | ${tailJoined}`;
    if (line.endsWith(withSrcTail)) {
      const rest = line.slice(0, -withSrcTail.length);
      const marker = rest.lastIndexOf('  ; ');
      if (marker > 0) {
        const src = rest.slice(marker + 4);
        if (src && !src.includes(' | ')) {
          return { instr: rest.slice(0, marker), src };
        }
      }
    }
    return null;
  }
  const marker = line.indexOf('  ; ');
  if (marker === -1) return { instr: line, src: '' };
  // Suffixe présent alors qu'aucune partie n'est attendue : soit un src
  // dwarf seul, soit un état inattendu — capturer comme src uniquement si
  // la forme est plausible (une seule partie).
  const src = line.slice(marker + 4);
  if (src && !src.includes(' | ')) {
    return { instr: line.slice(0, marker), src };
  }
  return null;
}

function readMapping(mappingPath) {
  try {
    return JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function atomicWrite(filePath, content) {
  const tmpPath = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(tmpPath, content, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

/**
 * Classifie une mutation d'annotation et patche le .asm/.mapping en place
 * quand seul un commentaire change.
 *
 * @returns 'unchanged' | 'patched' | 'rebuild-required'
 */
function applyAnnotationOverlayMutation({
  mappingPath,
  addr,
  name = '',
  comment = '',
  deleted = false,
}) {
  const asmPath = String(mappingPath || '').replace(/\.disasm\.mapping\.json$/, '.disasm.asm');
  if (!mappingPath || asmPath === mappingPath) return 'unchanged';
  if (!fs.existsSync(mappingPath) || !fs.existsSync(asmPath)) {
    // Pas d'artefacts : rien de périmé, le prochain build bakera l'état frais.
    return 'unchanged';
  }
  const mapping = readMapping(mappingPath);
  if (!mapping || !Array.isArray(mapping.lines)) return 'rebuild-required';

  const normAddr = normalizeHexAddress(addr);
  if (!normAddr) return 'unchanged';
  const entries = mapping.lines.filter((l) => normalizeHexAddress(l?.addr) === normAddr);
  if (!entries.length) {
    // Adresse hors du désassemblage courant (autre section, données…) :
    // l'overlay visible n'est pas affecté.
    return 'unchanged';
  }

  const targetName = deleted ? '' : String(name || '').trim();
  const targetComment = deleted ? '' : String(comment || '').trim();
  const bakedLabel = String(entries[0]?.label || '').trim();
  const bakedComment = String(entries[0]?.comment || '').trim();
  const functions = Array.isArray(mapping.functions) ? mapping.functions : [];
  const originalFnName = String(
    functions.find((fn) => normalizeHexAddress(fn?.addr) === normAddr)?.name || ''
  ).trim();

  // Après rebuild, le label résolu serait le rename utilisateur s'il existe,
  // sinon le nom de fonction d'origine (seedé dans label_map par disasm.py).
  const labelAfter = targetName || originalFnName;
  if (labelAfter !== bakedLabel) return 'rebuild-required';
  if (targetComment === bakedComment) return 'unchanged';

  let stat;
  try {
    stat = fs.statSync(asmPath);
  } catch (_) {
    return 'rebuild-required';
  }
  if (stat.size > MAX_PATCHABLE_ASM_BYTES) return 'rebuild-required';

  let asmContent;
  try {
    asmContent = fs.readFileSync(asmPath, 'utf8');
  } catch (_) {
    return 'rebuild-required';
  }
  const asmLines = asmContent.split('\n');

  const patchedIndexes = [];
  for (const entry of entries) {
    const lineNo = Number(entry?.line || 0);
    if (!Number.isInteger(lineNo) || lineNo <= 0 || lineNo > asmLines.length) {
      return 'rebuild-required';
    }
    const idx = lineNo - 1;
    const line = asmLines[idx];
    if (!line.startsWith(`  ${entry.addr}:  `)) return 'rebuild-required';
    const split = splitAsmLine(line, {
      oldComment: bakedComment,
      stackPart: stackHintsPart(entry.stack_hints),
      structPart: typedStructPart(entry.typed_struct_hints),
    });
    if (!split) return 'rebuild-required';
    asmLines[idx] = split.instr + commentSuffix([
      split.src,
      targetComment,
      stackHintsPart(entry.stack_hints),
      typedStructPart(entry.typed_struct_hints),
    ]);
    patchedIndexes.push(idx);
  }
  if (!patchedIndexes.length) return 'unchanged';

  for (const entry of entries) {
    entry.comment = targetComment || null;
  }
  try {
    atomicWrite(asmPath, asmLines.join('\n'));
    atomicWrite(mappingPath, JSON.stringify(mapping));
  } catch (_) {
    return 'rebuild-required';
  }
  return 'patched';
}

module.exports = {
  applyAnnotationOverlayMutation,
  // Exposés pour les tests unitaires.
  splitAsmLine,
  stackHintsPart,
  typedStructPart,
  commentSuffix,
};
