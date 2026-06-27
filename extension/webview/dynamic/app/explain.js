/**
 * @file explain.js
 * @brief Rendu du panneau pedagogique en langage humain.
 */
import { dom } from './dom.js';
import { diagnosticKindLabel, primaryDiagnostic } from './diagnostics.js';
import { explainStackEffect } from './render.js';

export function renderExplain(snap, prevSnap, regMap = {}, prevRegMap = {}, meta = {}, analysis = null, mcp = null, diagnostics = [], crash = null) {
  if (!dom.explainBody) return;
  dom.explainBody.replaceChildren();
  void prevSnap;
  void regMap;
  void prevRegMap;

  if (!snap) {
    const empty = document.createElement('div');
    empty.className = 'status';
    empty.textContent = 'Aucune explication disponible.';
    dom.explainBody.appendChild(empty);
    return;
  }

  const sections = buildSections(snap, meta, analysis, mcp, diagnostics, crash);
  sections.forEach((section) => {
    const card = document.createElement('section');
    card.className = 'explain-section';
    if (section.severity) card.classList.add(`explain-section-${section.severity}`);

    const label = document.createElement('div');
    label.className = 'explain-section-label';
    label.textContent = section.label;

    const body = document.createElement('div');
    body.className = 'explain-section-text';
    body.textContent = section.text;

    card.append(label, body);
    dom.explainBody.appendChild(card);
  });
}

function buildSections(snap, meta, analysis, mcp, diagnostics = [], crash = null) {
  const diagnostic = primaryDiagnostic(diagnostics);
  const classification = crash && typeof crash === 'object'
    ? String(crash.classification || '').trim().toLowerCase()
    : '';
  const crashSection = crash && typeof crash === 'object'
    ? classification === 'ret2win_success'
      ? { label: 'ACCES CIBLE', text: buildRetWinText(crash), severity: 'success' }
      : classification === 'control_hijack'
      ? { label: 'DETOURNEMENT', text: buildCrashText(crash), severity: 'warning' }
      : { label: 'CRASH DETECTE', text: buildCrashText(crash), severity: 'error' }
    : null;
  const suppressDiagnostic = diagnostic
    && classification === 'ret2win_success'
    && String(diagnostic.kind || '') === 'ret2win_success';
  const diagnosticSection = diagnostic && !suppressDiagnostic
    ? {
        label: diagnostic.severity === 'error' ? 'ERREUR'
          : diagnostic.severity === 'success' ? 'SUCCES'
          : 'AVERTISSEMENT',
        text: buildDiagnosticText(diagnostic),
        severity: diagnostic.severity || 'warning'
      }
    : null;
  const mcpSections = Array.isArray(mcp?.explanation?.sections) ? mcp.explanation.sections : null;
  if (mcpSections && mcpSections.length) {
    const rendered = mcpSections.map((section) => ({
      label: String(section?.label || 'Info'),
      text: String(section?.text || '')
    }));
    return [crashSection, diagnosticSection, ...rendered].filter(Boolean);
  }

  const instr = typeof snap.instr === 'string' && snap.instr.trim()
    ? snap.instr.trim()
    : '(instruction inconnue)';
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  const hasOverflowDiagnostic = Array.isArray(diagnostics)
    && diagnostics.some((entry) => entry?.kind === 'buffer_overflow');
  const writes = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes : [];
  const reads = Array.isArray(analysis?.delta?.reads) ? analysis.delta.reads : [];
  const payload = String(meta?.payload_text || meta?.argv1 || '').trim();
  const payloadLabel = String(meta?.payload_label || (meta?.payload_target === 'stdin' ? 'stdin' : meta?.payload_target === 'both' ? 'stdin + argv[1]' : 'argv[1]'));

  const stackText = writes.length
    ? `Cette instruction ecrit dans la pile. ${explainStackEffect(instr)}`
    : reads.length
    ? `Cette instruction lit dans la pile. ${explainStackEffect(instr)}`
    : explainStackEffect(instr);

  let payloadText = `${payloadLabel} n'a pas encore d'effet visible ici.`;
  if (payload) {
    payloadText = `${payloadLabel} courant: "${payload}".`;
  }
  if (overflow?.active && hasOverflowDiagnostic) {
    const reached = Array.isArray(overflow.reached) && overflow.reached.length
      ? overflow.reached.join(', ')
      : 'les zones de controle';
    payloadText = `Le contenu copie a deja depasse le buffer et touche ${reached}.`;
  }

  const sections = [
    {
      label: 'Maintenant',
      text: snap.func
        ? `Le programme execute ${instr} dans ${snap.func}.`
        : `Le programme execute ${instr}.`
    },
    {
      label: 'Pile',
      text: stackText
    },
    {
      label: payloadLabel,
      text: payloadText
    }
  ];
  return [crashSection, diagnosticSection, ...sections].filter(Boolean);
}

function tryDecodeAsText(hexAddr) {
  const text = String(hexAddr || '').trim().replace(/^0x/i, '');
  if (!text || text.length % 2 !== 0) return null;
  let result = '';
  for (let i = 0; i < text.length; i += 2) {
    const byte = parseInt(text.slice(i, i + 2), 16);
    if (byte === 0) continue;
    if (byte < 0x20 || byte > 0x7e) return null;
    result += String.fromCharCode(byte);
  }
  return result.length >= 2 ? result : null;
}

function addrWithDecode(hexAddr) {
  const addr = String(hexAddr || '').trim();
  if (!addr) return null;
  const decoded = tryDecodeAsText(addr);
  return decoded ? `${addr} ("${decoded}")` : addr;
}

function buildDiagnosticText(diagnostic) {
  const bits = [
    diagnosticKindLabel(diagnostic.kind),
    diagnostic.message
  ].filter(Boolean);
  if (diagnostic.before || diagnostic.after) {
    const b = addrWithDecode(diagnostic.before) || 'n/a';
    const a = addrWithDecode(diagnostic.after) || 'n/a';
    bits.push(`avant ${b} -> apres ${a}`);
  }
  if (diagnostic.probableSource) {
    bits.push(`source: ${diagnostic.probableSource}`);
  }
  if (Number.isFinite(Number(diagnostic.payloadOffset))) {
    bits.push(`offset payload: ${diagnostic.payloadOffset}`);
  }
  if (diagnostic.slot?.offset || diagnostic.slot?.address) {
    bits.push(`slot: ${diagnostic.slot.offset || '?'} ${diagnostic.slot.address || ''}`.trim());
  }
  return bits.join(' • ');
}

function buildCrashText(crash) {
  const retTarget = String(crash?.retTarget || '').trim();
  const faultAddr = String(crash?.memoryAddress || '').trim();
  const bits = [
    String(crash?.reason || '').trim(),
    String(crash?.instructionText || '').trim() ? `instruction: ${crash.instructionText}` : '',
    String(crash?.instructionAddress || '').trim() ? `@ ${crash.instructionAddress}` : '',
    faultAddr ? `adresse fautive: ${addrWithDecode(faultAddr) || faultAddr}` : '',
    String(crash?.probableSource || '').trim() ? `source: ${crash.probableSource}` : '',
    Number.isFinite(Number(crash?.payloadOffset)) ? `offset payload: ${crash.payloadOffset}` : '',
    crash?.suspectOverwrittenSlot?.kind
      ? `slot: ${crash.suspectOverwrittenSlot.kind}${crash.suspectOverwrittenSlot.offset ? ' ' + crash.suspectOverwrittenSlot.offset : ''}`
      : '',
    crash?.registers && typeof crash.registers === 'object'
      ? ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp']
        .filter((name) => crash.registers[name])
        .map((name) => {
          const val = String(crash.registers[name] || '');
          const decoded = tryDecodeAsText(val);
          return `${name.toUpperCase()}=${val}${decoded ? ` ("${decoded}")` : ''}`;
        })
        .join(' • ')
      : ''
  ].filter(Boolean);
  void retTarget;
  return bits.join(' • ');
}

function buildRetWinText(crash) {
  const target = String(crash?.retTarget || crash?.memoryAddress || crash?.rip || crash?.eip || '').trim();
  const bits = [
    `L'adresse de retour a ete detournee vers ${addrWithDecode(target) || 'une fonction cible'}.`,
    String(crash?.probableSource || '').trim() ? `Source: ${crash.probableSource}` : '',
    Number.isFinite(Number(crash?.payloadOffset)) ? `Offset dans le payload: ${crash.payloadOffset}` : '',
    crash?.suspectOverwrittenSlot?.kind === 'return_address'
      ? `Slot: adresse de retour${crash.suspectOverwrittenSlot.offset ? ' ' + crash.suspectOverwrittenSlot.offset : ''}`
      : '',
    crash?.registers && typeof crash.registers === 'object'
      ? ['rip', 'eip']
        .filter((name) => crash.registers[name])
        .map((name) => {
          const val = String(crash.registers[name] || '');
          const decoded = tryDecodeAsText(val);
          return `${name.toUpperCase()}=${val}${decoded ? ` ("${decoded}")` : ''}`;
        })
        .join(' • ')
      : ''
  ].filter(Boolean);
  return bits.join(' • ');
}
