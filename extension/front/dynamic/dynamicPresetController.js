/**
 * Classic-script controller for Dynamic preset / auto-notes launch in the hub.
 * Handles applyDynamicPreset, runAutoFromNotes, and related helpers.
 */
(function initHubDynamicPresetController(global) {
  function initDynamicPresetController(deps) {
    const {
      postMessage,
      showPanel,
      requestRunTraceInit,
      getDynamicPayloadTargetMode,
      normalizeDynamicPayloadTargetMode,
      dynamicPayloadTargetMode,
      runBtn,
      getDynamicTraceInitState,
      getStaticBinaryPath,
      form,
    } = deps || {};

    function setTraceField(name, value) {
      const el = form?.querySelector(`[name="${name}"]`);
      if (!el) return;
      if (el.type === 'checkbox') el.checked = !!value;
      else el.value = String(value ?? '');
    }

    function parseFlexibleInt(input) {
      const raw = String(input ?? '').trim();
      if (!raw) return null;
      if (/^[+-]?\d+$/.test(raw)) return parseInt(raw, 10);
      if (/^[+-]?0x[0-9a-f]+$/i.test(raw)) {
        const sign = raw.startsWith('-') ? -1 : 1;
        const normalized = raw.replace(/^[+-]/, '');
        return sign * parseInt(normalized, 16);
      }
      return null;
    }

    function parseFlexibleBigInt(input) {
      const raw = String(input ?? '').trim();
      if (!raw) return null;
      try {
        if (/^[+-]?\d+$/.test(raw)) return BigInt(raw);
        if (/^[+-]?0x[0-9a-f]+$/i.test(raw)) {
          const sign = raw.startsWith('-') ? -1n : 1n;
          const normalized = raw.replace(/^[+-]/, '').toLowerCase();
          return sign * BigInt(normalized);
        }
      } catch (_) {
        return null;
      }
      return null;
    }

    function normalizeNoteKey(rawKey) {
      return String(rawKey || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, '_')
        .replace(/[^a-z0-9_]/g, '');
    }

    function parseExploitNotes(rawText) {
      const lines = String(rawText || '').split(/\r?\n|;/g);
      const parsed = {};
      const keyMap = {
        cmp: 'cmpAddr',
        cmp_addr: 'cmpAddr',
        cmpaddr: 'cmpAddr',
        cmp_address: 'cmpAddr',
        padding: 'padding',
        pad: 'padding',
        overflow: 'padding',
        buffer_size: 'bufferSize',
        buffersize: 'bufferSize',
        suffix: 'suffix',
        payload_suffix: 'suffix',
        payload: 'payloadExpr',
        payload_expr: 'payloadExpr',
        payloadexpr: 'payloadExpr',
        buffer_offset: 'bufferOffset',
        bufoffset: 'bufferOffset',
        capture_size: 'captureSize',
        capturesize: 'captureSize',
        start: 'startSymbol',
        start_symbol: 'startSymbol',
        target: 'targetSymbol',
        target_symbol: 'targetSymbol',
        stop: 'targetSymbol',
        stop_symbol: 'targetSymbol',
        max_steps: 'maxSteps',
        maxstep: 'maxSteps',
        steps: 'maxSteps',
        payload_target: 'payloadTarget',
        cmp_value: 'cmpValue',
        cmp_immediate: 'cmpValue',
        immediate: 'cmpValue',
        cmp_width: 'cmpWidth',
        width: 'cmpWidth',
      };

      for (const lineRaw of lines) {
        const line = lineRaw.trim();
        if (!line || line.startsWith('#') || line.startsWith('//')) continue;
        const sepIdx = line.search(/[:=]/);
        if (sepIdx <= 0) continue;
        const key = normalizeNoteKey(line.slice(0, sepIdx));
        const value = line.slice(sepIdx + 1).trim();
        if (!value) continue;
        const canonical = keyMap[key];
        if (!canonical) continue;
        parsed[canonical] = value;
      }

      if (parsed.cmpAddr && /^(?:0x)?[0-9a-f]+$/i.test(parsed.cmpAddr)) {
        parsed.cmpAddr = parsed.cmpAddr.startsWith('0x') ? parsed.cmpAddr : `0x${parsed.cmpAddr}`;
      }
      parsed.padding = parseFlexibleInt(parsed.padding);
      parsed.bufferSize = parseFlexibleInt(parsed.bufferSize);
      parsed.bufferOffset = parseFlexibleInt(parsed.bufferOffset);
      parsed.captureSize = parseFlexibleInt(parsed.captureSize);
      parsed.maxSteps = parseFlexibleInt(parsed.maxSteps);
      parsed.cmpWidth = parseFlexibleInt(parsed.cmpWidth);
      parsed.cmpValue = parseFlexibleBigInt(parsed.cmpValue);
      return parsed;
    }

    function deriveSuffixFromCmpValue(cmpValue, cmpWidthHint) {
      if (cmpValue === null || cmpValue === undefined) return null;
      let width = cmpWidthHint;
      if (![1, 2, 4, 8].includes(width)) {
        if (cmpValue < 0n) width = 4;
        else if (cmpValue <= 0xffn) width = 1;
        else if (cmpValue <= 0xffffn) width = 2;
        else if (cmpValue <= 0xffffffffn) width = 4;
        else width = 8;
      }
      let masked = BigInt.asUintN(width * 8, cmpValue);
      const bytes = [];
      for (let i = 0; i < width; i += 1) {
        bytes.push(Number(masked & 0xffn));
        masked >>= 8n;
      }
      const printable = bytes.every((b) => b >= 0x20 && b <= 0x7e && b !== 0x2b && b !== 0x2a);
      return printable ? String.fromCharCode(...bytes) : 'B'.repeat(Math.max(4, width));
    }

    function applyDynamicPreset({
      startSymbol,
      targetSymbol,
      payloadExpr,
      payloadTarget,
      maxSteps,
      suggestedOffset,
      suggestedCaptureSize,
      binaryPath,
    }) {
      showPanel('dynamic');
      const presetTargetMode = normalizeDynamicPayloadTargetMode(payloadTarget || getDynamicPayloadTargetMode());
      if (dynamicPayloadTargetMode) dynamicPayloadTargetMode.value = presetTargetMode;
      requestRunTraceInit({
        startSymbol,
        targetSymbol,
        payloadExpr,
        payloadTargetMode: presetTargetMode,
        maxSteps,
        suggestedOffset,
        suggestedCaptureSize,
        binaryPath,
      }, binaryPath);
      runBtn?.focus();
    }

    function runAutoFromNotes() {
      const notesText = document.getElementById('exploitNotes')?.value || '';
      const hint = document.getElementById('exploitAutoHint');
      if (!notesText.trim()) {
        postMessage({ type: 'hubError', message: 'Ajoutez des notes (format key=value).' });
        return false;
      }

      const notes = parseExploitNotes(notesText);
      const bp = getStaticBinaryPath();

      if (notes.cmpAddr) {
        const cmpInput = document.getElementById('exploitCmpAddr');
        if (cmpInput) cmpInput.value = notes.cmpAddr;
      }
      if (notes.startSymbol) {
        const el = document.getElementById('exploitStartSymbol');
        if (el) el.value = notes.startSymbol;
      }
      if (notes.targetSymbol) {
        const el = document.getElementById('exploitTargetSymbol');
        if (el) el.value = notes.targetSymbol;
      }
      if (Number.isFinite(notes.maxSteps) && notes.maxSteps > 0) {
        const el = document.getElementById('exploitMaxSteps');
        if (el) el.value = String(notes.maxSteps);
      }
      if (Number.isFinite(notes.bufferSize) && notes.bufferSize > 0) {
        const el = document.getElementById('exploitBufferSize');
        if (el) el.value = String(notes.bufferSize);
      }
      if (notes.payloadTarget) {
        const targetSel = document.getElementById('exploitPayloadTarget');
        if (targetSel && Array.from(targetSel.options).some((o) => o.value === notes.payloadTarget)) {
          targetSel.value = notes.payloadTarget;
        }
      }

      let payloadExpr = String(notes.payloadExpr || '').trim();
      if (!payloadExpr && Number.isFinite(notes.padding) && notes.padding > 0) {
        let suffix = String(notes.suffix || '').trim();
        if (!suffix) suffix = deriveSuffixFromCmpValue(notes.cmpValue, notes.cmpWidth) || '';
        if (!suffix) suffix = 'CCCC';
        payloadExpr = `A*${notes.padding}+${suffix}`;
        const suffixInput = document.getElementById('exploitPayloadSuffix');
        if (suffixInput) suffixInput.value = suffix;
        const sizeInput = document.getElementById('exploitBufferSize');
        if (sizeInput) sizeInput.value = String(notes.padding);
      }

      if (payloadExpr) {
        const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
        const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
        const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
        const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';
        const is32Bit = Number(getDynamicTraceInitState().archBits) === 32;
        const padding = Number.isFinite(notes.padding) && notes.padding > 0
          ? notes.padding
          : parseFlexibleInt(document.getElementById('exploitBufferSize')?.value || '64') || 64;
        const suggestedOffset = Number.isFinite(notes.bufferOffset)
          ? notes.bufferOffset
          : (is32Bit ? -Math.max(padding + 16, 64) : -Math.max(padding + 32, 96));
        const suggestedCaptureSize = Number.isFinite(notes.captureSize)
          ? notes.captureSize
          : (is32Bit ? Math.max(padding + 48, 96) : Math.max(padding + 64, 128));

        applyDynamicPreset({
          startSymbol,
          targetSymbol,
          payloadExpr,
          payloadTarget,
          maxSteps,
          suggestedOffset,
          suggestedCaptureSize,
          binaryPath: bp,
        });
        if (hint) hint.textContent = `Auto Notes OK: ${payloadExpr} (offset=${suggestedOffset}, capture=${suggestedCaptureSize})`;
        return true;
      }

      if (notes.cmpAddr) {
        if (!bp) {
          postMessage({ type: 'hubError', message: 'Sélectionnez un binaire pour utiliser cmp=...' });
          return false;
        }
        if (hint) hint.textContent = 'Analyse du CMP (depuis notes) en cours…';
        postMessage({ type: 'hubAutoFromCmp', binaryPath: bp, cmpAddr: notes.cmpAddr });
        return true;
      }

      postMessage({
        type: 'hubError',
        message: 'Notes insuffisantes: utilisez payload=..., ou padding=... (+ suffix=.../cmp_value=...), ou cmp=...',
      });
      return false;
    }

    function _initListeners() {
      document.getElementById('btnPrepareDynamic')?.addEventListener('click', () => {
        const startSymbol = document.getElementById('exploitStartSymbol')?.value?.trim() || 'main';
        const targetSymbol = document.getElementById('exploitTargetSymbol')?.value?.trim() || 'win';
        const payloadSuffix = document.getElementById('exploitPayloadSuffix')?.value?.trim() || 'CCCC';
        const payloadTarget = document.getElementById('exploitPayloadTarget')?.value || 'argv1';
        const maxSteps = document.getElementById('exploitMaxSteps')?.value?.trim() || '400';
        const bufferSizeRaw = document.getElementById('exploitBufferSize')?.value?.trim() || '64';
        const bufferSize = parseInt(bufferSizeRaw, 10);
        if (!Number.isFinite(bufferSize) || bufferSize <= 0) {
          postMessage({ type: 'hubError', message: 'Taille buffer invalide.' });
          return;
        }

        const is32Bit = Number(getDynamicTraceInitState().archBits) === 32;
        const suggestedOffset = is32Bit
          ? -Math.max(bufferSize + 16, 64)
          : -Math.max(bufferSize + 32, 96);
        const suggestedCaptureSize = is32Bit
          ? Math.max(bufferSize + 48, 96)
          : Math.max(bufferSize + 64, 128);
        const payloadExpr = `A*${bufferSize}+${payloadSuffix}`;
        applyDynamicPreset({
          startSymbol,
          targetSymbol,
          payloadExpr,
          payloadTarget,
          maxSteps,
          suggestedOffset,
          suggestedCaptureSize,
          binaryPath: getStaticBinaryPath(),
        });
      });

      document.getElementById('btnAutoFromCmp')?.addEventListener('click', () => {
        const cmpAddr = document.getElementById('exploitCmpAddr')?.value?.trim();
        const bp = getStaticBinaryPath();
        if (!bp) {
          postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
          return;
        }
        if (!cmpAddr) {
          postMessage({ type: 'hubError', message: 'Indiquez une adresse CMP.' });
          return;
        }
        const hint = document.getElementById('exploitAutoHint');
        if (hint) hint.textContent = 'Analyse du CMP en cours…';
        postMessage({ type: 'hubAutoFromCmp', binaryPath: bp, cmpAddr });
      });

      document.getElementById('btnAutoFromNotes')?.addEventListener('click', runAutoFromNotes);
      document.getElementById('btnAutoFromNotesWidget')?.addEventListener('click', runAutoFromNotes);
    }

    _initListeners();

    return {
      applyDynamicPreset,
      runAutoFromNotes,
      setTraceField,
    };
  }

  const api = { initDynamicPresetController };
  global.POFHubDynamicPresetController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.dynamicPresetController = api;
  }
})(window);
