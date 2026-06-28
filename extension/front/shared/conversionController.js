// @ts-nocheck

(function initPwnConversionController(global) {
  const state = {
    byteDisplay: 'spaced',
    currentResult: null,
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const el = byId(id);
    if (el) el.textContent = value || '—';
  }

  function setCopiedFeedback(target) {
    const el = typeof target === 'string' ? byId(target) : target;
    if (!el) return;
    el.classList.add('copied');
    setTimeout(() => el.classList.remove('copied'), 650);
  }

  function renderWarnings(warnings) {
    const list = byId('pwnConverterWarnings');
    if (!list) return;
    list.replaceChildren();
    if (!warnings?.length) {
      list.hidden = true;
      return;
    }
    list.hidden = false;
    warnings.forEach((warning) => {
      const item = document.createElement('li');
      item.textContent = warning;
      list.appendChild(item);
    });
  }

  function setStatus(text, isError = false) {
    const status = byId('pwnConverterStatus');
    if (!status) return;
    status.textContent = text || '';
    status.classList.toggle('error', !!isError);
  }

  function formatByteField(bytes) {
    const formatter = global.POFHubConversionUtils?.formatDisplayBytes;
    return typeof formatter === 'function'
      ? formatter(bytes || [], state.byteDisplay)
      : String(bytes || '—');
  }

  function renderMeta(meta) {
    const el = byId('pwnConverterMeta');
    if (!el) return;
    if (!meta) {
      el.textContent = '';
      return;
    }
    el.textContent = [
      `${meta.usefulBytes} byte${meta.usefulBytes > 1 ? 's' : ''} utile${meta.usefulBytes > 1 ? 's' : ''}`,
      `fits 32-bit: ${meta.fits32 ? 'oui' : 'non'}`,
      `fits 64-bit: ${meta.fits64 ? 'oui' : 'non'}`,
      meta.recommendation,
    ].join(' · ');
  }

  function syncByteDisplayButtons() {
    document.querySelectorAll('[data-byte-display]').forEach((button) => {
      const active = button.dataset.byteDisplay === state.byteDisplay;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }

  function renderConversion(result) {
    state.currentResult = result;
    const outputIds = {
      hex: 'pwnConverterHex',
      decimal: 'pwnConverterDecimal',
      ascii: 'pwnConverterAscii',
      escaped: 'pwnConverterEscaped',
      p32: 'pwnConverterP32',
      p64: 'pwnConverterP64',
      u32: 'pwnConverterU32',
      u64: 'pwnConverterU64',
      unsigned32: 'pwnConverterUnsigned32',
      signed32: 'pwnConverterSigned32',
      unsigned64: 'pwnConverterUnsigned64',
      signed64: 'pwnConverterSigned64',
      hexdump: 'pwnConverterHexdump',
    };

    Object.entries(outputIds).forEach(([key, id]) => {
      setText(id, result?.ok ? result.outputs?.[key] : '—');
    });
    setText('pwnConverterLittle32', result?.ok ? formatByteField(result.byteFields?.little32) : '—');
    setText('pwnConverterLittle64', result?.ok ? formatByteField(result.byteFields?.little64) : '—');
    setText('pwnConverterBig32', result?.ok ? formatByteField(result.byteFields?.big32) : '—');
    setText('pwnConverterBig64', result?.ok ? formatByteField(result.byteFields?.big64) : '—');
    renderMeta(result?.ok ? result.meta : null);
    renderWarnings(result?.warnings || []);
    setStatus(result?.ok ? `Format détecté: ${result.inputKind}` : (result?.error || 'Entrée invalide'), !result?.ok);
    syncByteDisplayButtons();
  }

  async function copyOutput(button) {
    const target = button?.dataset?.copyConversion;
    const value = target ? byId(target)?.textContent || '' : button?.textContent || '';
    if (!value || value === '—') return;
    try {
      await navigator.clipboard?.writeText(value);
      setCopiedFeedback(button);
      if (target) setCopiedFeedback(target);
      setStatus('Copied');
    } catch (_) {
      setStatus('Copie impossible', true);
    }
  }

  function initConversionController() {
    const input = byId('pwnConverterInput');
    if (!input || !global.POFHubConversionUtils?.convertPwnValue) return null;
    const convert = () => renderConversion(global.POFHubConversionUtils.convertPwnValue(input.value));
    input.addEventListener('input', convert);
    input.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      convert();
    });
    document.querySelectorAll('[data-copy-conversion]').forEach((button) => {
      button.addEventListener('click', () => copyOutput(button));
    });
    document.querySelectorAll('.pwn-converter-output code').forEach((output) => {
      output.tabIndex = 0;
      output.title = 'Copy';
      output.addEventListener('click', () => copyOutput(output));
      output.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        copyOutput(output);
      });
    });
    document.querySelectorAll('[data-byte-display]').forEach((button) => {
      button.addEventListener('click', () => {
        state.byteDisplay = button.dataset.byteDisplay === 'compact' ? 'compact' : 'spaced';
        renderConversion(state.currentResult || global.POFHubConversionUtils.convertPwnValue(input.value));
      });
    });
    convert();
    return { convert };
  }

  const api = { initConversionController };
  global.POFHubConversionController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.conversionController = api;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => initConversionController(), { once: true });
  } else {
    initConversionController();
  }
})(window);
