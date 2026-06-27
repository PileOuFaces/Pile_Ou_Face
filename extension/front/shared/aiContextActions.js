// SPDX-License-Identifier: AGPL-3.0-only
(function initAiContextActions(global) {
  const DEFAULT_MAX_CONTEXT_CHARS = 6000;

  const VIEW_CONFIGS = Object.freeze({
    cfg: {
      label: 'CFG',
      sourceSelector: '#cfgContent',
      contextBarSelector: '#cfgContextBar',
      instruction: 'Explique le flux de contrôle, les branches, les boucles et les chemins qui méritent une vérification.',
    },
    decompile: {
      label: 'pseudo-C',
      sourceSelector: '#decompileContent',
      contextBarSelector: '#decompileContextBar',
      instruction: 'Explique le comportement du pseudo-code, les appels importants et les risques potentiels.',
    },
    strings: {
      label: 'strings',
      sourceSelector: '#stringsContent',
      instruction: 'Classe les chaînes utiles, relève les indicateurs suspects et propose les prochains pivots d’analyse.',
    },
    imports: {
      label: 'imports',
      sourceSelector: '#importsContent',
      contextBarSelector: '#importsContextBar',
      instruction: 'Interprète les capacités suggérées par les imports, leur niveau de risque et les vérifications à effectuer.',
    },
    search: {
      label: 'résultats de recherche',
      sourceSelector: '#searchResultsBody',
      querySelector: '#searchBinaryPattern',
      instruction: 'Interprète les correspondances, relie les offsets et adresses pertinents et propose les prochains pivots.',
    },
  });

  function normalizeText(value) {
    return String(value || '')
      .replace(/\r\n?/g, '\n')
      .replace(/[ \t]+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  function clipText(value, maxChars = DEFAULT_MAX_CONTEXT_CHARS) {
    const text = normalizeText(value);
    const limit = Math.max(200, Number(maxChars || DEFAULT_MAX_CONTEXT_CHARS));
    if (text.length <= limit) {
      return { text, truncated: false, originalChars: text.length };
    }
    const marker = '\n\n[… contexte tronqué …]\n\n';
    const available = Math.max(1, limit - marker.length);
    const headLength = Math.ceil(available * 0.75);
    const tailLength = Math.max(0, available - headLength);
    return {
      text: `${text.slice(0, headLength)}${marker}${text.slice(-tailLength)}`,
      truncated: true,
      originalChars: text.length,
    };
  }

  function cleanContextValue(value, prefix) {
    const normalized = normalizeText(value)
      .replace(new RegExp(`^${prefix}\\s*:\\s*`, 'i'), '')
      .trim();
    return normalized === '—' ? '' : normalized;
  }

  function readElementText(documentRef, selector) {
    const element = documentRef?.querySelector?.(selector);
    if (!element) return '';
    return normalizeText(element.innerText || element.textContent || '');
  }

  function collectAnalysisContext(documentRef, view, extras = {}) {
    const config = VIEW_CONFIGS[view];
    if (!config) return null;
    const contextBar = config.contextBarSelector
      ? documentRef?.querySelector?.(config.contextBarSelector)
      : null;
    const functionName = cleanContextValue(
      contextBar?.querySelector?.('[data-role="function"]')?.textContent,
      'Fonction',
    );
    const address = cleanContextValue(
      contextBar?.querySelector?.('[data-role="address"]')?.textContent,
      'Adresse',
    );
    const query = config.querySelector
      ? String(documentRef?.querySelector?.(config.querySelector)?.value || '').trim()
      : '';
    return {
      view,
      binaryPath: String(extras.binaryPath || '').trim(),
      binaryMeta: extras.binaryMeta || {},
      functionName,
      address,
      query,
      filters: normalizeText(extras.filters),
      content: readElementText(documentRef, config.sourceSelector),
    };
  }

  function buildAnalysisPrompt(context, options = {}) {
    const config = VIEW_CONFIGS[context?.view];
    if (!config) return '';
    const clipped = clipText(context.content, options.maxContextChars);
    if (!clipped.text) return '';
    const meta = context.binaryMeta || {};
    const details = [
      context.binaryPath ? `Fichier : ${context.binaryPath}` : '',
      meta.kind || meta.format ? `Format : ${meta.kind || meta.format}` : '',
      meta.arch ? `Architecture : ${meta.arch}` : '',
      context.functionName ? `Fonction : ${context.functionName}` : '',
      context.address ? `Adresse : ${context.address}` : '',
      context.query ? `Recherche : ${context.query}` : '',
      context.filters ? `Filtres : ${context.filters}` : '',
    ].filter(Boolean);
    const truncation = clipped.truncated
      ? `\nLe contexte a été limité à ${clipped.text.length} caractères sur ${clipped.originalChars}.`
      : '';
    return [
      `Analyse ce contexte extrait de la vue ${config.label} de Pile ou Face.`,
      details.join('\n'),
      '',
      config.instruction,
      'Appuie-toi sur les adresses et valeurs fournies et signale clairement les informations manquantes au lieu de les inventer.',
      truncation,
      '',
      `Contexte ${config.label} :`,
      '```text',
      clipped.text,
      '```',
    ].filter((line, index, lines) => line !== '' || lines[index - 1] !== '').join('\n').trim();
  }

  const api = {
    DEFAULT_MAX_CONTEXT_CHARS,
    VIEW_CONFIGS,
    buildAnalysisPrompt,
    clipText,
    collectAnalysisContext,
    normalizeText,
  };
  global.POFAiContextActions = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
