/**
 * @file dom.js
 * @brief Cache DOM pour la webview Pile ou Face.
 * @details Centralise les elements afin de limiter les queries.
 */
/**
 * @brief Cree les references DOM Runtime depuis une racine optionnelle.
 */
export function createRuntimeDom(root = null) {
  const scope = resolveRuntimeRoot(root);
  const doc = scope?.ownerDocument || document;
  const q = (selector) => {
    if (!selector || !scope) return null;
    if (typeof scope.matches === 'function' && scope.matches(selector)) return scope;
    return scope.querySelector(selector) || (scope !== doc ? doc.querySelector(selector) : null);
  };

  const controls = {
    prev: q('#btnPrev'),
    next: q('#btnNext'),
    range: q('#stepRange'),
    showAllTrace: q('#showAllTrace'),
    focusLabel: q('#focusLabel'),
    stackModeFrame: q('#stackModeFrame'),
    stackModeExpert: q('#stackModeExpert'),
    stackModeAdvanced: q('#stackModeAdvanced')
  };

  const panels = {
    runtime: q('#panel-runtime'),
    asm: q('#disasmPanel'),
    stack: q('#stackPanel'),
    explain: q('[data-runtime-panel="explain"]') || q('#explainPanel'),
    dump: q('[data-runtime-panel="dump"]') || q('#dumpPanel'),
    registers: q('[data-runtime-panel="registers"]') || q('#registersPanel')
  };

  const outputs = {
    status: q('#status'),
    stack: q('#stack'),
    registers: q('#registers'),
    risks: q('#risks'),
    dump: q('#memoryDump'),
    explain: q('#explainBody'),
    asm: q('#disasmList')
  };

  return {
    root: scope,
    controls,
    panels,
    outputs,

    // Backward-compatible flat aliases used by current renderers.
    status: outputs.status,
    stack: outputs.stack,
    registers: outputs.registers,
    risks: outputs.risks,
    memoryDump: outputs.dump,
    frameContext: q('#frameContext'),
    explainPanel: panels.explain,
    explainBody: outputs.explain,
    explainSubtitle: q('#explainSubtitle'),
    disasmPanel: panels.asm,
    disasmList: outputs.asm,
    disasmSubtitle: q('#disasmSubtitle'),
    stepLabel: q('#stepLabel'),
    stepRange: controls.range,
    showAllTrace: controls.showAllTrace,
    focusLabel: controls.focusLabel,
    btnPrev: controls.prev,
    btnNext: controls.next,
    legend: q('#stackLegend'),
    stackSummary: q('#stackSummary'),
    stackModeFrame: controls.stackModeFrame,
    stackModeExpert: controls.stackModeExpert,
    stackModeAdvanced: controls.stackModeAdvanced,
    stackWorkspace: q('#stackWorkspace'),
    stackWorkspaceTitle: q('#stackWorkspaceTitle'),
    stackWorkspaceSubtitle: q('#stackWorkspaceSubtitle'),
    stackWorkspaceBack: q('#stackWorkspaceBack'),
    stackFunctions: q('#stackFunctions'),
    stackDetail: q('#stackDetail')
  };
}

function resolveRuntimeRoot(root) {
  if (root && typeof root.querySelector === 'function') return root;
  return document.getElementById('panel-runtime') || document;
}

/**
 * @brief References DOM reutilisees par les renderers.
 */
export const dom = createRuntimeDom();
