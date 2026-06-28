/**
 * @file stackViewMode.js
 * @brief Stack panel view mode — simple / expert.
 * @details Pure state helpers with injectable storage for testability.
 */

export const STACK_PANEL_MODE_KEY = 'pile-ou-face-stack-panel-mode';

/** @returns {'simple'|'expert'} */
export function normalizeStackPanelMode(mode) {
  return mode === 'expert' ? 'expert' : 'simple';
}

/** @param {Storage} [storage] */
export function restoreStackPanelMode(storage = globalThis.localStorage) {
  try {
    return normalizeStackPanelMode(storage?.getItem(STACK_PANEL_MODE_KEY));
  } catch (_) {
    return 'simple';
  }
}

/** @param {'simple'|'expert'} mode @param {Storage} [storage] */
export function persistStackPanelMode(mode, storage = globalThis.localStorage) {
  try {
    storage?.setItem(STACK_PANEL_MODE_KEY, normalizeStackPanelMode(mode));
  } catch (_) { /* ignore */ }
}

/**
 * Resolve which render strategy to apply.
 * @param {'simple'|'expert'} mode
 * @returns {'simple'|'expert'}
 */
export function resolveStackPanelRenderMode(mode) {
  return normalizeStackPanelMode(mode);
}
