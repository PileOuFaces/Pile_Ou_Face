/**
 * @file stackEmptyState.js
 * @brief Shared renderer for stack empty/no-model states.
 */

export function renderStackEmptyState(container, frameModel, {
  documentRef = typeof document !== 'undefined' ? document : null,
  onJumpToStep,
  fallbackText = 'Choisissez une fonction pour afficher sa frame.'
} = {}) {
  if (!container || !documentRef) return null;
  const empty = documentRef.createElement('div');
  empty.className = 'stack-empty';
  const emptyState = frameModel?.emptyState && typeof frameModel.emptyState === 'object'
    ? frameModel.emptyState
    : null;
  if (!emptyState) {
    empty.textContent = frameModel?.emptyText || fallbackText;
    container.appendChild(empty);
    return empty;
  }

  appendLine(empty, documentRef, 'stack-empty-message', emptyState.message || frameModel?.emptyText || '');
  appendLine(empty, documentRef, 'stack-empty-guidance', emptyState.guidance || '');
  appendLine(empty, documentRef, 'stack-empty-missing-step', emptyState.noExecutedStepText || '');

  const actionStep = Number(emptyState.actionStep);
  if (emptyState.actionLabel && Number.isFinite(actionStep) && typeof onJumpToStep === 'function') {
    const action = documentRef.createElement('button');
    action.type = 'button';
    action.className = 'stack-empty-action';
    action.textContent = emptyState.actionLabel;
    action.addEventListener('click', () => onJumpToStep(actionStep));
    empty.appendChild(action);
  }

  container.appendChild(empty);
  return empty;
}

function appendLine(parent, documentRef, className, text) {
  if (!text) return null;
  const line = documentRef.createElement('div');
  line.className = className;
  line.textContent = text;
  parent.appendChild(line);
  return line;
}
