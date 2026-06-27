/**
 * @file disasm.js
 * @brief Helpers de desassemblage pour la webview.
 * @details Demande a l'extension d'ouvrir et surligner l'instruction courante.
 */
import { findDisasmEntryForAddress } from './disasmPanel.js';

/**
 * @brief Demande l'ouverture/surlignage de la ligne d'instruction.
 * @param vscode API VS Code webview.
 * @param state Etat courant.
 * @param currentAddr Adresse courante (RIP/EIP).
 */
export function highlightDisasmFile(vscode, state, currentAddr) {
  // Requires disasm metadata + line mapping from the backend.
  if (!state.meta.disasm_path || !Array.isArray(state.disasmLines) || state.disasmLines.length === 0) {
    return;
  }
  const match = findDisasmEntryForAddress(state.disasmLines, currentAddr);
  const entry = match?.entry;
  if (!entry || typeof entry.line !== 'number') return;
  // Avoid re-highlighting the same line.
  if (state.lastDisasmLine === entry.line) return;
  state.lastDisasmLine = entry.line;

  // Ask the extension to open the file and reveal the line.
  vscode.postMessage({
    type: 'goToLine',
    line: entry.line,
    file: state.meta.disasm_path
  });
}
