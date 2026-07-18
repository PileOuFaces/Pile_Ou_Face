// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Confirmation avant d'ouvrir un fichier volumineux dans un éditeur texte.
 *
 * Le .asm généré par disasm.py grossit proportionnellement au binaire
 * source : sur un gros binaire, `vscode.workspace.openTextDocument` charge
 * le fichier entier dans l'extension host + le renderer, ce qui peut geler
 * VS Code. Ce garde demande confirmation au-delà d'un seuil, et mémorise
 * l'accord de l'utilisateur pour ne pas le redemander à chaque navigation
 * dans le même fichier.
 */

const LARGE_FILE_WARN_BYTES = 50 * 1024 * 1024; // 50 Mo

// Chemins déjà confirmés par l'utilisateur pour la session courante.
const confirmedLargePaths = new Set<string>();

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  const units = ['Ko', 'Mo', 'Go'];
  let size = bytes;
  let unitIndex = -1;
  do {
    size /= 1024;
    unitIndex += 1;
  } while (size >= 1024 && unitIndex < units.length - 1);
  return `${size.toFixed(1)} ${units[unitIndex]}`;
}

/**
 * Retourne true si l'ouverture peut continuer (fichier sous le seuil, déjà
 * confirmé pour cette session, ou l'utilisateur accepte), false sinon.
 */
async function confirmOpenLargeTextFile(filePath, options: { fs?: any; vscode?: any; warnBytes?: number } = {}) {
  const { fs, vscode, warnBytes = LARGE_FILE_WARN_BYTES } = options;
  if (!filePath) return true;
  let sizeBytes = 0;
  try {
    sizeBytes = fs.statSync(filePath).size;
  } catch (_) {
    return true;
  }
  if (sizeBytes < warnBytes) return true;
  if (confirmedLargePaths.has(filePath)) return true;
  const fileName = filePath.split(/[\\/]/).pop() || filePath;
  const choice = await vscode.window.showWarningMessage(
    `${fileName} fait ${formatBytes(sizeBytes)} : l'ouvrir dans l'éditeur peut ralentir ou geler VS Code. Continuer ?`,
    { modal: true },
    'Ouvrir quand même'
  );
  if (choice === 'Ouvrir quand même') {
    confirmedLargePaths.add(filePath);
    return true;
  }
  return false;
}

module.exports = { confirmOpenLargeTextFile, LARGE_FILE_WARN_BYTES };
