// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file hub/settingsActions.ts
 * @brief Handlers des réglages du hub : lecture, enregistrement validé par schéma,
 *        réinitialisation et sélection native de pythonPath (POF-P1-002).
 */

const {
  SETTINGS_STATE_KEY,
  PYTHON_PATH_ATTESTATION_KEY,
  cloneSettingsDefaults,
  readStoredSettings,
  readSettingsWithDefaults,
  validateSettingsUpdate,
} = require('../../shared/settingsSchema');
const { selectPythonExecutable: defaultSelectPythonExecutable } = require('../../shared/pythonPathSelection');

function createSettingsActions({
  panel,
  context,
  vscode,
  root,
  logChannel,
  selectPythonExecutable = defaultSelectPythonExecutable,
}) {
  const store = context.globalState;
  // Read-modify-write of the stored settings, one at a time: an update must not be built from a
  // snapshot taken before another update was written (e.g. a save during the pythonPath write).
  let writes = Promise.resolve();
  const serialized = (task) => {
    const run = writes.then(task);
    writes = run.catch(() => {});
    return run;
  };
  const postSettings = (requestId) => panel.webview.postMessage({
    type: 'hubSettings',
    settings: readSettingsWithDefaults(store),
    requestId,
  });

  return {
    hubGetSettings: async (message) => {
      postSettings(message?.requestId);
    },

    hubSaveSettings: (message) => serialized(async () => {
      const result = validateSettingsUpdate(message?.settings, readStoredSettings(store));
      if (!result.ok) {
        const details = result.errors.join('; ');
        logChannel?.appendLine?.(`[Settings] Rejected settings update: ${details}`);
        vscode.window.showErrorMessage(`Pile ou Face: settings were not saved (${details}).`);
        panel.webview.postMessage({ type: 'hubSettingsSaved', ok: false, errors: result.errors, requestId: message?.requestId });
        return;
      }
      await store.update(SETTINGS_STATE_KEY, result.settings);
      panel.webview.postMessage({ type: 'hubSettingsSaved', ok: true, requestId: message?.requestId });
    }),

    hubResetSettings: (message) => serialized(async () => {
      await store.update(SETTINGS_STATE_KEY, cloneSettingsDefaults());
      await store.update(PYTHON_PATH_ATTESTATION_KEY, undefined);
      postSettings(message?.requestId);
    }),

    hubSelectPythonPath: async (message) => {
      const defaultPath = readStoredSettings(store).pythonPath || root;
      const selection = await selectPythonExecutable(vscode, { defaultPath });
      if (selection.ok) {
        // Le sélecteur est ouvert hors de la file : les sauvegardes restent possibles pendant ce
        // temps. L'écriture, elle, relit les réglages dans la file, après toute sauvegarde acquittée.
        await serialized(async () => {
          // Attestation d'abord : le pythonPath enregistré n'est réutilisé que s'il est attesté.
          await store.update(PYTHON_PATH_ATTESTATION_KEY, selection.path);
          await store.update(SETTINGS_STATE_KEY, { ...readStoredSettings(store), pythonPath: selection.path });
        });
        logChannel?.appendLine?.(`[Settings] pythonPath set to ${selection.path}`);
      } else if (!selection.cancelled) {
        logChannel?.appendLine?.(`[Settings] pythonPath selection rejected: ${selection.error}`);
        vscode.window.showErrorMessage(`Pile ou Face: ${selection.error}`);
      }
      // Toujours appliqué par le formulaire, même si une sauvegarde locale était en attente
      // (requestId absent) : le champ affiche l'interpréteur réellement utilisé.
      panel.webview.postMessage({ type: 'hubPythonPathSelected', pythonPath: readStoredSettings(store).pythonPath || '' });
      if (message?.requestId != null) postSettings(message.requestId);
    },
  };
}

module.exports = { createSettingsActions };
