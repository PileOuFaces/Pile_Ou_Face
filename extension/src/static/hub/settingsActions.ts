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
  const reportWriteFailure = (action, err) => {
    const reason = err?.message || String(err);
    logChannel?.appendLine?.(`[Settings] ${action} failed: ${reason}`);
    vscode.window.showErrorMessage(`Pile ou Face: ${action} failed (${reason}).`);
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
      try {
        await store.update(SETTINGS_STATE_KEY, result.settings);
      } catch (err) {
        // Always acknowledge: the form waits for this answer before it reloads the settings.
        reportWriteFailure('saving settings', err);
        panel.webview.postMessage({ type: 'hubSettingsSaved', ok: false, errors: ['storage error'], requestId: message?.requestId });
        return;
      }
      panel.webview.postMessage({ type: 'hubSettingsSaved', ok: true, requestId: message?.requestId });
    }),

    hubResetSettings: (message) => serialized(async () => {
      try {
        await store.update(SETTINGS_STATE_KEY, cloneSettingsDefaults());
        await store.update(PYTHON_PATH_ATTESTATION_KEY, undefined);
      } catch (err) {
        reportWriteFailure('resetting settings', err);
      } finally {
        postSettings(message?.requestId);
      }
    }),

    hubSelectPythonPath: async (message) => {
      const defaultPath = readStoredSettings(store).pythonPath || root;
      const selection = await selectPythonExecutable(vscode, { defaultPath });
      let changed = false;
      if (selection.ok) {
        // Le sélecteur est ouvert hors de la file : les sauvegardes restent possibles pendant ce
        // temps. L'écriture, elle, relit les réglages dans la file, après toute sauvegarde acquittée.
        try {
          await serialized(async () => {
            // 1. B attesté en plus de A ; 2. réglage B ; 3. B seul. À chaque étape, le pythonPath
            // enregistré reste attesté : un lecteur concurrent ou un échec d'écriture garde A ou B.
            // Seul le chemin en service (déjà attesté) reste valide pendant la transition.
            const inUse = readStoredSettings(store).pythonPath;
            const transition = inUse && inUse !== selection.path ? [selection.path, inUse] : selection.path;
            await store.update(PYTHON_PATH_ATTESTATION_KEY, transition);
            await store.update(SETTINGS_STATE_KEY, { ...readStoredSettings(store), pythonPath: selection.path });
            await store.update(PYTHON_PATH_ATTESTATION_KEY, selection.path);
          });
          changed = true;
          logChannel?.appendLine?.(`[Settings] pythonPath set to ${selection.path}`);
        } catch (err) {
          reportWriteFailure('saving pythonPath', err);
        }
      } else if (!selection.cancelled) {
        logChannel?.appendLine?.(`[Settings] pythonPath selection rejected: ${selection.error}`);
        vscode.window.showErrorMessage(`Pile ou Face: ${selection.error}`);
      }
      // Toujours appliqué par le formulaire, même si une sauvegarde locale était en attente
      // (requestId absent) : le champ affiche l'interpréteur réellement utilisé.
      // `changed` : seule une sélection enregistrée remplace une demande « Auto » encore en attente.
      panel.webview.postMessage({ type: 'hubPythonPathSelected', changed, pythonPath: readStoredSettings(store).pythonPath || '' });
      if (message?.requestId != null) postSettings(message.requestId);
    },
  };
}

module.exports = { createSettingsActions };
