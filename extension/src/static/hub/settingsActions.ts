// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file hub/settingsActions.ts
 * @brief Handlers des réglages du hub : lecture, enregistrement validé par schéma,
 *        réinitialisation et sélection native de pythonPath (POF-P1-002) et des dossiers
 *        de décompilateurs locaux (#531).
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
const { DECOMPILER_PATHS_ATTESTATION_KEY, isSupportedDecompilerId } = require('../../shared/decompilerPathsSchema');
const { selectInstallFolder: defaultSelectInstallFolder } = require('../../shared/decompilerLocalPaths');

function createSettingsActions({
  panel,
  context,
  vscode,
  root,
  logChannel,
  selectPythonExecutable = defaultSelectPythonExecutable,
  selectInstallFolder = defaultSelectInstallFolder,
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
        await store.update(DECOMPILER_PATHS_ATTESTATION_KEY, undefined);
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

    // #531 : effacement explicite d'un dossier (retour à l'auto-détection) : entrée et attestation.
    hubClearDecompilerLocalPath: (message) => serialized(async () => {
      const decompilerId = message?.decompilerId;
      if (!isSupportedDecompilerId(decompilerId)) {
        panel.webview.postMessage({ type: 'hubDecompilerLocalPathSelected', decompilerId: null, changed: false, path: '' });
        return;
      }
      let changed = false;
      try {
        const settings = readStoredSettings(store);
        const paths = { ...(settings.decompilerLocalPaths || {}) };
        delete paths[decompilerId];
        await store.update(SETTINGS_STATE_KEY, { ...settings, decompilerLocalPaths: paths });
        const attested = { ...(store.get(DECOMPILER_PATHS_ATTESTATION_KEY, {}) || {}) };
        delete attested[decompilerId];
        await store.update(DECOMPILER_PATHS_ATTESTATION_KEY, attested);
        changed = true;
      } catch (err) {
        reportWriteFailure(`clearing the ${decompilerId} folder`, err);
      }
      const remaining = (readStoredSettings(store).decompilerLocalPaths || {})[decompilerId] || '';
      panel.webview.postMessage({ type: 'hubDecompilerLocalPathSelected', decompilerId, changed, path: remaining });
    }),

    // #531 : seul le dialogue natif du Host fixe un dossier de décompilateur local.
    hubSelectDecompilerLocalPath: async (message) => {
      const decompilerId = message?.decompilerId;
      if (!isSupportedDecompilerId(decompilerId)) {
        logChannel?.appendLine?.(`[Settings] decompiler folder selection refused: unsupported ${String(decompilerId)}`);
        panel.webview.postMessage({ type: 'hubDecompilerLocalPathSelected', decompilerId: null, changed: false, path: '' });
        return;
      }
      const currentPaths = () => readStoredSettings(store).decompilerLocalPaths || {};
      const selection = await selectInstallFolder(vscode, decompilerId, { defaultPath: currentPaths()[decompilerId] || '' });
      let changed = false;
      if (selection.ok) {
        try {
          await serialized(async () => {
            // Même transition que pythonPath : le dossier en service reste attesté jusqu'à
            // l'écriture du nouveau, puis seul le nouveau l'est.
            const attested = store.get(DECOMPILER_PATHS_ATTESTATION_KEY, {}) || {};
            const inUse = currentPaths()[decompilerId];
            const transition = inUse && inUse !== selection.path ? [selection.path, inUse] : selection.path;
            await store.update(DECOMPILER_PATHS_ATTESTATION_KEY, { ...attested, [decompilerId]: transition });
            const settings = readStoredSettings(store);
            const paths = { ...(settings.decompilerLocalPaths || {}), [decompilerId]: selection.path };
            await store.update(SETTINGS_STATE_KEY, { ...settings, decompilerLocalPaths: paths });
            await store.update(DECOMPILER_PATHS_ATTESTATION_KEY, { ...attested, [decompilerId]: selection.path });
          });
          changed = true;
          logChannel?.appendLine?.(`[Settings] ${decompilerId} folder set to ${selection.path}`);
        } catch (err) {
          reportWriteFailure(`saving the ${decompilerId} folder`, err);
        }
      } else if (!selection.cancelled) {
        logChannel?.appendLine?.(`[Settings] ${decompilerId} folder rejected: ${selection.error}`);
        vscode.window.showErrorMessage(`Pile ou Face: ${selection.error}`);
      }
      panel.webview.postMessage({
        type: 'hubDecompilerLocalPathSelected',
        decompilerId,
        changed,
        path: currentPaths()[decompilerId] || '',
      });
    },
  };
}

module.exports = { createSettingsActions };
