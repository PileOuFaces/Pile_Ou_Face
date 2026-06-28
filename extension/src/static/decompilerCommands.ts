// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file decompilerCommands.js
 * @brief Commandes VS Code pour gérer les décompilateurs dynamiquement.
 *
 * Commandes enregistrées :
 *   pileOuFace.decompilerAdd        — Wizard complet d'ajout (Docker / local / les deux)
 *   pileOuFace.decompilerEdit       — Modifier un décompilateur custom existant
 *   pileOuFace.decompilerRemove     — Supprimer un décompilateur custom
 *   pileOuFace.decompilerList       — Lister tous les décompilateurs (avec statut dispo)
 *   pileOuFace.decompilerTest       — Tester un décompilateur sur un binaire
 *   pileOuFace.decompilerOpenConfig — Ouvrir storageDir/decompilers.json dans l'éditeur
 */

'use strict';

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildRuntimeEnv, resolveDockerExecutable, getExtensionPath } = require('../shared/utils');

// ─── Constantes ───────────────────────────────────────────────────────────────

/** Tokens disponibles dans les commandes */
const TOKEN_HELP = 'Tokens : {binary} {addr} {func_name} {mode} {out}';

/** Formats de sortie supportés */
const OUTPUT_FORMATS = [
  { label: 'JSON (recommandé)', description: 'Sortie JSON {code, addr, functions…}', value: 'json' },
  { label: 'C brut', description: 'Code C direct, parsé automatiquement en blocs', value: 'c' },
  { label: 'Texte brut', description: 'Sortie quelconque retournée telle quelle', value: 'text' },
];

// ─── Helpers config ───────────────────────────────────────────────────────────

function _configPath(storageDir) {
  return path.join(storageDir, 'decompilers.json');
}

function _readConfig(storageDir) {
  const p = _configPath(storageDir);
  try {
    if (!fs.existsSync(p)) return { decompilers: {} };
    const raw = fs.readFileSync(p, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.decompilers || typeof parsed.decompilers !== 'object') return { decompilers: {} };
    return parsed;
  } catch (_) {
    return { decompilers: {} };
  }
}

function _writeConfig(storageDir, config) {
  if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir, { recursive: true });
  fs.writeFileSync(_configPath(storageDir), JSON.stringify(config, null, 2), 'utf8');
}

function _normalizeId(id) {
  return String(id || '').toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '');
}

/** Vérifie si une image Docker est disponible localement (synchrone, rapide). */
function _checkDockerImageSync(image) {
  try {
    const dockerExe = resolveDockerExecutable();
    const r = cp.spawnSync(dockerExe, ['image', 'inspect', image], {
      encoding: 'utf8',
      timeout: 4000,
      env: buildRuntimeEnv(''),
    });
    return r.status === 0;
  } catch (_) {
    return false;
  }
}

/** Retourne les images Docker locales dont le nom contient `hint` */
function _suggestDockerImages(hint) {
  try {
    const dockerExe = resolveDockerExecutable();
    const r = cp.spawnSync(
      dockerExe, ['images', '--format', '{{.Repository}}:{{.Tag}}'],
      { encoding: 'utf8', timeout: 4000, env: buildRuntimeEnv('') }
    );
    if (r.status !== 0) return [];
    return r.stdout.split('\n').map(s => s.trim()).filter(s => s && s !== '<none>:<none>');
  } catch (_) {
    return [];
  }
}

function _dockerMissingImageHint(id, image) {
  const normalizedId = _normalizeId(id);
  const normalizedImage = String(image || '').trim().toLowerCase();
  if (normalizedImage.startsWith('pile-ou-face/decompiler-')) {
    return `Construis-la d'abord avec: make decompiler-docker-build DECOMPILER=${normalizedId}`;
  }
  return `Fais un 'docker pull ${image}' ou utilise une image registry valide.`;
}

// ─── Wizard d'ajout / modification ───────────────────────────────────────────

/**
 * Wizard structuré en étapes claires.
 * @param {string} root
 * @param {string} storageDir
 * @param {string|null} editId — ID existant à modifier (null = ajout)
 */
async function cmdDecompilerAdd(root, storageDir, editId = null) {
  const cfg = _readConfig(storageDir);
  const isEdit = editId !== null;
  const existing = isEdit ? (cfg.decompilers[editId] || {}) : {};

  // ── ÉTAPE 1 : Identité ────────────────────────────────────────────────────
  const rawId = await vscode.window.showInputBox({
    title: isEdit ? `Modifier "${editId}" — ID` : 'Nouveau décompilateur — Identifiant',
    prompt: 'Identifiant unique (lettres, chiffres, tirets). Ex: binja, idalite, my-tool',
    value: isEdit ? editId : '',
    validateInput: (v) => {
      const n = _normalizeId(v);
      if (!n) return 'ID invalide (utilise lettres, chiffres, tirets)';
      if (!isEdit && cfg.decompilers[n]) return `"${n}" existe déjà — utilise "Modifier" pour l'éditer`;
      return null;
    },
  });
  if (rawId === undefined) return;
  const id = _normalizeId(rawId);

  const label = await vscode.window.showInputBox({
    title: `"${id}" — Nom affiché`,
    prompt: 'Label visible dans l\'interface Pile ou Face',
    value: existing.label || id,
  });
  if (label === undefined) return;

  // ── ÉTAPE 2 : Mode d'exécution ────────────────────────────────────────────
  const modeChoice = await vscode.window.showQuickPick(
    [
      {
        label: '$(cloud) Docker uniquement',
        description: 'L\'outil tourne dans un container Docker',
        detail: 'Idéal pour les outils difficiles à installer localement (Ghidra, IDA…)',
        value: 'docker',
      },
      {
        label: '$(terminal) Local uniquement',
        description: 'L\'outil est installé sur ta machine',
        detail: 'Plus rapide, pas besoin de Docker',
        value: 'local',
      },
      {
        label: '$(repo-sync) Local + Docker (fallback)',
        description: 'Essaie local d\'abord, Docker si indisponible',
        detail: 'Le mode "auto" de Pile ou Face gère le fallback automatiquement',
        value: 'both',
      },
    ],
    {
      title: `"${id}" — Mode d'exécution`,
      placeHolder: 'Choisir comment lancer ce décompilateur',
    }
  );
  if (!modeChoice) return;
  const mode = modeChoice.value;

  const config = { label: label || id };

  // ── ÉTAPE 3 : Configuration Docker ───────────────────────────────────────
  if (mode === 'docker' || mode === 'both') {
    // Suggestion d'images disponibles
    const localImages = _suggestDockerImages(id);
    const defaultImage = existing.docker_image
      || localImages.find(i => i.includes(id))
      || `pile-ou-face/decompiler-${id}:latest`;

    const dockerImage = await vscode.window.showInputBox({
      title: `"${id}" — Image Docker`,
      prompt: localImages.length
        ? `Images disponibles : ${localImages.slice(0, 3).join(', ')}`
        : 'Ex: pile-ou-face/decompiler-mytool:latest  ou  registry.io/mytool:1.0',
      value: defaultImage,
      validateInput: (v) => {
        if (!v.trim()) return 'Image requise';
        if (v.includes(' ')) return 'Le nom d\'image ne doit pas contenir d\'espace';
        return null;
      },
    });
    if (dockerImage === undefined) return;
    config.docker_image = dockerImage.trim();

    // Vérification de disponibilité de l'image
    const imageOk = _checkDockerImageSync(config.docker_image);
    if (!imageOk) {
      const pullChoice = await vscode.window.showWarningMessage(
        `L'image "${config.docker_image}" n'est pas disponible localement.\n${_dockerMissingImageHint(id, config.docker_image)}`,
        { modal: false },
        'Continuer quand même',
        'Annuler'
      );
      if (pullChoice !== 'Continuer quand même') return;
    }

    // Commande Docker — fonction
    const dockerCmd = await vscode.window.showInputBox({
      title: `"${id}" — Commande Docker (décompilation de fonction)`,
      prompt: TOKEN_HELP + '  •  Laisser vide si non supporté',
      value: existing.docker_command
        ? existing.docker_command.join(' ')
        : `/usr/bin/${id} --json {binary} --addr {addr}`,
      validateInput: (v) => {
        if (!v.trim() && mode === 'docker') return 'Commande requise pour le mode Docker-only';
        return null;
      },
    });
    if (dockerCmd === undefined) return;
    if (dockerCmd.trim()) config.docker_command = _splitCommand(dockerCmd.trim());

    // Commande Docker — binaire complet
    const dockerFullCmd = await vscode.window.showInputBox({
      title: `"${id}" — Commande Docker (binaire complet, optionnel)`,
      prompt: TOKEN_HELP + '  •  Laisser vide pour désactiver --full',
      value: existing.docker_full_command ? existing.docker_full_command.join(' ') : '',
    });
    if (dockerFullCmd === undefined) return;
    if (dockerFullCmd.trim()) {
      config.docker_full_command = _splitCommand(dockerFullCmd.trim());
      config.supports_full = true;
    }
  }

  // ── ÉTAPE 4 : Configuration locale ───────────────────────────────────────
  if (mode === 'local' || mode === 'both') {
    const localCmd = await vscode.window.showInputBox({
      title: `"${id}" — Commande locale (décompilation de fonction)`,
      prompt: TOKEN_HELP,
      value: existing.command ? existing.command.join(' ') : `${id} --json {binary} --addr {addr}`,
      validateInput: (v) => (v.trim() ? null : 'Commande requise'),
    });
    if (localCmd === undefined) return;
    config.command = _splitCommand(localCmd.trim());

    const localFullCmd = await vscode.window.showInputBox({
      title: `"${id}" — Commande locale (binaire complet, optionnel)`,
      prompt: TOKEN_HELP + '  •  Laisser vide pour désactiver --full en local',
      value: existing.full_command ? existing.full_command.join(' ') : '',
    });
    if (localFullCmd === undefined) return;
    if (localFullCmd.trim()) {
      config.full_command = _splitCommand(localFullCmd.trim());
      config.supports_full = true;
    }
  }

  // ── ÉTAPE 5 : Options avancées (optionnel) ────────────────────────────────
  const advanced = await vscode.window.showQuickPick(
    [
      { label: '$(check) Enregistrer maintenant', description: 'Utilise les valeurs par défaut', value: 'save' },
      { label: '$(settings-gear) Configurer les options avancées', description: 'Format de sortie, timeout, variables d\'env, réseau Docker…', value: 'advanced' },
    ],
    { title: `"${id}" — Finaliser` }
  );
  if (!advanced) return;

  if (advanced.value === 'advanced') {
    // Format de sortie
    const fmtChoice = await vscode.window.showQuickPick(OUTPUT_FORMATS, {
      title: `"${id}" — Format de sortie`,
      placeHolder: 'Comment le décompilateur retourne ses résultats',
    });
    if (!fmtChoice) return;
    if (fmtChoice.value !== 'json') config.output_format = fmtChoice.value;

    // Timeout
    const timeoutStr = await vscode.window.showInputBox({
      title: `"${id}" — Timeout (secondes)`,
      prompt: 'Durée max d\'exécution. 120 par défaut pour une fonction, 300 pour --full.',
      value: existing.timeout ? String(existing.timeout) : '',
      placeHolder: 'Laisser vide pour la valeur par défaut',
      validateInput: (v) => {
        if (!v.trim()) return null;
        const n = parseInt(v, 10);
        if (isNaN(n) || n < 5) return 'Entier ≥ 5';
        return null;
      },
    });
    if (timeoutStr === undefined) return;
    if (timeoutStr.trim()) config.timeout = parseInt(timeoutStr.trim(), 10);

    // Variables d'environnement (si mode local ou les deux)
    if (mode !== 'docker') {
      const envStr = await vscode.window.showInputBox({
        title: `"${id}" — Variables d'environnement (optionnel)`,
        prompt: 'Format : KEY=value,KEY2=value2. Ces vars sont injectées lors de l\'exécution locale.',
        value: existing.env ? Object.entries(existing.env).map(([k, v]) => `${k}=${v}`).join(',') : '',
        placeHolder: 'Ex: TOOL_HOME=/opt/mytool,JAVA_OPTS=-Xmx2g',
      });
      if (envStr === undefined) return;
      if (envStr.trim()) {
        config.env = _parseEnvString(envStr.trim());
      }
    }

    // Réseau Docker
    if (mode !== 'local') {
      const networkChoice = await vscode.window.showQuickPick(
        [
          { label: 'none (recommandé)', description: 'Aucun accès réseau — isolation maximale', value: 'none' },
          { label: 'bridge', description: 'Accès internet via le bridge Docker', value: 'bridge' },
          { label: 'host', description: 'Partage le réseau de l\'hôte', value: 'host' },
        ],
        { title: `"${id}" — Réseau Docker` }
      );
      if (!networkChoice) return;
      if (networkChoice.value !== 'none') config.network = networkChoice.value;

      // Variables d'env Docker
      const dockerEnvStr = await vscode.window.showInputBox({
        title: `"${id}" — Variables d'environnement Docker (optionnel)`,
        prompt: 'Injectées via -e dans docker run. Format : KEY=value,KEY2=value2',
        value: existing.env ? Object.entries(existing.env).map(([k, v]) => `${k}=${v}`).join(',') : '',
        placeHolder: 'Ex: TOOL_HOME=/opt/tool,LICENSE_KEY=xxx',
      });
      if (dockerEnvStr === undefined) return;
      if (dockerEnvStr.trim()) {
        config.env = _parseEnvString(dockerEnvStr.trim());
      }

      // Arguments docker run supplémentaires
      const extraArgs = await vscode.window.showInputBox({
        title: `"${id}" — Arguments docker run supplémentaires (optionnel)`,
        prompt: 'Ajoutés avant le nom de l\'image. Ex: --memory 2g --cpus 2',
        value: existing.docker_extra_args ? existing.docker_extra_args.join(' ') : '',
        placeHolder: 'Laisser vide si non nécessaire',
      });
      if (extraArgs === undefined) return;
      if (extraArgs.trim()) config.docker_extra_args = _splitCommand(extraArgs.trim());
    }
  }

  // ── ÉTAPE 6 : Enregistrement ──────────────────────────────────────────────
  // Pour le mode docker-only sans command locale, on n'ajoute PAS de stub command
  // (le backend Python supporte maintenant docker-only)
  if ((mode === 'local' || mode === 'both') && !config.command) {
    vscode.window.showErrorMessage(`Configuration incomplète : commande locale manquante pour "${id}".`);
    return;
  }

  if (isEdit) delete cfg.decompilers[editId];
  cfg.decompilers[id] = config;
  _writeConfig(storageDir, cfg);

  // ── Auto-test silencieux ──────────────────────────────────────────────────
  // Lance --list en arrière-plan et affiche une notif quand c'est terminé.
  // Le withProgress se ferme dès que Python répond (ou timeout 12s).
  // Les showMessage sont hors du withProgress pour ne pas bloquer le spinner.
  const _autoCheckDecompiler = async () => {
    let result = null;
    let timedOut = false;

    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `Vérification de "${label || id}"…`, cancellable: true },
      async (_progress, token) => {
        const pythonExe = _findPythonExe(root);
        const child = cp.spawn(
          pythonExe,
          [path.join(getExtensionPath() || root, 'backends/static/decompile/decompile.py'), '--list', '--provider', 'auto'],
          { encoding: 'utf8', cwd: root, env: buildRuntimeEnv(root, storageDir) },
        );
        let stdout = '';
        let killed = false;
        child.stdout.on('data', (d) => { stdout += d; });

        const killTimer = setTimeout(() => {
          killed = true;
          timedOut = true;
          child.kill('SIGTERM');
        }, 12000);

        token.onCancellationRequested(() => {
          killed = true;
          clearTimeout(killTimer);
          child.kill('SIGTERM');
        });

        await new Promise((resolve) => child.on('close', resolve));
        clearTimeout(killTimer);

        if (!killed && stdout.trim()) {
          try { result = JSON.parse(stdout.trim()); } catch (_) { /* intentional */ }
        }
      }
    );

    // Hors du withProgress — le spinner est fermé, on peut afficher des messages
    if (timedOut) {
      const action = await vscode.window.showWarningMessage(
        `"${label || id}" ajouté — vérification trop longue (Docker lent ?). Teste manuellement.`,
        'Tester manuellement', 'OK'
      );
      if (action === 'Tester manuellement') await cmdDecompilerTest(root, storageDir, null, id);
      return;
    }
    if (!result) return; // annulé ou erreur silencieuse

    const isAvailable = !!result[id];
    const meta = result._meta || {};
    const localOk = !!(meta.local_available || {})[id];
    const dockerOk = !!(meta.docker_images_available || {})[id];
    const dockerImage = (meta.docker_images || {})[id] || '';

    if (isAvailable) {
      const via = localOk ? 'local' : dockerOk ? `Docker (${dockerImage})` : 'auto';
      const action = await vscode.window.showInformationMessage(
        `✅ "${label || id}" est prêt — disponible via ${via}.`,
        'Tester une décompilation', 'OK'
      );
      if (action === 'Tester une décompilation') await cmdDecompilerTest(root, storageDir, null, id);
    } else {
      const why = !dockerImage
        ? 'Aucune image Docker configurée et outil non trouvé en local.'
        : !dockerOk
          ? `Image Docker "${dockerImage}" introuvable — lance \`make decompiler-docker-build DECOMPILER=${id}\`.`
          : 'Outil non détecté en local (champ "detect" absent ou exécutable introuvable dans PATH).';
      const action = await vscode.window.showWarningMessage(
        `⚠️ "${label || id}" configuré mais non disponible. ${why}`,
        'Tester quand même', 'Ouvrir config JSON', 'OK'
      );
      if (action === 'Tester quand même') await cmdDecompilerTest(root, storageDir, null, id);
      else if (action === 'Ouvrir config JSON') await cmdDecompilerOpenConfig(storageDir);
    }
  };
  _autoCheckDecompiler();
}

// ─── Helpers wizard ───────────────────────────────────────────────────────────

/** Découpe une commande en tenant compte des guillemets simples/doubles. */
function _splitCommand(str) {
  const parts = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  for (const ch of str) {
    if (ch === "'" && !inDouble) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; continue; }
    if (ch === ' ' && !inSingle && !inDouble) {
      if (current) { parts.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current) parts.push(current);
  return parts;
}

/** Parse "KEY=value,KEY2=value2" → { KEY: "value", KEY2: "value2" } */
function _parseEnvString(str) {
  const result = {};
  for (const pair of str.split(',')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) result[k] = v;
    }
  }
  return result;
}

/** Génère un résumé texte de la config */
function _buildSummary(id, config, mode) {
  const lines = [`ID: ${id}`, `Mode: ${mode}`];
  if (config.docker_image) lines.push(`Image Docker: ${config.docker_image}`);
  if (config.docker_command) lines.push(`Cmd Docker: ${config.docker_command.join(' ')}`);
  if (config.command) lines.push(`Cmd locale: ${config.command.join(' ')}`);
  if (config.output_format) lines.push(`Format: ${config.output_format}`);
  if (config.timeout) lines.push(`Timeout: ${config.timeout}s`);
  return lines.join('\n');
}

// ─── Commande : modifier ──────────────────────────────────────────────────────

async function cmdDecompilerEdit(root, storageDir, preselectedId = null) {
  const cfg = _readConfig(storageDir);
  const ids = Object.keys(cfg.decompilers);
  if (ids.length === 0) {
    vscode.window.showInformationMessage('Aucun décompilateur custom à modifier.');
    return;
  }
  if (preselectedId && ids.includes(preselectedId)) {
    await cmdDecompilerAdd(root, storageDir, preselectedId);
    return;
  }
  const picked = await vscode.window.showQuickPick(
    ids.map((id) => {
      const d = cfg.decompilers[id];
      const badges = [];
      if (d.docker_image) badges.push('🐳 Docker');
      if (d.command) badges.push('💻 Local');
      return { label: d.label || id, description: id, detail: badges.join('  '), value: id };
    }),
    { title: 'Modifier un décompilateur custom', placeHolder: 'Choisir…' }
  );
  if (!picked) return;
  await cmdDecompilerAdd(root, storageDir, picked.value);
}

// ─── Commande : supprimer ─────────────────────────────────────────────────────

async function cmdDecompilerRemove(root, storageDir, preselectedId = null) {
  const cfg = _readConfig(storageDir);
  const ids = Object.keys(cfg.decompilers).filter(id => !id.startsWith('_'));
  if (ids.length === 0) {
    vscode.window.showInformationMessage('Aucun décompilateur configuré.');
    return;
  }
  if (preselectedId && ids.includes(preselectedId)) {
    const direct = cfg.decompilers[preselectedId];
    const confirmDirect = await vscode.window.showWarningMessage(
      `Supprimer le décompilateur "${direct.label || preselectedId}" (${preselectedId}) ?`,
      { modal: true },
      'Supprimer'
    );
    if (confirmDirect !== 'Supprimer') return;
    delete cfg.decompilers[preselectedId];
    _writeConfig(storageDir, cfg);
    vscode.window.showInformationMessage(`Décompilateur "${direct.label || preselectedId}" supprimé.`);
    return;
  }
  const picked = await vscode.window.showQuickPick(
    ids.map((id) => ({
      label: cfg.decompilers[id].label || id,
      description: id,
      detail: [
        cfg.decompilers[id].docker_image ? `🐳 ${cfg.decompilers[id].docker_image}` : '',
        cfg.decompilers[id].command ? '💻 local' : '',
      ].filter(Boolean).join('  '),
    })),
    { title: 'Supprimer un décompilateur', placeHolder: 'Choisir le décompilateur à supprimer' }
  );
  if (!picked) return;
  const confirm = await vscode.window.showWarningMessage(
    `Supprimer le décompilateur "${picked.label}" (${picked.description}) ?`,
    { modal: true },
    'Supprimer'
  );
  if (confirm !== 'Supprimer') return;
  delete cfg.decompilers[picked.description];
  _writeConfig(storageDir, cfg);
  vscode.window.showInformationMessage(`Décompilateur "${picked.label}" supprimé.`);
}

// ─── Commande : ouvrir config JSON ───────────────────────────────────────────

async function cmdDecompilerOpenConfig(storageDir) {
  const p = _configPath(storageDir);
  if (!fs.existsSync(p)) {
    _writeConfig(storageDir, {
      decompilers: {
        '_example': {
          label: 'Mon outil (exemple)',
          docker_image: 'registry/mon-outil:latest',
          docker_command: ['/usr/bin/mon-outil', '--json', '{binary}', '--addr', '{addr}'],
          docker_full_command: ['/usr/bin/mon-outil', '--json', '{binary}', '--full'],
          command: ['mon-outil', '--json', '{binary}', '--addr', '{addr}'],
          full_command: ['mon-outil', '--json', '{binary}', '--full'],
          supports_full: true,
          output_format: 'json',
          timeout: 120,
          network: 'none',
        },
      },
    });
    vscode.window.showInformationMessage('Fichier decompilers.json créé avec un exemple — adapte-le.');
  }
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(p));
  await vscode.window.showTextDocument(doc);
}

// ─── Commande : lister ────────────────────────────────────────────────────────

async function cmdDecompilerList(root, runPython, logChannel) {
  try {
    const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', 'auto'], { cwd: root });
    const data = JSON.parse(stdout.trim());
    const meta = data._meta || {};
    const dockerImages = meta.docker_images || {};
    const dockerAvail = meta.docker_images_available || {};
    const lines = ['', '═══ Décompilateurs disponibles ═══', ''];
    const allIds = Object.keys(data).filter(k => !k.startsWith('_'));

    for (const key of allIds) {
      const avail = !!data[key];
      const label = (meta.labels || {})[key] || key;
      const image = dockerImages[key] || '';
      const dockerOk = image ? (dockerAvail[key] ? '🐳✓' : '🐳✗') : '  ';
      const localOk = avail ? '💻✓' : '💻✗';
      const imagePart = image ? `  (${image})` : '';
      lines.push(`  ${avail ? '✅' : '❌'} ${label.padEnd(18)} ${localOk}  ${dockerOk}${imagePart}`);
    }
    lines.push('');
    lines.push(`Provider: ${meta.provider || 'auto'}`);
    lines.push('');
    logChannel.appendLine(lines.join('\n'));
    logChannel.show(true);
  } catch (e) {
    vscode.window.showErrorMessage(`Erreur listing décompilateurs: ${e.message || e}`);
  }
}

// ─── Commande : tester ────────────────────────────────────────────────────────

async function cmdDecompilerTest(root, storageDir, runPython, preselectedId = null) {
  // 1. Récupérer la liste
  let decompilerData = {};
  if (runPython) {
    try {
      const { stdout } = await runPython(['backends/static/decompile/decompile.py', '--list', '--provider', 'auto'], { cwd: root });
      decompilerData = JSON.parse(stdout.trim());
    } catch (_) { /* intentional */ }
  }

  // 2. Choisir le décompilateur
  let targetId = preselectedId;
  if (!targetId) {
    const allIds = Object.keys(decompilerData).filter(k => !k.startsWith('_'));
    const choices = allIds.map(id => {
      const avail = !!decompilerData[id];
      const meta = decompilerData._meta || {};
      const label = (meta.labels || {})[id] || id;
      const image = (meta.docker_images || {})[id] || '';
      const dockerOk = image ? !!(meta.docker_images_available || {})[id] : null;
      const localOk = !!(meta.local_available || {})[id];
      return {
        label: `${avail ? '$(check)' : '$(x)'} ${label}`,
        description: 'configuré',
        detail: [
          localOk ? '💻 backend local prêt' : '💻 backend local indisponible',
          dockerOk === true ? `🐳 image prête (${image})` : dockerOk === false ? `🐳 image manquante` : '🐳 pas de runtime Docker déclaré',
        ].filter(Boolean).join('  '),
        value: id,
      };
    });
    const picked = await vscode.window.showQuickPick(choices, {
      title: 'Tester un décompilateur — choisir le backend',
      placeHolder: 'Tous les backends sont listés même si non disponibles',
    });
    if (!picked) return;
    targetId = picked.value;
  }

  // 3. Choisir le provider
  const providerChoice = await vscode.window.showQuickPick(
    [
      { label: 'auto', description: 'Local si dispo, sinon Docker', value: 'auto' },
      { label: 'local', description: 'Forcer l\'exécution locale', value: 'local' },
      { label: 'docker', description: 'Forcer l\'exécution Docker', value: 'docker' },
    ],
    { title: `Test "${targetId}" — Provider` }
  );
  if (!providerChoice) return;

  // 4. Choisir le binaire
  const uris = await vscode.window.showOpenDialog({
    title: `Test "${targetId}" — Choisir un binaire`,
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false,
    openLabel: 'Sélectionner',
  });
  if (!uris || !uris[0]) return;
  const binaryPath = uris[0].fsPath;

  // 5. Mode décompilation
  const modeChoice = await vscode.window.showQuickPick(
    [
      { label: '$(symbol-function) Décompiler une fonction', description: 'Par adresse hex', value: 'function' },
      { label: '$(file-code) Décompiler tout le binaire', description: 'Mode --full (plus lent)', value: 'full' },
    ],
    { title: `Test "${targetId}" — Mode` }
  );
  if (!modeChoice) return;

  let addr = '';
  if (modeChoice.value === 'function') {
    const addrInput = await vscode.window.showInputBox({
      title: `Test "${targetId}" — Adresse de la fonction`,
      prompt: 'Adresse en hexadécimal. Laisser vide pour tenter 0x1000 par défaut.',
      placeHolder: '0x401000',
      validateInput: (v) => {
        if (!v.trim()) return null;
        if (!/^0x[0-9a-fA-F]+$|^\d+$/.test(v.trim())) return 'Format invalide (ex: 0x401000)';
        return null;
      },
    });
    if (addrInput === undefined) return;
    addr = addrInput.trim() || '0x1000';
  }

  // 6. Lancer le test
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Test ${targetId} via ${providerChoice.value}…`,
      cancellable: false,
    },
    async (progress) => {
      const testMode = providerChoice.value === 'docker'
        ? 'Démarrage du container Docker éphémère…'
        : providerChoice.value === 'auto'
          ? 'Test du backend (local puis Docker si nécessaire)…'
          : 'Test du backend local…';
      progress.report({ message: testMode });
      try {
        const pythonExe = _findPythonExe(root);
        const scriptPath = path.join(getExtensionPath() || root, 'backends/static/decompile/decompile.py');
        const args = [scriptPath, '--binary', binaryPath, '--decompiler', targetId, '--provider', providerChoice.value];
        if (modeChoice.value === 'full') {
          args.push('--full');
        } else {
          args.push('--addr', addr);
        }
        const result = await _runPythonDirect(pythonExe, args, root, 120000, storageDir);
        if (result.error) {
          const provider = result.provider || providerChoice.value;
          const rawError = String(result.error || '');
          vscode.window.showErrorMessage(`❌ ${targetId} (${provider}) — ${rawError}`);
          return;
        }
        const provider = result.provider || providerChoice.value;
        if (modeChoice.value === 'full') {
          const fnCount = (result.functions || []).length;
          vscode.window.showInformationMessage(
            `✅ ${targetId} (${provider}) — ${fnCount} fonction(s) décompilée(s)${provider === 'docker' ? ' • container supprimé automatiquement' : ''}`
          );
        } else {
          const preview = (result.code || '').slice(0, 200).replace(/\n/g, ' ');
          vscode.window.showInformationMessage(
            `✅ ${targetId} (${provider}) — ${preview || '(sortie vide)'}…${provider === 'docker' ? ' • container supprimé automatiquement' : ''}`
          );
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Erreur test "${targetId}": ${e.message || e}`);
      }
    }
  );
}

// ─── Helpers exécution Python ─────────────────────────────────────────────────

function _findPythonExe(root) {
  const base = getExtensionPath() || root;
  const candidates = [
    path.join(base, 'backends', '.venv', 'bin', 'python3'),
    path.join(base, 'backends', '.venv', 'bin', 'python'),
    'python3',
    'python',
  ];
  for (const c of candidates) {
    if (c.includes(path.sep) && !fs.existsSync(c)) continue;
    return c;
  }
  return 'python3';
}

function _runPythonDirect(pythonExe, args, root, timeout = 60000, storageDir = '') {
  return new Promise((resolve, reject) => {
    cp.execFile(
      pythonExe, args,
      { encoding: 'utf8', cwd: root, timeout, maxBuffer: 8 * 1024 * 1024, env: buildRuntimeEnv(root, storageDir) },
      (err, stdout, stderr) => {
        if (err && !stdout) { err.stderr = stderr; reject(err); return; }
        try {
          resolve(JSON.parse(stdout.trim()));
        } catch (_) {
          resolve({ code: stdout.trim(), error: err ? (stderr || err.message) : null });
        }
      }
    );
  });
}

// ─── Enregistrement ───────────────────────────────────────────────────────────

function registerDecompilerCommands(context, deps, root, storageDir) {
  const { runPython, logChannel } = deps;
  const subs = [];

  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerAdd',        () => cmdDecompilerAdd(root, storageDir)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerEdit',       (preselectedId) => cmdDecompilerEdit(root, storageDir, preselectedId || null)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerRemove',     (preselectedId) => cmdDecompilerRemove(root, storageDir, preselectedId || null)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerOpenConfig', () => cmdDecompilerOpenConfig(storageDir)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerList',       () => cmdDecompilerList(root, runPython, logChannel)));
  subs.push(vscode.commands.registerCommand('pileOuFace.decompilerTest',       (preselectedId) => cmdDecompilerTest(root, storageDir, runPython, preselectedId || null)));

  return subs;
}

module.exports = { registerDecompilerCommands };
