// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');
const { EN } = require('../front/shared/i18n.js');

const FRONT_ROOT = path.resolve(__dirname, '../front');
const TRANSLATED_ATTRIBUTES = ['aria-label', 'placeholder', 'title', 'data-tooltip'];
const IGNORED_PARENTS = new Set(['CODE', 'PRE', 'SCRIPT', 'STYLE']);
const ALLOWED_UNTRANSLATED = new Set([
  'Pile ou Face',
  'Dynamic — Run Trace',
  'Run Trace',
  'TRACE',
]);
const FRENCH_HINT = /[À-ÿ]|\b(?:Aucun|Aucune|Ajouter|Afficher|Analyse|Binaire|Calcul|Chemin|Choisir|Code source|Connexion|Copier|Créer|Données|Entrée|Erreur|Étape|Fermer|Fichier|Fonction|Générer|Lancer|Lecture|Masquer|Mémoire|Modifier|Notes exploit|Ouvrir|Paramètres|Pile|Prêt|Rafraîchir|Rechercher|Réduire|Résultat|Sauvegarder|Sélectionner|Sortie|Supprimer|Taille|Trace|Valeur|Vue|actuel|courant|dans|depuis|pour|avec|sans|sont|sera)\b/i;

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

function isUntranslated(value) {
  const text = String(value || '').trim();
  return Boolean(text && FRENCH_HINT.test(text) && !EN[text] && !ALLOWED_UNTRANSLATED.has(text));
}

function auditFile(file) {
  const document = new JSDOM(fs.readFileSync(file, 'utf8'), {
    virtualConsole: new VirtualConsole(),
  }).window.document;
  const findings = new Set();
  const walker = document.createTreeWalker(document.body, 4);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!IGNORED_PARENTS.has(node.parentElement?.tagName) && isUntranslated(node.nodeValue)) {
      findings.add(String(node.nodeValue).trim());
    }
  }
  document.querySelectorAll('*').forEach((element) => {
    TRANSLATED_ATTRIBUTES.forEach((attribute) => {
      if (isUntranslated(element.getAttribute(attribute))) {
        findings.add(String(element.getAttribute(attribute)).trim());
      }
    });
  });
  return [...findings].map((text) => ({ file: path.relative(path.resolve(__dirname, '..'), file), text }));
}

const findings = walk(FRONT_ROOT)
  .filter((file) => file.endsWith('.html'))
  .flatMap(auditFile);

if (findings.length) {
  console.error('Uncatalogued French-looking webview strings:');
  findings.forEach(({ file, text }) => console.error(`- ${file}: ${JSON.stringify(text)}`));
  process.exitCode = 1;
} else {
  console.log('i18n HTML coverage audit passed.');
}
