// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');
const ts = require('typescript');
const { EN } = require('../front/shared/i18n.js');

const FRONT_ROOT = path.resolve(__dirname, '../front');
const HOST_ROOT = path.resolve(__dirname, '../src');
const HOST_UI_METHODS = new Set([
  'showErrorMessage',
  'showInformationMessage',
  'showInputBox',
  'showOpenDialog',
  'showQuickPick',
  'showSaveDialog',
  'showWarningMessage',
  'withProgress',
]);
const TRANSLATED_ATTRIBUTES = ['aria-label', 'placeholder', 'title', 'data-tooltip'];
const IGNORED_PARENTS = new Set(['CODE', 'PRE', 'SCRIPT', 'STYLE']);
const ALLOWED_UNTRANSLATED = new Set([
  'Pile ou Face',
  'Dynamic — Run Trace',
  'Run Trace',
  'TRACE',
]);
const FRENCH_HINT = /[À-ÿ]|\b(?:Aucun|Aucune|Ajouter|Afficher|Analyse|Binaire|Calcul|Chemin|Choisir|Code source|Connexion|Copier|Créer|Données|Entrée|Erreur|Étape|Fermer|Fichier|Fonction|Générer|Lancer|Lecture|Masquer|Mémoire|Modifier|Notes exploit|Ouvrir|Paramètres|Prêt|Rafraîchir|Rechercher|Réduire|Résultat|Sauvegarder|Sélectionner|Sortie|Supprimer|Taille|Valeur|Vue|actuel|courant|dans|depuis|pour|avec|sans|sont|sera)\b/i;

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

function auditHostFile(file) {
  const source = fs.readFileSync(file, 'utf8');
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const findings = [];
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const method = ts.isPropertyAccessExpression(node.expression) ? node.expression.name.text : '';
      if (HOST_UI_METHODS.has(method)) {
        const inspect = (child) => {
          if (ts.isStringLiteralLike(child) && isUntranslated(child.text)) {
            const { line } = sourceFile.getLineAndCharacterOfPosition(child.getStart(sourceFile));
            findings.push({
              file: path.relative(path.resolve(__dirname, '..'), file),
              line: line + 1,
              text: child.text.trim(),
            });
          }
          ts.forEachChild(child, inspect);
        };
        node.arguments.forEach(inspect);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return findings;
}

const htmlFindings = walk(FRONT_ROOT)
  .filter((file) => file.endsWith('.html'))
  .flatMap(auditFile);
const hostFindings = walk(HOST_ROOT)
  .filter((file) => file.endsWith('.ts') && !file.includes(`${path.sep}tests${path.sep}`))
  .flatMap(auditHostFile);

if (htmlFindings.length || hostFindings.length) {
  if (htmlFindings.length) console.error('Uncatalogued French-looking webview strings:');
  htmlFindings.forEach(({ file, text }) => console.error(`- ${file}: ${JSON.stringify(text)}`));
  if (hostFindings.length) console.error('French-looking native VS Code UI strings:');
  hostFindings.forEach(({ file, line, text }) => console.error(`- ${file}:${line}: ${JSON.stringify(text)}`));
  process.exitCode = 1;
} else {
  console.log('i18n HTML and native VS Code UI coverage audit passed.');
}
