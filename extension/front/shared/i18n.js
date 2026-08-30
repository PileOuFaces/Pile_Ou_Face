// SPDX-License-Identifier: AGPL-3.0-only
(function initI18n(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.POFI18n = api;
})(typeof window !== 'undefined' ? window : globalThis, function createI18n() {
  const EN = Object.freeze({
    'Fichier de travail': 'Working file',
    'Choisir ou changer le fichier de travail': 'Choose or change the working file',
    'Choisir un fichier…': 'Choose a file…',
    "Le fichier choisi sera repris dans l'analyse statique et la trace dynamique.": 'The selected file will be used for static analysis and dynamic tracing.',
    'Fichier actuel': 'Current file',
    'Aucun': 'None',
    'Choisir…': 'Choose…',
    'Aucun fichier sélectionné': 'No file selected',
    'Choisis un fichier pour démarrer.': 'Choose a file to get started.',
    'Profil blob brut': 'Raw blob profile',
    'Actif': 'Active',
    'Reconfigurer ce blob brut': 'Reconfigure this raw blob',
    'Récents': 'Recent',
    'Effacer': 'Clear',
    'Analyse statique': 'Static analysis',
    'Trace dynamique': 'Dynamic trace',
    'Outils': 'Tools',
    "En attente d'une trace…": 'Waiting for a trace…',
    'Étape:': 'Step:',
    'Toute la trace': 'Entire trace',
    'Appliquer un preset de layout': 'Apply a layout preset',
    'Débutant': 'Beginner',
    'Visibilité des panneaux optionnels': 'Optional panel visibility',
    'Explications': 'Explanations',
    'Registres': 'Registers',
    'Workspace d’analyse': 'Analysis workspace',
    "Workspace d'analyse": 'Analysis workspace',
    "Choisis un fichier de travail puis lance le bon flux d'analyse.": 'Choose a working file, then start the appropriate analysis workflow.',
    'Modules disponibles': 'Available modules',
    'Entrées rapides': 'Quick actions',
    'Accès rapide': 'Quick access',
    'Flux de travail': 'Workflows',
    'Choisis le mode adapté à ce que tu veux comprendre ou modifier.': 'Choose the workflow that matches what you want to understand or modify.',
    'Désassemblage, symboles, CFG, xrefs': 'Disassembly, symbols, CFG, xrefs',
    'Calculette, payload, fichiers': 'Calculator, payload, files',
    'Automatisation IA': 'AI automation',
    'Auto-triage du binaire': 'Binary auto-triage',
    'Priorise, nomme et documente les fonctions, puis génère un rapport vérifiable.': 'Prioritize, name and document functions, then generate a verifiable report.',
    'Prêt': 'Ready',
    'Binaire': 'Binary',
    'Aucun binaire': 'No binary',
    'Modèle': 'Model',
    'Configuration enregistrée': 'Saved configuration',
    'Périmètre': 'Scope',
    'Budget': 'Budget',
    'Le code n’est envoyé qu’après confirmation explicite.': 'Code is sent only after explicit confirmation.',
    'Préparer l’auto-triage': 'Prepare auto-triage',
    'Annuler': 'Cancel',
    'Dernier résultat': 'Latest result',
    'Voir le rapport': 'View report',
    'Exporter en Markdown': 'Export as Markdown',
    'Vérification avant envoi': 'Preflight review',
    'Lancer l’auto-triage IA ?': 'Start AI auto-triage?',
    'Provider et modèle': 'Provider and model',
    'Fonctions détectées': 'Detected functions',
    'Limites': 'Limits',
    'Le code décompilé sera transmis au provider indiqué.': 'Decompiled code will be sent to the selected provider.',
    'Retour': 'Back',
    'Confirmer et lancer': 'Confirm and start',
    'Assistant IA': 'AI Assistant',
    '0 token consommé': '0 tokens used',
    'Contexte · ~0 token · 0 message': 'Context · ~0 tokens · 0 messages',
    'Réglages du modèle': 'Model settings',
    'Portée': 'Scope',
    'Globale': 'Global',
    'Température': 'Temperature',
    'Tokens max.': 'Max tokens',
    'Exporter': 'Export',
    'Exporter la conversation active en Markdown ou JSON': 'Export the active conversation as Markdown or JSON',
    'Créer une nouvelle conversation': 'Create a new conversation',
    '＋ Nouvelle conversation': '＋ New conversation',
    'Rafraîchir les modèles': 'Refresh models',
    'Templates rapides': 'Quick templates',
    'Rapport': 'Report',
    'Désassemble': 'Disassemble',
    'Vulnérabilités': 'Vulnerabilities',
    'Message…': 'Message…',
    'Arrêter': 'Stop',
    'Envoyer': 'Send',
    'Historique': 'History',
    'Vider': 'Clear',
    'Rechercher…': 'Search…',
    'Rechercher une conversation': 'Search conversations',
    'Trier les conversations': 'Sort conversations',
    'Plus récentes': 'Newest first',
    'Plus anciennes': 'Oldest first',
    'Titre A–Z': 'Title A–Z',
    'Modèle A–Z': 'Model A–Z',
    "Parler à l'IA": 'Talk to the AI',
    'Assistant IA flottant': 'Floating AI Assistant',
    'Redimensionner la fenêtre': 'Resize window',
    'Redimensionner la fenêtre Assistant IA': 'Resize AI Assistant window',
    'Fermer': 'Close',
    'Rafraîchir': 'Refresh',
    'Assistant prêt.': 'Assistant ready.',
    "Pose ta question sans quitter l'outil courant…": 'Ask your question without leaving the current tool…',
    'Interface': 'Interface',
    'Confort de lecture': 'Reading comfort',
    'Langue': 'Language',
    "Choisis la langue de l'interface Pile ou Face.": 'Choose the Pile ou Face interface language.',
    'Français': 'French',
  });

  const ATTRIBUTES = Object.freeze(['aria-label', 'placeholder', 'title', 'data-tooltip']);
  const TEXT_SOURCES = new WeakMap();
  const TEXT_RENDERED = new WeakMap();
  const ATTRIBUTE_SOURCES = new WeakMap();
  const ATTRIBUTE_RENDERED = new WeakMap();
  let currentLocale = 'en';

  function resolveLocale(value) {
    return String(value || '').trim().toLowerCase().startsWith('fr') ? 'fr' : 'en';
  }

  function translate(value, locale) {
    if (resolveLocale(locale) === 'fr') return String(value ?? '');
    return EN[String(value ?? '')] || String(value ?? '');
  }

  function translateTextNode(node, locale) {
    const current = String(node.nodeValue || '');
    const previousRender = TEXT_RENDERED.get(node);
    if (!TEXT_SOURCES.has(node) || (previousRender !== undefined && current !== previousRender)) {
      TEXT_SOURCES.set(node, current);
    }
    const source = TEXT_SOURCES.get(node);
    const trimmed = source.trim();
    if (!trimmed) return;
    const translated = translate(trimmed, locale);
    const rendered = source.replace(trimmed, translated);
    if (current !== rendered) node.nodeValue = rendered;
    TEXT_RENDERED.set(node, rendered);
  }

  function translateElement(element, locale) {
    let sources = ATTRIBUTE_SOURCES.get(element);
    let renderedValues = ATTRIBUTE_RENDERED.get(element);
    if (!sources) {
      sources = new Map();
      ATTRIBUTE_SOURCES.set(element, sources);
    }
    if (!renderedValues) {
      renderedValues = new Map();
      ATTRIBUTE_RENDERED.set(element, renderedValues);
    }
    ATTRIBUTES.forEach((attribute) => {
      if (!element.hasAttribute?.(attribute)) return;
      const current = element.getAttribute(attribute);
      const previousRender = renderedValues.get(attribute);
      if (!sources.has(attribute) || (previousRender !== undefined && current !== previousRender)) {
        sources.set(attribute, current);
      }
      const source = sources.get(attribute);
      const translated = translate(source, locale);
      if (current !== translated) element.setAttribute(attribute, translated);
      renderedValues.set(attribute, translated);
    });
    Array.from(element.childNodes || []).forEach((node) => {
      if (node.nodeType === 3) translateTextNode(node, locale);
      else if (node.nodeType === 1) translateElement(node, locale);
    });
  }

  function localizeDocument(documentRef, locale = documentRef?.documentElement?.lang) {
    const resolved = resolveLocale(locale);
    if (!documentRef?.documentElement) return resolved;
    documentRef.documentElement.lang = resolved;
    if (documentRef.body) translateElement(documentRef.body, resolved);
    return resolved;
  }

  function setLocale(locale, documentRef = typeof document !== 'undefined' ? document : null) {
    currentLocale = resolveLocale(locale);
    return localizeDocument(documentRef, currentLocale);
  }

  function observeDocument(documentRef, locale = documentRef?.documentElement?.lang) {
    currentLocale = resolveLocale(locale);
    const resolved = localizeDocument(documentRef, currentLocale);
    const Observer = documentRef?.defaultView?.MutationObserver;
    if (!Observer || !documentRef.body) return null;
    const observer = new Observer((mutations) => mutations.forEach((mutation) => {
      if (mutation.type === 'characterData') translateTextNode(mutation.target, currentLocale);
      if (mutation.type === 'attributes') translateElement(mutation.target, currentLocale);
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === 3) translateTextNode(node, currentLocale);
        else if (node.nodeType === 1) translateElement(node, currentLocale);
      });
    }));
    observer.observe(documentRef.body, {
      attributes: true,
      attributeFilter: ATTRIBUTES,
      characterData: true,
      childList: true,
      subtree: true,
    });
    return observer;
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => observeDocument(document), { once: true });
    } else {
      observeDocument(document);
    }
  }

  return { EN, resolveLocale, translate, translateElement, localizeDocument, setLocale, observeDocument };
});
