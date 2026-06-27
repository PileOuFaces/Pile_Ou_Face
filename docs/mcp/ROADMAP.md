# Roadmap MCP — Assistant IA

Features planifiées pour l'intégration IA (Ollama + cloud providers) dans le dashboard.
Ordonnées par priorité décroissante.

**Dernière mise à jour :** 2026-06-21

---

## P0 — Critique (bugs bloquants)

### Contexte binaire enrichi ✅ (fixé)
**Problème :** `buildOllamaPromptWithContext()` n'injectait que le chemin du fichier (`Projet actif: /path`), sans format ni architecture. Le modèle ne comprenait pas que l'utilisateur parlait du binaire ouvert dans l'app.
**Fix :** injection du chemin + `format` + `arch` depuis `getCurrentBinaryMeta()`.

### Auto-fetch MCP pour modèles sans tool calling ✅ (fixé)
**Problème :** quand un modèle (ex: codegemma:7b) lève `OllamaToolsUnsupportedError`, le bridge réessayait sans outils mais sans données — le modèle répondait uniquement depuis son system prompt (`memory.md`).
**Fix :** `_auto_tool_fallback()` est appelé avant le retry, les données MCP sont injectées dans le message utilisateur.

---

## P1 — Haute valeur

### Streaming Ollama ✅ (implémenté)
**Quoi :** les fragments arrivent progressivement au lieu d'un bloc unique à la fin.
**Impl :** API Ollama `/api/chat` avec `stream: true`, bridge NDJSON, batching côté host et mise à jour incrémentale de la bulle dans le DOM.
**UX livrée :** statut live, tokens entrée/sortie/total, historique par conversation et auto-scroll suspendu lorsque l'utilisateur remonte lire.

### Streaming des providers cloud — V3 ✅ (implémenté)
**Quoi :** appliquer le même rendu progressif à OpenAI, Claude, Mistral, Gemini, OpenRouter, Groq et DeepSeek.
**Impl :**
- streaming natif SSE pour OpenAI, Claude, Mistral, Gemini, OpenRouter, Groq et DeepSeek ;
- événements normalisés en NDJSON (`token`, `done`, `error`) ;
- consommation progressive de `stdout` côté host avec batching des fragments ;
- métriques finales conservées pour les tokens `entrée`, `sortie` et `total`.

### Visibilité des appels d'outils MCP dans le chat ✅ (implémenté)
**Quoi :** afficher dans le chat quels outils MCP ont été appelés et leur résultat brut (pliable).
**Pourquoi :** l'utilisateur ne sait pas que le modèle a appelé `disassemble` ou `get_symbols` — manque de transparence.
**Impl :** `run_agent_once` retourne `{response, tool_calls}`, bridge passe `--json-output`, Node.js parse le JSON et forwarde `tool_calls`, frontend affiche une bulle `system` avec `[outil : nom] ✓/✗`.

### Intégration clic droit dans le désassemblage ✅ (implémenté)
**Quoi :** menu contextuel sur une instruction ou une sélection `.asm` → « Demander à l’IA d’expliquer cette instruction ».
**UX livrée :** le dashboard s'ouvre avec un prompt prérempli et focalisé contenant le binaire, la fonction, l'adresse et le code sélectionné.
**Impl :** commande VS Code dédiée dans le menu contextuel de l'éditeur, extraction du contexte depuis le fichier `.disasm.asm`, puis transfert fiable au webview après son initialisation.

---

## P2 — Valeur moyenne

### Templates de prompt RE ✅ (implémenté)
**Quoi :** boutons/chips rapides au-dessus du textarea pour les tâches courantes.
**Chips disponibles :** Rapport, Désassemble, Vulnérabilités, Strings, Imports.
**Impl :** chips `.ollama-template-chip` dans `.ollama-prompt-templates`, clic → pré-remplit le textarea.

### Bouton copier sur les messages de l'assistant ✅ (implémenté)
**Quoi :** icône copier sur chaque bulle assistant, copie le contenu en texte brut.
**Impl :** action `Copier` regroupée avec les autres actions de la bulle assistant, via `navigator.clipboard.writeText()`.

### Widget IA redimensionnable ✅ (implémenté)
**Quoi :** redimensionner directement le widget flottant à la souris.
**UX livrée :** poignée dans l'angle supérieur gauche, limites adaptées au viewport, historique extensible et taille mémorisée entre les rechargements.

---

## V4 — Prochain lot

### P1 — Contrôle et lisibilité

#### Annulation commune des réponses ✅ (implémenté)
**Quoi :** bouton `Arrêter` visible pendant une génération Ollama ou cloud.
**Impl :** identifiant de requête actif, registre commun des processus, arrêt `SIGTERM`, rejet des événements tardifs et conservation du texte déjà streamé.

#### Rendu Markdown sécurisé ✅ (implémenté)
**Quoi :** rendre les titres, listes, tableaux, liens et blocs de code retournés par les modèles.
**Impl :** parseur local avec rendu DOM par liste blanche, sans `innerHTML`. Les liens sont limités à `http`, `https` et `mailto` ; le streaming reste affiché en texte brut jusqu'à la réponse finale.

#### Régénérer et modifier un message ✅ (implémenté)
**Quoi :** relancer la dernière réponse ou modifier un ancien prompt avant de le renvoyer.
**Impl :** actions sur les bulles utilisateur/assistant avec reconstruction explicite du contexte. Une modification ou régénération crée une nouvelle branche depuis le prompt concerné et remplace la suite devenue obsolète.

### P2 — Gestion des conversations

#### Export de conversation ✅ (implémenté)
**Quoi :** exporter la conversation active en Markdown ou JSON avec modèle, date et consommation de tokens.
**Impl :** action `Exporter` commune au Dashboard et au widget, choix du format via VS Code, nom de fichier nettoyé et snapshot JSON versionné.

#### Renommer et rechercher les conversations ✅ (implémenté)
**Quoi :** titres éditables, recherche locale et tri par date/modèle.
**Impl :** renommage inline persistant, recherche sans accents dans les titres, modèles et messages, tri récent/ancien/titre/modèle mémorisé.

#### Budget de contexte ✅ (implémenté)
**Quoi :** afficher la taille approximative du contexte envoyé et avertir avant une troncature importante.
**Impl :** estimation locale à quatre caractères par token, compteur messages inclus/total, badge orange en cas de troncature et confirmation avant les pertes importantes.

### P3 — Configuration et coûts

#### Paramètres avancés du modèle ✅ (implémenté)
**Quoi :** température, `max_tokens`, `top_p` configurables par conversation ou globalement.
**Impl :** valeurs globales dans Options, surcharge persistante par conversation dans les deux vues du chat, validation commune et traduction native pour Ollama, Anthropic, Gemini et les APIs compatibles OpenAI.

#### Estimation des coûts cloud ✅ (implémenté)
**Quoi :** convertir les tokens entrée/sortie en coût estimé par requête et conversation.
**Impl :** catalogue local de tarifs USD par million de tokens, modèles exacts ou motifs, date d’effet, estimation par réponse et total partiel/complet de conversation.
**Contrainte :** aucun tarif n’est prérempli ni mis à jour automatiquement ; l’utilisateur garde la source de vérité.

#### Prompts contextuels depuis les vues d'analyse ✅ (implémenté)
**Quoi :** actions « Demander à l'IA » depuis le CFG, le pseudo-C, les strings, les imports et les résultats de recherche.
**Impl :** chaque vue transfère son contenu visible, le binaire actif, la fonction,
l'adresse et ses filtres utiles vers le composeur du Dashboard. Le contexte est
limité à 6 000 caractères en conservant son début et sa fin, avec une mention
explicite lorsqu'il est tronqué.

---

## Notes d'implémentation

- V3 est livrée ; un smoke test cloud réel reste recommandé dès qu'une clé API de test est disponible.
- `_detect_tool_intent` couvre déjà désassemblage, symboles, strings, imports, sections, headers, entropie, rapports, vulnérabilités et packers.
- Le lot fonctionnel V4 est terminé ; restent les smoke tests UX et providers
  cloud réels avant la PR de stabilisation.
