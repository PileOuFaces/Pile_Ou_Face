# Pile ou Face - VS Code Extension

Extension VS Code pour visualiser graphiquement la pile à partir d'un `output.json` généré par le simulateur C.

## Structure du projet

```
extension/
├── src/
│   └── extension.ts       # Source principale de l'extension
├── out/
│   └── extension.js       # Build CommonJS chargé par VS Code
├── webview/
│   ├── app/              # Code JavaScript frontend
│   └── media/            # HTML, CSS et assets
├── test/                 # Tests unitaires
├── .eslintrc             # Configuration ESLint
├── .prettierrc            # Configuration Prettier
└── package.json          # Configuration npm
```

## Installation

```bash
cd extension
```

## Scripts disponibles

- `npm test` - Exécuter les tests
- `npm run test:watch` - Tests en mode watch
- `npm run test:coverage` - Couverture de code
- `npm run lint` - Vérifier le code
- `npm run lint:fix` - Corriger le code automatiquement

## Développement

L'extension charge maintenant directement les fichiers CommonJS présents dans `src/`.
Elle ne dépend plus de `out/extension.js` pour démarrer, donc un utilisateur n'a pas
besoin de lancer `npm install` ou `npm run build` juste pour ouvrir l'extension.

Pour debugger l'extension, ouvrez le dossier `extension/` dans VS Code puis appuyez
sur `F5`.

Pour créer un `.vsix`, utilisez aussi un packaging depuis ce dossier `extension/` :

```bash
npx @vscode/vsce package
```

## Commandes disponibles

- `Pile ou Face: Exécuter la trace...` - Lance la pipeline complète de traçage

## Assistant Ollama dans l'UI

Dans le Hub :

1. Rester sur la page `Dashboard`
2. Utiliser la carte `Discussion Ollama + MCP`
3. Cliquer sur `Rafraîchir` pour charger les modèles Ollama
4. Choisir un modèle, écrire un message, puis `Envoyer`

La discussion garde un historique local pour conserver le contexte entre messages.
`Nouvelle discussion` démarre un nouveau fil, et la zone `Historique des conversations`
permet de rouvrir une discussion précédente ou de tout vider.
Un bouton flottant `IA` est aussi disponible depuis tous les onglets pour discuter sans revenir au Dashboard.
Chaque message est exécuté via `backends/mcp/ollama_bridge.py` et peut appeler les outils MCP sans passer par le terminal.

Le chat affiche les réponses progressivement pour Ollama et les providers cloud
configurés, avec les tokens entrée/sortie/total. Le widget flottant est
redimensionnable depuis son angle supérieur gauche et mémorise sa taille.

Dans un fichier `.disasm.asm`, le menu contextuel
`Demander à l’IA d’expliquer cette instruction` prépare automatiquement une
question avec l’adresse, la fonction et le code sélectionné.
