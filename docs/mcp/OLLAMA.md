# Ollama + MCP

Ce guide explique comment faire utiliser les tools MCP par un modele Ollama local.

## Principe

- Ollama ne parle pas MCP nativement dans ce repo.
- Le script `backends/mcp/ollama_bridge.py` fait l'adaptation:
  - Ollama `tool_calls` -> MCP `tools/call`
  - Resultats MCP -> messages `role=tool` pour Ollama

## Prerequis

- Ollama installe et lance localement
- Un modele present (exemple: `qwen3:8b`)
- Serveur MCP disponible dans le repo (`backends/mcp/server.py`)

## Verifier Ollama

```bash
curl -s http://127.0.0.1:11434/api/tags
```

Si la commande retourne des modeles, Ollama est OK.

## Lister les tools MCP exposes au bridge

```bash
python3 backends/mcp/ollama_bridge.py --list-tools
```

## One-shot

```bash
python3 backends/mcp/ollama_bridge.py \
  --model qwen3:8b \
  --prompt "Analyse via l'outil disassemble le code de demo_analysis.elf"
```

Tu peux aussi donner seulement le nom du fichier:

```bash
python3 backends/mcp/ollama_bridge.py \
  --model qwen3:8b \
  --prompt "Trouve les symboles sur demo_analysis.elf et resume le resultat."
```

Le serveur MCP tente maintenant de resoudre automatiquement le chemin dans le workspace.
L'outil `disassemble` n'a pas besoin d'arguments CLI comme `--output`: c'est gere automatiquement cote MCP.

## Mode interactif

```bash
python3 backends/mcp/ollama_bridge.py --model qwen3:8b
```

Puis tape tes prompts, `exit` pour quitter.

## Depuis l'extension VS Code

Le hub UI integre maintenant la discussion Ollama directement dans le `Dashboard` (page d'accueil).

1. Ouvrir `Reverse Workspace` dans VS Code
2. Rester sur `Dashboard`
3. Dans `Discussion Ollama + MCP`, cliquer sur `Rafraîchir`
4. Choisir le modele, ecrire un message, puis `Envoyer`

La discussion conserve un historique local (messages user/assistant) pour que les prompts suivants gardent le contexte des resultats precedents.
Le bouton `Nouvelle discussion` ouvre un nouveau fil sans perdre les precedents.
Un panneau `Historique des conversations` permet de rouvrir une ancienne discussion, et le bouton `Vider` supprime tout l'historique.
Un widget flottant `IA` est disponible depuis tous les onglets du hub pour discuter sans quitter l'outil en cours.
Le widget peut etre redimensionne depuis sa poignee superieure gauche ; sa taille est memorisee localement.

Cette UI appelle `backends/mcp/ollama_bridge.py` en backend et affiche les reponses dans un fil de chat.
Les fragments sont affiches progressivement pendant la generation. A la fin,
l'interface conserve les compteurs de tokens entree, sortie et total.

Depuis un fichier `.disasm.asm`, le menu contextuel
`Demander a l'IA d'expliquer cette instruction` ouvre le Dashboard et prepare
un prompt contenant le binaire, la fonction, l'adresse et le code selectionne.

## Robustesse des prompts naturels

Le bridge gere maintenant mieux les formulations naturelles:

- "donne le code asm de ...", "desassemblage de ...", "analyse ..."
- demandes de symboles/strings sans syntaxe technique stricte
- message de precision du fichier ("le fichier c'est ...")

Ameliorations techniques:

- fallback automatique par intention (`disassemble`, `get_symbols`, `extract_strings`, puis `get_binary_info` si intention absente)
- resolution fuzzy du nom de binaire cote MCP (ex: `vul_demo.elf` -> `vuln_demo.elf` si correspondance proche)
- retry plus direct quand le modele repond une phrase generique au lieu d'appeler les tools
- selection dynamique d'un sous-ensemble de tools selon l'intention (moins de bruit, meilleur tool-calling)
- normalisation automatique des arguments tools (ex: ajout de `binary_path`, correction de `max_lines`)
- boucle tool-calling resiliente: une erreur tool est renvoyee au modele comme resultat tool pour permettre auto-correction

## Options utiles

- `--base-url http://127.0.0.1:11434` : URL Ollama.
- `--max-steps 8` : nombre max d'iterations tools.
- `--timeout 90` : timeout HTTP vers Ollama.
- `--system "..."` : prompt systeme.
- `--server-cmd "python3 backends/mcp/server.py --transport stdio"` : commande MCP custom.

## Notes

- Pour de meilleurs appels outils, prefere un modele connu pour le tool-calling.
- Le bridge expose le streaming NDJSON avec `--stream-output`.
- Le bridge applique un retry automatique si le modele renvoie une reponse generique
  ("please provide a request") alors que le prompt semble deja exploitable avec les tools.
