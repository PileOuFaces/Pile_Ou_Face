# Documentation MCP

Ce dossier centralise la documentation MCP du projet.

## Documents

- [INSTALLATION.md](./INSTALLATION.md) : installation et lancement local du serveur MCP.
- [IMPLEMENTATION.md](./IMPLEMENTATION.md) : architecture, protocole, mapping des tools.
- [OLLAMA.md](./OLLAMA.md) : integration Ollama <-> MCP (tool calling).
- [TESTS.md](./TESTS.md) : tests unitaires et smoke tests MCP.
- [CHANGELOG.md](./CHANGELOG.md) : historique des changements MCP documentes.
- [../modules.md](../modules.md) : reference complete des modules/outils exposes.

## Regle de maintenance

A chaque evolution MCP (code, protocole, tools, integration), la documentation de ce dossier doit etre mise a jour dans la meme PR/commit.

## Etat actuel de l'assistant IA

- Streaming progressif Ollama et providers cloud.
- Compteurs de tokens entree, sortie et total par requete et conversation.
- Historique multi-conversations avec modele selectionne persistant.
- Widget flottant redimensionnable.
- Action contextuelle depuis un fichier `.disasm.asm` pour preparer une demande IA.

Le streaming cloud est implemente pour OpenAI, Anthropic, Mistral, Gemini,
OpenRouter, Groq et DeepSeek. Sans cle API, les parseurs restent verifies par
des tests HTTP/SSE simules.
