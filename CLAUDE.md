# Contexte repo (lire avant le bloc GitNexus)

Repo **host public** (extension VS Code + backends Python publics). Pour toute tâche non triviale :
lire à la racine du workspace `../ARCHITECTURE.md`, `../CONTRACTS_SHARED.md`, et `OPEN_CORE_BOUNDARY.md`.
Le bloc GitNexus ci-dessous est **optionnel** : l'utiliser pour les refactors à risque, pas à chaque édition.

Avant d'implémenter une issue existante, vérifier qu'elle est toujours vraie sur la branche cible :
lire les commentaires et PRs liées, chercher les PRs mergées par numéro/mots-clés, puis inspecter le code actuel.
Si la fonctionnalité existe déjà, fermer/commenter l'issue au lieu de recréer une UI ou un flux parallèle.

Cas connu : le choix d'image/version Docker pour les décompilateurs existe déjà dans le flux :

```text
Settings -> Decompilers -> Add -> Image OCI PileOuFaces / Image personnalisée
```

Historique :
- #111 épingle les images OCI officielles sur des tags versionnés.
- #112 ajoute le sélecteur de version.
- #113 rend le menu dynamique depuis GHCR et retire les lectures de versions hardcodées côté extension.

Ne pas ajouter une seconde UI de sélection d'image décompilateur sans preuve dans le code actuel que ce flux manque ou casse.
Pour la sélection de version, privilégier le wizard GHCR existant et le câblage `decompilers.json`, pas un chemin parallèle dans `pof-settings`.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **Pile_Ou_Face** (21698 symbols, 36690 relationships, 265 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/Pile_Ou_Face/context` | Codebase overview, check index freshness |
| `gitnexus://repo/Pile_Ou_Face/clusters` | All functional areas |
| `gitnexus://repo/Pile_Ou_Face/processes` | All execution flows |
| `gitnexus://repo/Pile_Ou_Face/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
