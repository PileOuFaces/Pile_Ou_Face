# Importer un projet Ghidra

L’import passe par un JSON canonique afin de rester reproductible et indépendant de la version interne du projet Ghidra.

## Export headless

Copiez `tooling/pof_ghidra_export.py` dans le dossier de scripts Ghidra, puis lancez :

```bash
analyzeHeadless /tmp/pof-ghidra PofImport \
  -import /chemin/vers/programme \
  -postScript pof_ghidra_export.py /tmp/programme.pof.json /chemin/vers/programme
```

Le second chemin doit désigner exactement le binaire qui sera sélectionné dans Pile ou Face : son SHA-256 est inclus dans l’export et vérifié avant toute écriture.

## Import dans VS Code

Dans la palette de commandes, choisissez **Pile ou Face: Importer depuis Ghidra…**, sélectionnez le JSON puis le binaire. Le bilan indique les éléments importés, ignorés et en conflit.

Les annotations et types manuels sont prioritaires. Relancer le même import ne crée pas de doublons. Les types Ghidra non représentables sont listés dans les diagnostics et n’empêchent pas l’import des autres éléments.

## Format canonique

La version courante est `pile-ou-face.canonical-import/v1`. Le document contient `binary_sha256`, puis les collections `functions`, `comments`, `types` et `bookmarks`. Ce contrat est volontairement indépendant de Ghidra et sert aussi de point d’entrée aux futurs importeurs, notamment IDB.
