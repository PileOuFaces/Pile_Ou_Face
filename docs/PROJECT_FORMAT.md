# Format de projet git-native

Le format stable `pile-ou-face.project/v1` transporte l’état d’analyse d’un binaire entre
machines sans inclure de chemin local, de mtime ou de base SQLite. Le JSON utilise une
indentation de deux espaces, des clés triées et des collections ordonnées pour produire des
diffs Git lisibles et limiter les conflits de merge.

## Identité stable

Le binaire est identifié par le SHA-256 de son contenu. Une annotation ou une fonction est
identifiée par `<binary_sha256>:<adresse_normalisée>`, par exemple
`8a…f2:0x401000`. Cette clé reste identique si le fichier est déplacé ou renommé ; l’import
refuse un binaire dont le contenu diffère.

## Contenu versionné

- commentaires, renommages, bookmarks et états/notes de revue ;
- définitions de types (`struct`, `union`, `enum`, `typedef`, prototypes) ;
- types appliqués aux adresses ;
- bindings de types sur paramètres et variables locales.

Les timestamps, chemins locaux et identifiants SQLite ne sont jamais exportés. À l’import,
les chemins internes des stores de types sont recalculés pour la machine cible. Une annotation
locale humaine en conflit est conservée et signalée dans le rapport.

## Export et import

```bash
cd extension
python -m backends.static.annotations.project_format \
  --binary ./firmware.elf \
  --workspace-root ./.pile-ou-face \
  export --output ./analysis.pof.json

python -m backends.static.annotations.project_format \
  --binary /autre/chemin/firmware.elf \
  --workspace-root /autre/projet/.pile-ou-face \
  import --input ./analysis.pof.json
```

Le fichier `analysis.pof.json` peut être committé et revu comme n’importe quel fichier source.
Le code de sortie vaut `0` en cas de succès et `2` pour un format invalide, un hash différent
ou une donnée refusée.
