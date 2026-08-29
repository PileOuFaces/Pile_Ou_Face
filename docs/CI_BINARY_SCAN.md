# Scan binaire headless en CI

Le scanner CI orchestre les capacités des plugins installés sans démarrer VS Code :

```bash
cd extension
python -m backends.ci_scan ./dist/application \
  --plugin-path "$POF_PLUGIN_PATH" \
  --feature yara_scan \
  --feature capa_scan \
  --feature vulns \
  --format sarif \
  --output pof-results.sarif \
  --fail-on high
```

Pour un plugin `ONLINE_STANDARD`, Auth fournit le JSON `{"content_keys": {...}}` au
pipeline. Passez-le sur stdin et activez `BINHOST_CONTENT_KEYS_STDIN=1`, comme dans
l’exemple GitHub Actions. La valeur ne doit jamais être écrite dans le dépôt ou le rapport.

Les plugins, licences et dépendances d’analyse restent à installer dans le runner. Le host
public ne contient pas les capacités premium. L’exécution explicite de cette commande vaut
consentement pour les plugins indiqués ; leurs règles habituelles de licence restent appliquées.

## Codes de sortie

| Code | Signification |
|---:|---|
| `0` | Scan terminé, aucun résultat au niveau configuré par `--fail-on` |
| `1` | Au moins un résultat atteint le seuil (`high` par défaut) |
| `2` | Erreur opérationnelle : binaire absent, plugin/feature indisponible ou scan en échec |

`--format json` produit le rapport natif avec le SHA-256 du binaire, le bilan de chaque
feature et les résultats normalisés. `--format sarif` produit SARIF 2.1.0, importable dans
GitHub Code Scanning. Utilisez `--fail-on none` pour publier les résultats sans bloquer le job.

## Exemple GitHub Actions

Le workflow copiable [`docs/ci/binary-scan-action.yml`](ci/binary-scan-action.yml)
compile l’artefact, lance le scanner, téléverse le SARIF même lorsque le seuil est dépassé,
puis conserve le code de sortie pour faire échouer le job. Il attend un secret GitHub
`POF_PLUGIN_CONTENT_KEYS_JSON` contenant le payload éphémère délivré par Auth.
