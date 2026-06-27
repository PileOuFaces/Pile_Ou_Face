# Corpus de calibration du scoring décompilateur

Ce répertoire contient des exemples synthétiques de pseudo-C à différents niveaux
de qualité, utilisés pour calibrer et valider la fonction `_score_decompile_code`
dans `backends/static/decompile/decompile.py`.

## Niveaux de qualité

| Niveau | Score attendu | Description |
|--------|--------------|-------------|
| `high` | ≥ 50 | Pseudo-C lisible : types précis, flux de contrôle clair, appels de fonctions résolus, pas de symboles placeholder |
| `medium` | 15–49 | Partiellement lisible : quelques gotos, types génériques, placeholders limités |
| `low` | 0–14 | Difficilement lisible : nombreux gotos, WARNINGs, symbols bas niveau |
| `bad` | < 0 | Inutilisable : majoritairement des placeholders, stubs vides, code ASM brut |

## Format des fixtures

Chaque fichier JSON contient :
```json
{
  "tool":        "ghidra | retdec | angr | generic",
  "arch":        "x86_64 | arm64 | arm32",
  "quality":     "high | medium | low | bad",
  "score_min":   <int>,
  "score_max":   <int>,
  "description": "...",
  "code":        "..."
}
```

## Utilisation

```python
from backends.static.decompile.decompile import _score_decompile_code

with open("fixtures/decompile_corpus/ghidra_x86_64_high.json") as f:
    sample = json.load(f)

result = _score_decompile_code(sample["code"])
assert sample["score_min"] <= result["score"] <= sample["score_max"]
```

## Source

Ces exemples sont synthétiques, inspirés de sorties réelles de Ghidra, RetDec et Angr
sur des binaires ELF x86-64 et ARM64 courants (fibonacci, sort, string utilities).
Ils ne contiennent aucun code propriétaire.
