# Politique de couverture

Les seuils de couverture **ne baissent jamais pour faire passer la CI**. Toute baisse exige une décision écrite. Cette décision est liée dans le tableau « Historique » ci-dessous.

## Seuils en vigueur

### Python

Les seuils sont définis dans `extension/pyproject.toml`.

| Gate | Périmètre | Seuil | Job CI |
|---|---|---|---|
| Global (historique) | Sources de `[tool.coverage.run]` | 62 % (`fail_under`) | `full-test`, matrice OS |
| `static+plugins` | `backends/static`, `backends/plugins` (hors tests) | 69 % | `full-test`, matrice OS |
| `dynamic` | `backends/dynamic` (hors tests) | 69 % | `Dynamic Unicorn Regression` |

- **Script :** les gates par composant sont vérifiées par `extension/scripts/check_coverage_gates.py`, à partir de `[tool.pof.coverage_gates]`.
- **Gate sans données :** une gate nommée par un job mais sans données mesurées échoue. Une gate ne peut donc jamais passer parce que son code n'a pas été mesuré.
- **unicorn installé dans les deux jobs** (`unicorn==2.1.4`) : les tests dynamic sont exécutés, et non ignorés.
- **Job `Dynamic Unicorn Regression` :** il lance tout `backends/dynamic/tests` et mesure `backends/dynamic` seul.

### JavaScript

Les seuils c8 sont définis dans `extension/.c8rc.json`.

| Mesure | Seuil |
|---|---|
| lines / statements | 54 % |
| branches | 70 % |
| functions | 83 % |

## Mesures de référence (2026-11-21)

| Mesure | `develops` (`5982d85`) | Avec `front/`, `dynamic` et `mcp` mesurés (#524) |
|---|---|---|
| Python `static+plugins` (Linux) | 69,3 % | 69,3 à 69,6 % |
| Python `dynamic` avec unicorn | non mesuré | 69,6 % |
| Python `mcp` | non mesuré | 61,6 % |
| JS lines / branches / functions | 81,9 / 76,2 / 89,6 % (`src/` seul) | 54,8 / 70,3 / 83,7 % (`front/` inclus) |

Les seuils JS correspondent à l'arrondi inférieur de l'état le plus exigeant, soit #524 avec `front/` mesuré. Ils ne relèvent pas artificiellement l'exigence : `develops` les dépasse.

## Ratchet

- **Relèvement :** une gate est relevée quand le taux mesuré sur toute la matrice la dépasse d'au moins 2 points. La nouvelle valeur est l'arrondi inférieur du taux le plus bas de la matrice.
- **Baisse :** elle n'est autorisée qu'avec une décision écrite (issue ou commentaire de PR), liée dans l'historique, qui en explique la raison. Exemple : du code devenu mesuré pour la première fois.
- **Nouveau composant mesuré :** sa gate démarre à l'arrondi inférieur de son premier taux mesuré sur toute la matrice.

## Historique

| Date | Changement | Décision |
|---|---|---|
| 2026-11-21 | Gates `static+plugins` 69 % et `dynamic` 69 %, global 62 % conservé ; c8 relevé de 30/30/60/76 à 54/54/70/83 | Mainteneur, mission de finalisation pré-V1 |
