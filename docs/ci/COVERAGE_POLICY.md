# Politique de couverture

Les seuils de couverture **ne baissent jamais pour faire passer la CI**. Toute baisse exige une décision écrite. Cette décision est liée dans le tableau « Historique » ci-dessous.

## Seuils en vigueur

### Python

Les seuils sont définis dans `extension/pyproject.toml`.

| Gate | Périmètre | Seuil | Job CI |
|---|---|---|---|
| Global (historique) | Sources de `[tool.coverage.run]` | 62 % (`fail_under`) | `full-test`, matrice OS |
| `static+plugins` | `backends/static`, `backends/plugins` (hors tests) | 69 % sous Linux, 68 % sous macOS | `full-test`, matrice OS |
| `dynamic` | `backends/dynamic` (hors tests) | 69 % | `Dynamic Unicorn Regression` |

- **Script :** les gates par composant sont vérifiées par `extension/scripts/check_coverage_gates.py`, à partir de `[tool.pof.coverage_gates]`.
- **Gate sans données :** une gate nommée par un job mais sans données mesurées échoue. Une gate ne peut donc jamais passer parce que son code n'a pas été mesuré.
- **Mesure de `dynamic` :** elle est faite par le job `Dynamic Unicorn Regression`. Ce job installe `unicorn==2.1.4`, lance tout `backends/dynamic/tests` et mesure `backends/dynamic` seul. Il tourne pour toute modification de `extension/backends/**`, car la pipeline dynamic utilise aussi des analyses static.
- **unicorn dans `full-test` :** le job installe la même version. Les tests dynamic n'y seront exécutés qu'une fois collectés par `testpaths` (#524). Sans unicorn, ils y seraient ignorés et feraient baisser le taux global.

### JavaScript

Les seuils c8 sont définis dans `extension/.c8rc.json`.

| Mesure | Seuil |
|---|---|
| lines / statements | 54 % |
| branches | 70 % |
| functions | 83 % |

## Différence Linux / macOS

Sous macOS, 18 tests de `backends/static/tests` sont ignorés volontairement. Ils compilent un binaire ELF avec gcc, mais le gcc de macOS est clang et produit du Mach-O. `compile_minimal_elf` (`backends/static/tests/util.py`) renvoie donc `None` dès que `sys.platform != "linux"`.

| Fichier de test | Tests ignorés sous macOS seulement |
|---|---|
| `test_disasm.py` | 4 |
| `test_calling_convention.py` | 3 |
| `test_symbols.py`, `test_sections.py`, `test_headers.py`, `test_binary_metadata_model.py` | 2 chacun |
| `test_tools_symbols.py`, `test_tools_strings.py`, `test_tools_disasm.py`, `test_analysis_index.py` | 1 chacun |

À l'inverse, `test_macho_symbol_types.py` ne tourne que sous macOS.

**Mesures :**
- `static+plugins` : 68,02 % sous macOS et 69,34 % sous Linux. Valeurs identiques sur deux exécutions complètes de la CI de la PR #532, avec la même liste de tests ignorés.
- Le seuil macOS (`fail_under_by_platform`) suit la règle du ratchet : arrondi inférieur du taux mesuré sur cette plateforme.

**Si le taux macOS fluctue sous 68 %,** le seuil n'est pas baissé : il faut identifier la source de variation et la corriger.

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
| 2026-11-21 | Gates `static+plugins` 69 % (68 % sous macOS, tests ELF ignorés par conception) et `dynamic` 69 %, global 62 % conservé ; c8 relevé de 30/30/60/76 à 54/54/70/83 | Mainteneur, mission de finalisation pré-V1 |
