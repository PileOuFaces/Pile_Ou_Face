# Compatibilité IDAPython (idc / idautils / idaapi)

Le shim `backends/static/compat/ida/` permet à des scripts IDAPython publics
non modifiés (`import idc, idautils, idaapi`) de tourner tels quels contre
les backends `backends.static.*` de Pile ou Face, via `repl.py`
(`patched_ida_runtime`).

Toute API non listée ci-dessous lève `NotImplementedError` à l'appel —
jamais de faux-négatif silencieux (valeur par défaut ou `False` renvoyée
comme si l'appel avait réussi).

## `idc`

| API | Support |
|-----|---------|
| `BADADDR` | Supporté |
| `get_func_name(ea)` | Supporté |
| `get_name(ea)` | Supporté (alias de `get_func_name`) |
| `get_name_ea_simple(name)` | Supporté |
| `get_bytes(ea, size)` | Supporté |
| `get_operand_value(ea, n)` | Partiel — opérandes immédiats/mémoire à offset constant uniquement |
| `GetDisasm(ea)` | Supporté |
| `generate_disasm_line(ea, flags)` | Supporté (alias de `GetDisasm`) |
| `set_name(ea, name)` | Supporté — écrit via `AnnotationStore` (`source="script"`) |
| `set_cmt(ea, text)` | Supporté — écrit via `AnnotationStore` (`source="script"`) |
| `get_cmt(ea)` | Supporté |
| `next_head(ea, maxea)` | Supporté |
| `prev_head(ea, minea)` | Supporté |
| `here()` | Non supporté — pas de curseur en exécution headless |
| Tout le reste | Non supporté |

## `idautils`

| API | Support |
|-----|---------|
| `Functions(start, end)` | Supporté |
| `XrefsTo(ea, flags)` | Supporté |
| `XrefsFrom(ea, flags)` | Supporté |
| `Strings(default_setup)` | Supporté |
| Tout le reste | Non supporté |

## `idaapi`

| API | Support |
|-----|---------|
| `BADADDR` | Supporté |
| `get_func(ea)` | Supporté |
| `get_imagebase()` | Supporté |
| `func_t` | Supporté (classe minimale, `start_ea`/`end_ea`) |
| Tout le reste | Non supporté |

## Limites connues

- `get_operand_value` ne résout que les opérandes numériques simples (immédiat
  ou offset constant dans une expression mémoire) — pas d'évaluation
  d'expression arbitraire.
- Aucune modélisation de la base d'image réelle : `get_imagebase()` renvoie
  l'adresse minimale connue parmi les fonctions découvertes, pas la valeur
  ELF `e_entry`/segment de chargement.
- Aucun état de curseur interactif (`here()`, sélection courante) : le
  shim tourne en headless pur.
