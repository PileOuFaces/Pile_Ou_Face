# Développer un plugin pour Pile ou Face

Ce guide s'adresse aux développeurs qui veulent créer un plugin open source pour Pile ou Face.

---

## Principes fondamentaux

**No plugin, no problem** — le host reste fonctionnel sans aucun plugin installé.

**Fail closed for plugin, fail open for host** — si un plugin échoue au chargement, le host continue sans lui.

**Contract first** — le `manifest.json` et le format des hooks sont stables. Ne jamais casser l'interface publique.

**No domain plugin logic in host** — le host intègre et exécute, mais ne contient aucune logique métier spécifique aux plugins.

---

## Structure minimale d'un plugin

```
mon-plugin/
├── manifest.json          ← OBLIGATOIRE
└── python/
    └── plugin_main.py     ← OBLIGATOIRE si entrypoint Python déclaré
```

Structure complète recommandée :

```
mon-plugin/
├── manifest.json
├── README.md
├── python/
│   └── plugin_main.py
├── data/
│   └── (règles YARA, signatures, wordlists, etc.)
└── metadata/
    └── (clés publiques, extras)
```

### Générer ce squelette automatiquement

Depuis le repo host (`extension/`) :

```bash
python -m backends.plugins.scaffold /chemin/vers/mon-plugin \
  --id acme.mon-plugin --name "Mon Plugin" [--with-webview]
```

Génère `manifest.json`, `python/plugin_main.py`, `README.md`, et (avec
`--with-webview`) `webview/tab.html` + `webview/tab.js` déjà câblés sur
`window.PoF` (voir plus bas). Valide ensuite avec
`python -m backends.plugins.runtime validate /chemin/vers/mon-plugin`.

---

## Format `manifest.json`

### Champs obligatoires

```json
{
  "id": "acme.mon-plugin",
  "name": "Mon Plugin",
  "version": "1.0.0",
  "kind": "analysis-pack",
  "host": {
    "api_version": 1,
    "min_version": "0.1.0",
    "max_version": "0.1.x"
  },
  "entrypoints": {
    "python": {
      "module": "plugin_main",
      "register": "register_plugin"
    }
  }
}
```

### Champs optionnels recommandés

```json
{
  "id": "acme.mon-plugin",
  "name": "Mon Plugin",
  "version": "1.0.0",
  "kind": "analysis-pack",
  "license": "MIT",

  "host": {
    "api_version": 1,
    "min_version": "0.1.0",
    "max_version": "0.1.x"
  },

  "ui": {
    "family": "audit",
    "tab_label": "MON PLUGIN",
    "tab_color": {
      "bg":     "#1a2a1a",
      "fg":     "#a8d5a8",
      "border": "#4a8a4a"
    },
    "tabs": [
      { "tabId": "main", "label": "Analyse", "hint": "Vue principale de l'analyse." }
    ]
  },

  "distribution": {
    "encrypted": false,
    "bundle_format": "directory"
  },

  "licensing": {
    "required": false,
    "mode": "",
    "status": "unlocked",
    "message": ""
  },

  "capabilities": {
    "analysis": ["mon_enricher.enrich"],
    "exports": ["mon_export_json"]
  },

  "dependencies": {
    "host_features": [
      "static.symbols",
      "static.strings",
      "static.call_graph"
    ]
  },

  "entrypoints": {
    "python": {
      "module": "plugin_main",
      "register": "register_plugin"
    }
  }
}
```

---

## Référence des champs `manifest.json`

### Champ `id`

**Obligatoire.** Format : `<namespace>.<slug>` en minuscules avec tirets.

```
acme.mon-plugin
com-exemple.analyseur-elf
```

Convention pour les plugins open source :
- namespace = votre pseudo GitHub ou organisation
- slug = nom court du plugin

### Champ `kind`

**Obligatoire.** Toujours `"analysis-pack"` pour les plugins d'analyse.

### Champ `host`

**Obligatoire.** Déclare la compatibilité avec le host.

```json
"host": {
  "api_version": 1,
  "min_version": "0.1.0",
  "max_version": "0.1.x"
}
```

`api_version: 1` est la seule valeur supportée actuellement.

### Champ `ui.family`

Détermine dans quel groupe UI le plugin apparaît.

| Valeur | Usage |
|---|---|
| `"audit"` | Analyse de vulnérabilités |
| `"malware"` | Triage malware |
| `"offensif"` | Recherche offensive |
| Valeur custom | Groupe UI dédié (si non réservé) |

Si absent, le plugin est fonctionnel mais n'active aucun groupe UI optionnel.

### Champ `distribution`

Pour un plugin open source non chiffré :

```json
"distribution": {
  "encrypted": false,
  "bundle_format": "directory"
}
```

### Champ `licensing`

Pour un plugin libre sans licence :

```json
"licensing": {
  "required": false,
  "mode": "",
  "status": "unlocked",
  "message": ""
}
```

### Champ `capabilities`

Déclare ce que le plugin expose. Utilisé par le host pour le découverte.

```json
"capabilities": {
  "analysis": ["nom_enricher.enrich"],
  "exports": ["nom_export_json", "nom_export_markdown"]
}
```

### Champ `dependencies.host_features`

Déclare les capacités du host dont dépend le plugin. Le host peut les vérifier à l'attachement.

```
static.symbols        — symboles ELF/PE/Mach-O
static.strings        — extraction de chaînes
static.call_graph     — graphe d'appels
static.decompile      — décompilation
static.import_xrefs   — références croisées d'imports
shared.log            — système de log structuré
```

---

## Entrypoint Python : `register_plugin`

C'est la seule fonction appelée par le host. Elle reçoit un `context` et doit enregistrer les handlers.

```python
# python/plugin_main.py

from __future__ import annotations
import sys
from pathlib import Path


def register_plugin(context) -> None:
    """Point d'entrée appelé par le host Pile ou Face."""
    _setup_path()
    _register(context)


def _setup_path() -> None:
    """Ajoute src/ au sys.path pour les imports relatifs."""
    candidates = [
        Path(__file__).resolve().parent / "runtime" / "src",
        Path(__file__).resolve().parent / "source" / "src",
        Path(__file__).resolve().parents[3] / "src",
    ]
    for path in candidates:
        if path.is_dir():
            src = str(path)
            if src not in sys.path:
                sys.path.insert(0, src)
            return


def _register(context) -> None:
    from mon_module.analyse import analyser

    # Enricher d'analyse
    context.register_analysis_enricher(
        "mon_enricher",
        lambda payload: payload,
    )

    # Commande invocable depuis l'UI ou le MCP
    context.register_command(
        "mon_plugin.run",
        lambda payload: analyser(
            str(payload.get("binaryPath") or payload.get("binary_path") or "")
        ),
    )

    # Exporteur de résultats
    context.register_exporter(
        "mon_export_json",
        lambda payload: payload,
    )
```

### API `PluginContext`

| Méthode | Signature | Description |
|---|---|---|
| `register_analysis_enricher` | `(target: str, callback: Callable)` | Enrichisseur sur un type d'analyse |
| `register_command` | `(command_id: str, callback: Callable)` | Commande invocable |
| `register_exporter` | `(exporter_id: str, callback: Callable)` | Exporteur de résultats |
| `register_ui_panel` | `(panel_id: str, descriptor: dict)` | Panneau UI personnalisé |

#### `register_command`

Le callback reçoit un `payload: dict` et doit retourner un `dict` JSON-sérialisable.

```python
context.register_command(
    "mon_plugin.analyser",
    lambda payload: {
        "ok": True,
        "results": analyser(payload.get("binaryPath", "")),
    }
)
```

Conventions de nommage des commandes :

```
<famille>.<action>.run       — action principale
<famille>.<sous-action>.run  — sous-action

# Exemples
audit.vulns.run
malware.behavior.run
offensive.rop.run
mon_plugin.analyse.run
```

#### `register_analysis_enricher`

Déclenché lors de l'analyse. Le callback reçoit le payload d'analyse et peut y ajouter des champs.

```python
context.register_analysis_enricher(
    "mon_enricher",
    lambda payload: {**payload, "mon_champ": calculer(payload)}
)
```

#### `register_exporter`

Permet d'exporter les résultats dans un format spécifique.

```python
context.register_exporter(
    "mon_export_markdown",
    lambda payload: format_markdown(payload),
)
```

#### `register_ui_panel`

Enregistre un panneau UI avec un descripteur.

```python
context.register_ui_panel(
    "mon_panneau",
    {
        "label": "Mon Analyse",
        "tab": "main",
    }
)
```

### Attributs disponibles sur `context`

| Attribut | Type | Description |
|---|---|---|
| `context.host_version` | `str` | Version du host |
| `context.api_version` | `int` | Version de l'API (toujours `1`) |
| `context.paths["cwd"]` | `str` | Répertoire courant |
| `context.paths["home"]` | `str` | Répertoire home de l'utilisateur |
| `context.logger` | Logger | Logger structuré |

---

## Installation locale pour les tests

### 1. Installer dans le storage VS Code

Depuis l'extension, utiliser `Options > Plugins > Installer…`. Le host extrait le
plugin dans `context.storageUri/plugins/`, par exemple :

```text
~/Library/Application Support/Code/User/workspaceStorage/<workspace-id>/PileOuFaces.stack-visualizer/plugins/
```

Ne copiez pas de plugin dans `.pile-ou-face/plugins`. Ce chemin n'est pas le
contrat de chargement de l'extension. `.pile-ou-face/` reste le dossier des
caches et artefacts du projet ; les plugins installes par VS Code vivent dans
`context.storageUri/plugins/`.

### 2. Copier le plugin pour un test CLI

```bash
export BINHOST_PLUGIN_PATH="$HOME/Library/Application Support/Code/User/workspaceStorage/<workspace-id>/PileOuFaces.stack-visualizer/plugins"

# Vérifier la structure
ls "$BINHOST_PLUGIN_PATH/acme.mon-plugin/"
# → manifest.json  python/  README.md
```

### 3. Vérifier la détection

```bash
python -m backends.plugins.runtime list
```

Résultat attendu :
```
acme.mon-plugin  active  My Plugin  1.0.0
```

### 4. Attacher et tester

```bash
python -m backends.plugins.runtime list --attach
python -m backends.plugins.runtime inspect acme.mon-plugin
```

### 5. Invoquer une commande

```bash
python -m backends.plugins.runtime invoke mon_plugin.run \
  --payload-json '{"binaryPath": "/chemin/vers/binaire.elf"}'
```

---

## Commandes runtime utiles

```bash
# Lister les plugins détectés
python -m backends.plugins.runtime list

# Lister et attacher
python -m backends.plugins.runtime list --attach

# Inspecter un plugin
python -m backends.plugins.runtime inspect acme.mon-plugin

# Valider un manifest
python -m backends.plugins.runtime validate /chemin/vers/plugin/

# Invoquer une commande
python -m backends.plugins.runtime invoke <command_id> \
  --payload-json '{"binaryPath": "..."}'

# Afficher l'identifiant machine
python -m backends.plugins.runtime machine-id
```

---

## Variables d'environnement

| Variable | Description |
|---|---|
| `POF_PLUGIN_PATH` | Chemins supplémentaires de découverte (séparateur `:`) |

```bash
POF_PLUGIN_PATH=/mes/plugins:/autres/plugins python -m backends.plugins.runtime list
```

---

## Chemins de découverte

Dans l'extension VS Code, le host injecte explicitement :

```text
BINHOST_PLUGIN_PATH=<context.storageUri>/plugins
```

Pour les tests CLI hors VS Code, définir `POF_PLUGIN_PATH` ou `BINHOST_PLUGIN_PATH`
vers le dossier de plugins à tester.

---

## Webview et `window.PoF`

Chaque plugin peut fournir un `webview/tab.html` et un `webview/tab.js`. Depuis
la P3 (isolation iframe), **le webview d'un plugin tourne dans son propre
`<iframe sandbox="allow-scripts allow-same-origin">`** (`srcdoc`), séparé du
DOM du host et de celui des autres plugins. Le `tab.html` peut contenir un
bloc `<style>` librement — il n'est plus scopé/réécrit par le host, puisque
l'iframe l'isole déjà complètement (y compris ses propres `:root { --var }`).

Concrètement, ça veut dire :

- ton `tab.js` a son propre `document`, ses propres globals JS — il ne partage
  **rien** avec le host ni avec les autres plugins (pas d'accès direct à
  `document.getElementById` du host, pas de fonctions du host disponibles en
  global).
- La **seule** surface de contrat supportée pour parler au host est
  **`window.PoF`** (injecté automatiquement dans chaque iframe de plugin) :

  ```js
  // Adresse binaire actuellement ouverte (synchrone)
  const binaryPath = window.PoF?.getBinaryPath() ?? '';

  // Cache par onglet, propre à ton plugin (clé = tabId)
  window.PoF?.setTabCache('myTab', { binaryPath, result });
  const cached = window.PoF?.getTabCache('myTab');

  // Appelé quand l'utilisateur ouvre un nouveau binaire / active ton onglet
  window.PoF?.registerTabLoader('myTab', (binaryPath) => {
    vscode.postMessage({ type: 'hubPluginInvoke', feature: 'my.command', binaryPath, payload: {} });
  });

  // Indicateur de chargement dans TON propre DOM (pas de round-trip host)
  window.PoF?.setLoading('myTabContent', 'Analyse en cours…');

  // Stockage persistant propre au plugin
  window.PoF?.saveStorage({ myPreference: 'value' });

  // Navigation réelle dans le host (switch de panel/onglet, jump-to-address,
  // reveal xrefs/strings) — voir la table d'actions ci-dessous
  window.PoF?.navigateTo('jumpToAddr', { tab: 'disasm', addr, binaryPath });
  ```

  `window.PoF` est versionné (`window.PoF.version`, ex. `"1.1.0"`) ; déclare
  `minPoFVersion` dans ton `plugin.json` si tu dépends d'une méthode récente.
  Le host refuse d'attacher un plugin dont le `minPoFVersion` dépasse sa
  propre version.

  Méthodes disponibles sur `window.PoF` (référence complète — ne jamais
  utiliser autre chose pour parler au host depuis un webview) :

  | Méthode | Description |
  |---|---|
  | `version` | Chaîne SemVer de cette surface d'API (ex. `"1.1.0"`) |
  | `getBinaryPath()` | Chemin du binaire actuellement ouvert, ou `''`. Synchrone. |
  | `getTabCache(key)` | Lit une entrée de cache propre à ton plugin |
  | `setTabCache(key, value)` | Écrit une entrée de cache propre à ton plugin |
  | `registerTabLoader(tabId, fn)` | Appelle `fn(binaryPath)` quand l'utilisateur change de binaire ou active `tabId` |
  | `saveStorage(data)` | Persiste des données clé/valeur propres au plugin |
  | `setLoading(containerId, message)` | Affiche un indicateur de chargement dans un élément de **ton propre** DOM |
  | `getGroupLabels()` | `{tabId: label}` pour tous les onglets enregistrés (tous plugins confondus) |
  | `getTabFamilies()` | `{tabId: family}` pour tous les onglets enregistrés |
  | `getDisabledFamilies()` | `Set` des familles que l'utilisateur a désactivées |
  | `navigateTo(action, params)` | Exécute une action de navigation réelle côté host (fire-and-forget, voir table ci-dessous) |

  Actions `navigateTo` :

  | Action | Params | Effet |
  |---|---|---|
  | `showPanel` | `{panel}` | Change le panel principal (`static`, `dynamic`, `outils`, `options`) |
  | `showGroup` | `{group, tab}` | Change le groupe/sous-onglet dans le panel `static` |
  | `jumpToAddr` | `{tab, addr, binaryPath, opts}` | Navigue vers une adresse dans un onglet (disasm/cfg/callgraph/decompile/hex) |
  | `setActiveAddress` | `{addr, spanLength, opts}` | Synchronise l'état "adresse active" du host |
  | `ensureDecompileSources` | `{binaryPath}` | Charge sections/symboles/fonctions nécessaires avant une requête de décompilation |
  | `syncFunctionsSelection` | `{addr}` | Sélectionne la ligne correspondante dans l'onglet Fonctions |
  | `openXrefs` | `{addr, spanLength, mode}` | Révèle le panneau xrefs et lance la recherche pour `addr` |
  | `openStringAt` | `{addr, spanLength}` | Révèle l'onglet Strings et va à `addr` |

- Les résultats de tes commandes Python arrivent via un message `postMessage`
  standard (`vscode.postMessage({type: 'hubPluginInvoke', feature, binaryPath, payload})`
  côté plugin → réponse `{type: 'hubPluginResult', feature, plugin_id, result}`
  relayée automatiquement dans **ton** iframe). Écoute-la avec
  `window.addEventListener('message', (e) => { const msg = e.data; if (msg.type === 'hubPluginResult' && msg.feature === 'my.command') { ... } })`.

- Ne compte sur **rien d'autre** que `window.PoF` et le message `hubPluginResult` —
  pas de variable globale du host, pas de fonction déclarée par un autre
  plugin (chaque iframe est isolé, même entre plugins). Si une capacité te
  manque sur `window.PoF`, c'est un signal pour l'ajouter côté host plutôt que
  de contourner (voir `CONTRACTS_SHARED.md`, section `window.PoF`, dans le
  workspace root — c'est la référence normative et la plus à jour).

> ⚠️ **La preview locale des plugins (`npm run preview`, `scripts/preview.mjs`)
> n'utilise pas encore ce modèle iframe** — elle injecte encore le webview
> directement dans sa propre page et fournit les anciens globals bruts
> (`window.showPanel`, `window.tabDataCache`, etc.) au lieu de `window.PoF`.
> Un plugin qui n'appelle plus que `window.PoF.*` (recommandé ci-dessus) ne
> sera donc pas correctement exercé par cet outil tant qu'il n'aura pas été
> mis à jour. Teste dans l'extension réelle (VS Code) pour valider le
> comportement final.

---

## Règles de compatibilité

### Ce que le host garantit

- Le `manifest.json` est validé avant l'attachement
- `register_plugin(context)` est appelé avec un `PluginContext` valide
- Si `register_plugin` lève une exception, le plugin passe à l'état `failed` mais le host continue
- L'API `PluginContext` est stable dans une même `api_version`

### Ce que le plugin NE doit pas faire

- Appeler `sys.exit()` ou `os._exit()` — cela tuerait le host
- Modifier `sys.path` globalement sans nettoyer — risque de conflits
- Importer des modules au top-level du `plugin_main.py` — tout import se fait dans `register_plugin` ou dans les callbacks, pour éviter les erreurs à la découverte
- Écrire des fichiers en dehors de `context.paths["home"]` sans raison explicite

---

## Bonnes pratiques

### Structure du code

```
mon-plugin/
├── manifest.json
├── README.md
├── python/
│   ├── plugin_main.py        ← entrypoint seul ici
│   └── source/
│       └── src/
│           └── mon_module/
│               ├── __init__.py
│               └── analyse.py
└── tests/
    └── test_analyse.py
```

Le `plugin_main.py` ne contient que la logique de registration. La logique métier vit dans `source/src/`.

### Gestion des erreurs dans les commandes

```python
def ma_commande(payload: dict) -> dict:
    binary_path = str(payload.get("binaryPath") or "")
    if not binary_path:
        return {"ok": False, "error": "binaryPath requis"}
    try:
        result = analyser(binary_path)
        return {"ok": True, "results": result}
    except FileNotFoundError:
        return {"ok": False, "error": f"Fichier introuvable: {binary_path}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
```

Le callback ne doit **jamais** lever d'exception non gérée. Retourner `{"ok": False, "error": "..."}` à la place.

### Isolation des imports

```python
# Mauvais — les imports au top-level cassent la découverte si le module est absent
import numpy as np  # ← trop tôt

def register_plugin(context):
    ...

# Bien — les imports sont différés dans les callbacks
def register_plugin(context):
    def run(payload):
        import numpy as np  # ← importé seulement à l'invocation
        ...
    context.register_command("mon_plugin.run", run)
```

### Payload d'entrée

Toujours accepter les deux formes de clé (`binaryPath` camelCase et `binary_path` snake_case) :

```python
binary_path = (
    payload.get("binaryPath")
    or payload.get("binary_path")
    or ""
)
```

### README.md

Chaque plugin doit inclure un `README.md` à sa racine avec :

- description du plugin
- capabilities exposées
- liste des commandes et leur payload attendu
- exemples de résultats
- dépendances Python si applicable

---

## Exemple complet : plugin d'analyse de chaînes

```
strings-enricher/
├── manifest.json
├── README.md
└── python/
    └── plugin_main.py
```

**`manifest.json`**

```json
{
  "id": "acme.strings-enricher",
  "name": "Strings Enricher",
  "version": "1.0.0",
  "kind": "analysis-pack",
  "license": "MIT",
  "host": {
    "api_version": 1,
    "min_version": "0.1.0",
    "max_version": "0.1.x"
  },
  "distribution": {
    "encrypted": false,
    "bundle_format": "directory"
  },
  "licensing": {
    "required": false,
    "mode": "",
    "status": "unlocked",
    "message": ""
  },
  "capabilities": {
    "analysis": ["strings_enricher.enrich"]
  },
  "entrypoints": {
    "python": {
      "module": "plugin_main",
      "register": "register_plugin"
    }
  }
}
```

**`python/plugin_main.py`**

```python
"""Plugin d'enrichissement de chaînes de caractères."""

from __future__ import annotations
import re
import subprocess
from pathlib import Path


def register_plugin(context) -> None:
    context.register_command(
        "strings_enricher.classify",
        _classify_strings,
    )


def _classify_strings(payload: dict) -> dict:
    binary_path = str(payload.get("binaryPath") or payload.get("binary_path") or "")
    if not binary_path or not Path(binary_path).exists():
        return {"ok": False, "error": f"Fichier introuvable: {binary_path}"}

    try:
        proc = subprocess.run(
            ["strings", "-n", "6", binary_path],
            capture_output=True, text=True, timeout=30,
        )
        strings = proc.stdout.splitlines()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    urls = [s for s in strings if re.match(r"https?://", s)]
    ips  = [s for s in strings if re.match(r"\d{1,3}(\.\d{1,3}){3}", s)]

    return {
        "ok": True,
        "total": len(strings),
        "urls": urls[:50],
        "ips": ips[:50],
    }
```

---

## Intégration MCP

Quand un plugin est actif, ses commandes sont accessibles via le MCP du host.

Appel typique depuis un client MCP :

```json
// 1. Lister les plugins actifs
{ "tool": "plugins_list" }

// 2. Invoquer une commande
{
  "tool": "plugin_invoke",
  "arguments": {
    "command": "strings_enricher.classify",
    "payload": { "binaryPath": "/abs/path/sample.elf" }
  }
}
```

Les commandes peuvent aussi apparaître directement dans `tools/list` sous le nom `plugin.<command_id>`.

---

## États runtime d'un plugin

| État | Description |
|---|---|
| `active` | Plugin attaché et fonctionnel |
| `disabled` | Plugin désactivé manuellement |
| `invalid` | `manifest.json` invalide ou absent |
| `incompatible` | Version host incompatible avec `host.min_version` / `host.max_version` |
| `failed` | `register_plugin` a levé une exception |
| `locked` | Plugin chiffré sans licence valide |

---

## Checklist avant publication

- `manifest.json` valide (vérifier avec `python -m backends.plugins.runtime validate /chemin/`)
- `id` unique au format `<namespace>.<slug>`
- `version` au format semver `x.y.z`
- `register_plugin(context)` sans import au top-level de `plugin_main.py`
- Tous les callbacks retournent `dict` JSON-sérialisable
- Pas d'appel à `sys.exit()` ni `os._exit()`
- `README.md` à la racine avec les commandes documentées
- Tests locaux passants : `python -m backends.plugins.runtime list --attach`

---

## Distribution : dossier brut, pas de bundle `.pofplug`

Aujourd'hui, il n'existe **aucun outil public** pour produire un bundle
`.pofplug` (le format zippé utilisé pour les 4 plugins maison premium — leur
outil de packaging vit dans un dépôt privé). La façon supportée de distribuer
un plugin communautaire est le **dossier brut** :

1. Publie ton plugin comme un dépôt git normal (dossier avec `manifest.json`,
   `plugin_main.py`, `webview/`, etc. — la structure décrite plus haut).
2. L'utilisateur clone/télécharge ce dossier, puis l'installe via
   *Options → Plugins → Installer…* dans l'extension (accepte un dossier, pas
   seulement un zip), ou en le plaçant directement dans
   `<storageUri>/plugins/<plugin_id>/` (voir "Installation locale pour les
   tests" plus haut — le même mécanisme sert à l'installation finale).

C'est délibérément le chemin recommandé pour l'instant plutôt que d'essayer de
répliquer l'outil de compilation/packaging premium : un plugin ouvert n'a pas
besoin de compilation à bytecode ni de chiffrement, et un dossier brut clair
est plus simple à auditer pour un utilisateur prudent qu'un binaire zippé.

## Limites actuelles du host

Le host open source ne supporte pas encore :

- la saisie manuelle d'une clé courte pour activer un plugin
- la compilation ou l'obfuscation des plugins tiers
- la révocation ou l'activation en ligne
- un outil public de packaging en bundle `.pofplug` (voir section
  "Distribution" ci-dessus — utilise un dossier brut en attendant)
- un registre/annuaire centralisé des plugins communautaires disponibles

### Surface Python au-delà de `backends.plugin_api`

`backends.plugin_api` (7 symboles stables : `get_logger`, `configure_logging`,
`build_offset_to_vaddr`, `ArchInfo`, `FeatureSupport`,
`detect_binary_arch_from_path`, `get_feature_support`, `get_raw_arch_info`) est
la **seule** surface Python dont la stabilité est garantie entre versions du
host. D'autres modules `backends.*` existent et fonctionnent (désassemblage,
décompilation, gestion de règles YARA…), mais leur usage n'est pas couvert par
une promesse de compatibilité — le host peut les faire évoluer sans préavis.
Si ton plugin en a besoin, importe-les à l'intérieur d'une fonction (jamais en
top-level de `plugin_main.py`, voir "Isolation des imports" plus haut) et
attends-toi à devoir ajuster ton code lors d'une mise à jour du host. Si une
capacité te semble devoir être stable, ouvre une discussion — c'est un signal
pour l'ajouter à `backends.plugin_api`.
