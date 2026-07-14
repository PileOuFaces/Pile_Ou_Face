# SPDX-License-Identifier: AGPL-3.0-only
"""Generate a minimal open-source plugin skeleton.

See docs/static/PLUGIN_DEV.md for the full contract. This only saves the
boilerplate of hand-copying an existing plugin's folder structure — it does
not validate anything beyond what it generates itself. Run
`python -m backends.plugins.runtime validate <path>` on the result before
relying on it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from backends.plugins.runtime import DEFAULT_HOST_VERSION, HOST_API_VERSION

_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_NAMESPACE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]*\.[a-z][a-z0-9-]*$")


class ScaffoldError(ValueError):
    """Invalid scaffold input."""


def _validate_plugin_id(plugin_id: str) -> str:
    plugin_id = plugin_id.strip()
    if not _NAMESPACE_ID_RE.match(plugin_id):
        raise ScaffoldError(
            f"id invalide: {plugin_id!r} — attendu <namespace>.<slug> "
            "(minuscules, chiffres, tirets), ex. 'acme.strings-enricher'"
        )
    return plugin_id


def _slug_from_id(plugin_id: str) -> str:
    return plugin_id.split(".", 1)[1]


def _command_id_from_slug(slug: str) -> str:
    return slug.replace("-", "_")


def _manifest_json(plugin_id: str, name: str, slug: str, with_webview: bool) -> dict:
    command_prefix = _command_id_from_slug(slug)
    manifest = {
        "id": plugin_id,
        "name": name,
        "version": "0.1.0",
        "kind": "analysis-pack",
        "license": "MIT",
        "host": {
            "api_version": HOST_API_VERSION,
            "min_version": DEFAULT_HOST_VERSION,
            "max_version": f"{DEFAULT_HOST_VERSION.rsplit('.', 1)[0]}.x",
        },
        "distribution": {
            "encrypted": False,
            "bundle_format": "directory",
        },
        "licensing": {
            "required": False,
            "mode": "",
            "status": "unlocked",
            "message": "",
        },
        "capabilities": {
            "analysis": [f"{command_prefix}.run"],
        },
        "commands": [
            {"id": f"{command_prefix}.run", "feature": command_prefix},
        ],
        "entrypoints": {
            "python": {
                "module": "plugin_main",
                "register": "register_plugin",
            },
        },
    }
    if with_webview:
        manifest["minPoFVersion"] = "1.1.0"
        manifest["entrypoints"]["webview"] = {
            "tab_html": "webview/tab.html",
            "scripts": ["webview/tab.js"],
        }
        manifest["ui"] = {
            "family": command_prefix,
            "tabs": [{"id": command_prefix, "label": name}],
        }
    return manifest


def _plugin_main_py(slug: str) -> str:
    command_prefix = _command_id_from_slug(slug)
    return f'''"""{slug} — plugin principal.

Voir docs/static/PLUGIN_DEV.md dans le repo host pour le contrat complet
(register_plugin, PluginContext, isolation des imports, etc.).
"""

from __future__ import annotations

from pathlib import Path


def register_plugin(context) -> None:
    context.register_command(
        "{command_prefix}.run",
        _run,
    )


def _run(payload: dict) -> dict:
    binary_path = str(payload.get("binaryPath") or payload.get("binary_path") or "")
    if not binary_path or not Path(binary_path).exists():
        return {{"ok": False, "error": f"Fichier introuvable: {{binary_path}}"}}

    # TODO: ton analyse ici.
    return {{"ok": True, "binary_path": binary_path}}
'''


def _tab_html(slug: str) -> str:
    command_prefix = _command_id_from_slug(slug)
    return f'''<style>
#static{command_prefix.title().replace("_", "")} .empty-state {{
  color: var(--vscode-descriptionForeground, #9a9a9a);
  padding: 12px;
}}
</style>

<div id="static{command_prefix.title().replace("_", "")}" class="static-panel">
  <div id="{command_prefix}Content" class="data-container">
    <p class="empty-state">Ouvre un binaire pour lancer l'analyse.</p>
  </div>
</div>
'''


def _camel_case(snake_case: str) -> str:
    parts = snake_case.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _tab_js(slug: str) -> str:
    command_prefix = _command_id_from_slug(slug)
    invoke_fn = (
        "invoke"
        + _camel_case(command_prefix)[0].upper()
        + _camel_case(command_prefix)[1:]
    )
    return f"""// {slug} — webview. Voir docs/static/PLUGIN_DEV.md, section
// "Webview et window.PoF" — la SEULE surface supportee pour parler au host
// est window.PoF (pas d'acces direct au DOM/aux globals du host, l'iframe
// isole ce plugin des autres et du host).

function {invoke_fn}(payload) {{
  var binaryPath = (window.PoF && window.PoF.getBinaryPath()) || '';
  window.vscode.postMessage({{
    type: 'hubPluginInvoke',
    feature: '{command_prefix}',
    binaryPath: binaryPath,
    payload: payload || {{}},
  }});
}}

window.addEventListener('message', function (event) {{
  var msg = event.data;
  if (!msg || msg.type !== 'hubPluginResult' || msg.feature !== '{command_prefix}') return;
  var container = document.getElementById('{command_prefix}Content');
  if (!container) return;
  var result = msg.result || {{}};
  container.textContent = JSON.stringify(result, null, 2);
}});

if (window.PoF && typeof window.PoF.registerTabLoader === 'function') {{
  window.PoF.registerTabLoader('{command_prefix}', function (binaryPath) {{
    if (!binaryPath) return;
    window.PoF.setLoading('{command_prefix}Content', 'Analyse en cours\\u2026');
    {invoke_fn}({{}});
  }});
}}
"""


def _readme_md(name: str, plugin_id: str) -> str:
    return f"""# {name}

Plugin pour Pile ou Face ({plugin_id}).

## Installer pour tester

```bash
export BINHOST_PLUGIN_PATH=/chemin/vers/le/dossier/parent/de/ce/plugin
python -m backends.plugins.runtime list --attach
```

Voir `docs/static/PLUGIN_DEV.md` dans le repo host pour le guide complet
(structure, contrat `window.PoF`, checklist avant publication).
"""


def scaffold_plugin(
    output_dir: str | Path,
    *,
    plugin_id: str,
    name: str,
    with_webview: bool = False,
    force: bool = False,
) -> Path:
    """Create a minimal plugin skeleton at ``output_dir``. Returns the plugin root."""
    plugin_id = _validate_plugin_id(plugin_id)
    slug = _slug_from_id(plugin_id)
    if not _SLUG_RE.match(slug):
        raise ScaffoldError(f"slug dérivé de l'id invalide: {slug!r}")

    root = Path(output_dir).expanduser().resolve()
    if root.exists() and any(root.iterdir()) and not force:
        raise ScaffoldError(
            f"{root} existe déjà et n'est pas vide (utilise --force pour écraser)"
        )

    root.mkdir(parents=True, exist_ok=True)
    (root / "python").mkdir(exist_ok=True)

    manifest = _manifest_json(plugin_id, name, slug, with_webview)
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (root / "python" / "plugin_main.py").write_text(
        _plugin_main_py(slug), encoding="utf-8"
    )
    (root / "README.md").write_text(_readme_md(name, plugin_id), encoding="utf-8")

    if with_webview:
        (root / "webview").mkdir(exist_ok=True)
        (root / "webview" / "tab.html").write_text(_tab_html(slug), encoding="utf-8")
        (root / "webview" / "tab.js").write_text(_tab_js(slug), encoding="utf-8")

    return root


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Génère un squelette minimal de plugin Pile ou Face."
    )
    parser.add_argument(
        "output_dir", help="Dossier où créer le plugin (créé si absent)"
    )
    parser.add_argument(
        "--id",
        required=True,
        dest="plugin_id",
        help="Identifiant du plugin, format <namespace>.<slug> (ex. acme.strings-enricher)",
    )
    parser.add_argument("--name", required=True, help="Nom affiché du plugin")
    parser.add_argument(
        "--with-webview",
        action="store_true",
        help="Génère aussi webview/tab.html + tab.js (sinon plugin backend-only)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Écrase le contenu de output_dir s'il existe déjà",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        root = scaffold_plugin(
            args.output_dir,
            plugin_id=args.plugin_id,
            name=args.name,
            with_webview=args.with_webview,
            force=args.force,
        )
    except ScaffoldError as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1
    print(f"Plugin créé dans {root}")
    print("Prochaine étape : python -m backends.plugins.runtime validate " + str(root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
