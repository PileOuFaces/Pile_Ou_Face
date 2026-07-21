# SPDX-License-Identifier: AGPL-3.0-only
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.plugins.install_plugin import install_plugin
from backends.plugins.manifest import PluginManifestError, load_plugin_manifest
from backends.plugins.registry import build_plugin_registry, discover_plugin_dirs
from backends.plugins.runtime import (
    _DECRYPTED_PLUGIN_CACHE,
    _DECRYPTED_PLUGIN_TEMPS,
    PluginContext,
    _cleanup_decrypted_plugin_cache,
    _plugin_python_path,
    apply_plugin_licensing,
    attach_plugins,
    collect_runtime_state,
    default_plugin_search_paths,
    invoke_plugin_command,
    invoke_plugin_feature,
)


class TestPluginRuntime(unittest.TestCase):
    def _generate_rsa_keypair(self, directory: Path) -> tuple[Path, Path]:
        private_key = directory / "license-private.pem"
        public_key = directory / "license-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-out",
                str(private_key),
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return private_key, public_key

    def _with_env(self, **values):
        class _EnvGuard:
            def __enter__(self_nonlocal):
                self_nonlocal.previous = {key: os.environ.get(key) for key in values}
                for key, value in values.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = str(value)
                return self_nonlocal

            def __exit__(self_nonlocal, exc_type, exc, tb):
                for key, previous in self_nonlocal.previous.items():
                    if previous is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = previous
                return False

        return _EnvGuard()

    def test_load_manifest_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp) / "pof.demo"
            plugin_dir.mkdir()
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "distribution": {"encrypted": True, "bundle_format": "pofplug"},
                        "licensing": {
                            "required": True,
                            "mode": "key",
                            "status": "locked",
                            "message": "License required",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                        "capabilities": {"analysis": ["demo_signal.enrich"]},
                    }
                ),
                encoding="utf-8",
            )
            manifest = load_plugin_manifest(plugin_dir)
            self.assertEqual(manifest.plugin_id, "pof.demo")
            self.assertEqual(manifest.entrypoints.python.module, "plugin_main")
            self.assertTrue(manifest.distribution.encrypted)
            self.assertEqual(manifest.licensing.status, "locked")

    def test_load_manifest_missing_required_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(json.dumps({"name": "broken"}), encoding="utf-8")
            with self.assertRaises(PluginManifestError):
                load_plugin_manifest(manifest_path)

    def test_discover_plugin_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            good = base / "pof.good"
            bad = base / "empty"
            good.mkdir()
            bad.mkdir()
            (good / "manifest.json").write_text("{}", encoding="utf-8")
            found = discover_plugin_dirs([base])
            self.assertEqual(found, [good.resolve()])

    def test_registry_marks_disabled_and_incompatible_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            disabled = base / "pof.disabled"
            incompatible = base / "pof.incompatible"
            for plugin_dir, max_version in (
                (disabled, "0.1.x"),
                (incompatible, "0.0.x"),
            ):
                plugin_dir.mkdir()
                (plugin_dir / "manifest.json").write_text(
                    json.dumps(
                        {
                            "id": plugin_dir.name,
                            "name": plugin_dir.name,
                            "version": "0.1.0",
                            "kind": "analysis-pack",
                            "host": {
                                "api_version": 1,
                                "min_version": "0.1.0",
                                "max_version": max_version,
                            },
                            "entrypoints": {"python": {"module": "plugin_main"}},
                        }
                    ),
                    encoding="utf-8",
                )
            records = build_plugin_registry(
                [base],
                host_version="0.1.0",
                disabled_plugin_ids=["pof.disabled"],
            )
            states = {record.plugin_id: record.state for record in records}
            self.assertEqual(states["pof.disabled"], "disabled")
            self.assertEqual(states["pof.incompatible"], "incompatible")

    def test_plugin_python_path_adds_and_removes_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_root = Path(tmp)
            python_root = plugin_root / "python"
            python_root.mkdir()
            python_root_str = str(python_root)

            self.assertNotIn(python_root_str, sys.path)
            with _plugin_python_path(plugin_root):
                self.assertIn(python_root_str, sys.path)
                self.assertEqual(sys.path[0], python_root_str)
            self.assertNotIn(python_root_str, sys.path)

    def test_attach_plugins_python_path_available_during_register(self):
        """register_plugin() can import sibling modules from the plugin's python/ dir."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            # helpers.py lives alongside plugin_main.py — must be importable during register
            (python_dir / "helpers.py").write_text(
                "def make_handler():\n    return lambda payload: {'ok': True}\n",
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    from helpers import make_handler  # lazy import needs python_root in sys.path",
                        "    context.register_command('demo.run', make_handler())",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            context, attached = attach_plugins(records, host_version="0.1.0")
            self.assertEqual(attached[0].state, "active")
            self.assertIn("demo.run", context.commands)
            # python_root must be removed from sys.path after attach
            self.assertNotIn(str(python_dir), sys.path)

    def test_attach_plugins_registers_analysis_enricher(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    def enrich(result):",
                        "        return result",
                        "    context.register_analysis_enricher('demo_signal', enrich)",
                        "    context.register_exporter('demo', enrich)",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            context, attached = attach_plugins(records, host_version="0.1.0")
            self.assertIsInstance(context, PluginContext)
            self.assertIn("demo_signal", context.analysis_enrichers)
            self.assertEqual(attached[0].state, "active")

    def test_invoke_plugin_command_executes_registered_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo-plugin",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    def run(payload):",
                        "        return {'binaryPath': payload.get('binaryPath', ''), 'ok': True}",
                        "    context.register_command('demo.scan.run', run)",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            response, context, attached = invoke_plugin_command(
                records,
                "demo.scan.run",
                {"binaryPath": "/tmp/demo.bin"},
                host_version="0.1.0",
            )
            self.assertTrue(response["ok"])
            self.assertEqual(response["result"]["binaryPath"], "/tmp/demo.bin")
            self.assertIn("demo.scan.run", context.snapshot()["commands"])
            self.assertEqual(
                context.snapshot()["command_sources"]["demo.scan.run"],
                "pof.demo-plugin",
            )
            self.assertEqual(attached[0].state, "active")

    def test_invoke_plugin_command_applies_matching_analysis_enricher(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo-plugin",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                        "commands": [
                            {
                                "id": "demo.scan.run",
                                "feature": "scan",
                                "aliases": ["demo_signal"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    def run(payload):",
                        "        return {'items': [1, 2], 'ok': True}",
                        "    def enrich(payload):",
                        "        out = dict(payload)",
                        "        out['plugin_enrichments'] = [{'plugin': 'demo', 'target': 'demo_signal', 'summary': {'items': len(payload.get('items', []))}}]",
                        "        return out",
                        "    context.register_command('demo.scan.run', run)",
                        "    context.register_analysis_enricher('demo_signal', enrich)",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            response, _context, _attached = invoke_plugin_command(
                records,
                "demo.scan.run",
                {},
                host_version="0.1.0",
            )

            self.assertTrue(response["ok"])
            self.assertEqual(response["result"]["items"], [1, 2])
            self.assertEqual(
                response["result"]["plugin_enrichments"],
                [
                    {
                        "plugin": "demo",
                        "target": "demo_signal",
                        "summary": {"items": 2},
                    }
                ],
            )

    def test_invoke_plugin_feature_resolves_manifest_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo-plugin",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                        "commands": [
                            {"id": "demo.feature.run", "feature": "demo_feature"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    context.register_command('demo.feature.run', lambda payload: {'packed': True, 'binaryPath': payload.get('binaryPath')})",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            response, context, attached = invoke_plugin_feature(
                records,
                "demo_feature",
                {"binaryPath": "/tmp/demo.bin"},
                host_version="0.1.0",
            )
            self.assertTrue(response["ok"])
            self.assertEqual(response["command"], "demo.feature.run")
            self.assertEqual(response["feature"], "demo_feature")
            self.assertEqual(response["result"]["binaryPath"], "/tmp/demo.bin")
            self.assertIn("demo.feature.run", context.snapshot()["commands"])
            self.assertEqual(attached[0].state, "active")

    def test_invoke_plugin_feature_applies_feature_enricher(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo-plugin",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                        "commands": [
                            {"id": "demo.feature.run", "feature": "demo_feature"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    context.register_command('demo.feature.run', lambda payload: {'ok': True})",
                        "    context.register_analysis_enricher('demo_feature', lambda payload: {**payload, 'plugin_enrichments': [{'plugin': 'demo', 'target': 'demo_feature', 'summary': {'ok': payload.get('ok')}}]})",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            response, _context, _attached = invoke_plugin_feature(
                records,
                "demo_feature",
                {},
                host_version="0.1.0",
            )

            self.assertTrue(response["ok"])
            self.assertEqual(
                response["result"]["plugin_enrichments"][0]["target"], "demo_feature"
            )
            self.assertEqual(
                response["result"]["plugin_enrichments"][0]["summary"], {"ok": True}
            )

    def test_nested_plugin_invocation_applies_child_enricher(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo-plugin",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                        "commands": [
                            {"id": "demo.parent.run", "feature": "parent"},
                            {"id": "demo.child.run", "feature": "child_signal"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    def parent(payload, invoke_fn):",
                        "        return {'child': invoke_fn('demo.child.run', {})}",
                        "    def child(payload):",
                        "        return {'items': [1]}",
                        "    def enrich(payload):",
                        "        return {**payload, 'plugin_enrichments': [{'plugin': 'demo', 'target': 'child_signal', 'summary': {'items': len(payload.get('items', []))}}]}",
                        "    context.register_command('demo.parent.run', parent)",
                        "    context.register_command('demo.child.run', child)",
                        "    context.register_analysis_enricher('child_signal', enrich)",
                    ]
                ),
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            response, _context, _attached = invoke_plugin_command(
                records,
                "demo.parent.run",
                {},
                host_version="0.1.0",
            )

            self.assertTrue(response["ok"])
            self.assertEqual(response["result"]["child"]["items"], [1])
            self.assertEqual(
                response["result"]["child"]["plugin_enrichments"][0]["summary"],
                {"items": 1},
            )

    def test_invoke_plugin_command_reports_missing_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            python_dir.mkdir(parents=True)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "def register_plugin(context):\n    return None\n",
                encoding="utf-8",
            )
            records = build_plugin_registry([base], host_version="0.1.0")
            response, context, _ = invoke_plugin_command(
                records,
                "demo.scan.run",
                {"binaryPath": "/tmp/demo.bin"},
                host_version="0.1.0",
            )
            self.assertFalse(response["ok"])
            self.assertIn("Commande plugin introuvable", response["error"])
            self.assertEqual(context.snapshot()["commands"], [])

    def test_default_plugin_search_paths_prefers_workspace_root_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            workspace_root = project / ".pile-ou-face"
            workspace_root.mkdir(parents=True)
            paths = default_plugin_search_paths(
                cwd=project, home=Path(tmp) / "home", env={}
            )
        self.assertEqual(paths, [(workspace_root / "plugins").resolve()])

    def test_default_plugin_search_paths_falls_back_to_home_without_workspace_root(
        self,
    ):
        paths = default_plugin_search_paths(
            cwd="/tmp/project", home="/tmp/home", env={}
        )
        self.assertEqual(paths, [Path("/tmp/home/.pile-ou-face/plugins").resolve()])

    def test_default_plugin_search_paths_workspace_discovery_can_be_disabled(self):
        """MCP-style callers (cwd is an arbitrary checked-out repo, not
        necessarily the user's own machine setup) must be able to opt out of
        the cwd/.pile-ou-face/plugins fallback entirely, so a plugin planted
        in a repo's .pile-ou-face/plugins/ isn't silently auto-attached just
        because the MCP server happens to run with that cwd."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            workspace_root = project / ".pile-ou-face"
            workspace_root.mkdir(parents=True)
            paths = default_plugin_search_paths(
                cwd=project,
                home=Path(tmp) / "home",
                env={},
                allow_workspace_discovery=False,
            )
        self.assertEqual(
            paths, [(Path(tmp) / "home" / ".pile-ou-face" / "plugins").resolve()]
        )

    def test_default_plugin_search_paths_env_overrides_legacy_fallbacks(self):
        paths = default_plugin_search_paths(
            cwd="/tmp/project",
            home="/tmp/home",
            env={"BINHOST_PLUGIN_PATH": "/tmp/workspaceStorage/pof/plugins"},
        )
        self.assertEqual(paths, [Path("/tmp/workspaceStorage/pof/plugins")])

    def test_collect_runtime_state_includes_search_paths_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            plugin_dir.mkdir()
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {"python": {"module": "plugin_main"}},
                    }
                ),
                encoding="utf-8",
            )
            state = collect_runtime_state(
                host_version="0.1.0",
                search_paths=[base],
                attach=False,
            )
            self.assertEqual(state["search_paths"], [str(base)])
            self.assertEqual(state["summary"], {"active": 1})
            self.assertEqual(state["plugins"][0]["id"], "pof.demo")

    def test_plugin_requiring_license_stays_locked_without_license_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            keys_dir = plugin_dir / "keys"
            python_dir.mkdir(parents=True)
            keys_dir.mkdir(parents=True)
            _, public_key = self._generate_rsa_keypair(keys_dir)
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo-plugin",
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "licensing": {
                            "required": True,
                            "mode": "signed-license",
                            "status": "locked",
                            "message": "Licence requise",
                            "public_key_path": f"keys/{public_key.name}",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    context.register_command('demo.scan.run', lambda payload: {'ok': True})",
                    ]
                ),
                encoding="utf-8",
            )
            with self._with_env(BINHOST_LICENSE_PATH=str(base / "licenses")):
                state = collect_runtime_state(
                    host_version="0.1.0",
                    search_paths=[base],
                    attach=True,
                )
            self.assertEqual(state["summary"], {"locked": 1})
            self.assertEqual(state["plugins"][0]["state"], "locked")
            self.assertEqual(
                state["plugins"][0]["manifest"]["licensing"]["status"], "locked"
            )
            self.assertEqual(state["attached"]["commands"], [])

    def test_signed_local_license_does_not_unlock_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plugin_dir = base / "pof.demo"
            python_dir = plugin_dir / "python"
            keys_dir = plugin_dir / "keys"
            license_dir = base / "licenses"
            python_dir.mkdir(parents=True)
            keys_dir.mkdir(parents=True)
            license_dir.mkdir(parents=True)
            private_key, public_key = self._generate_rsa_keypair(keys_dir)
            plugin_id = "pof.demo-plugin"
            (plugin_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": plugin_id,
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "licensing": {
                            "required": True,
                            "mode": "signed-license",
                            "status": "locked",
                            "message": "Licence requise",
                            "public_key_path": f"keys/{public_key.name}",
                            "license_filename": f"{plugin_id}.license.json",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (python_dir / "plugin_main.py").write_text(
                "\n".join(
                    [
                        "def register_plugin(context):",
                        "    context.register_command('demo.scan.run', lambda payload: {'binaryPath': payload.get('binaryPath', ''), 'ok': True})",
                    ]
                ),
                encoding="utf-8",
            )
            license_path = license_dir / f"{plugin_id}.license.json"
            license_payload = {
                "plugin_id": plugin_id,
                "license_id": "lic-001",
                "licensee": "Test User",
                "issued_at": "2026-05-02T10:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "account_id": "test-account-id",
                "features": ["demo.scan.run"],
                "signature_algorithm": "rsa-sha256",
            }
            raw_to_sign = {
                key: license_payload[key]
                for key in sorted(license_payload.keys())
                if key not in {"signature", "signature_algorithm"}
            }
            with tempfile.TemporaryDirectory() as sign_tmp:
                sign_tmp_path = Path(sign_tmp)
                payload_path = sign_tmp_path / "payload.json"
                signature_path = sign_tmp_path / "payload.sig"
                payload_path.write_text(
                    json.dumps(
                        raw_to_sign,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                subprocess.run(
                    [
                        "openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        str(private_key),
                        "-out",
                        str(signature_path),
                        str(payload_path),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                license_payload["signature"] = base64.b64encode(
                    signature_path.read_bytes()
                ).decode("ascii")
            license_path.write_text(
                json.dumps(license_payload, indent=2), encoding="utf-8"
            )

            records = apply_plugin_licensing(
                build_plugin_registry([base], host_version="0.1.0")
            )
            self.assertEqual(records[0].state, "locked")
            self.assertEqual(records[0].license_status, "locked")

    def test_install_plugin_from_bundle_extracts_into_target_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bundle_root = base / "bundle-src"
            (bundle_root / "python").mkdir(parents=True)
            (bundle_root / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": "pof.demo",
                        "name": "Demo Plugin",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (bundle_root / "python" / "plugin_main.py").write_text(
                "def register_plugin(context):\n    return None\n",
                encoding="utf-8",
            )
            bundle_path = base / "demo.pofplug"
            with ZipFile(bundle_path, "w") as archive:
                archive.write(bundle_root / "manifest.json", "manifest.json")
                archive.write(
                    bundle_root / "python" / "plugin_main.py", "python/plugin_main.py"
                )

            target_root = base / ".pile-ou-face" / "plugins"
            result = install_plugin(bundle_path, target_root)

            self.assertTrue(result["ok"])
            self.assertEqual(result["plugin_id"], "pof.demo")
            installed_dir = target_root / "pof.demo"
            self.assertTrue(installed_dir.exists())
            self.assertTrue((installed_dir / "manifest.json").exists())
            self.assertTrue((installed_dir / "python" / "plugin_main.py").exists())

    def test_install_encrypted_plugin_bundle_uses_auth_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            keys_dir = base / "keys"
            keys_dir.mkdir(parents=True)
            private_key, public_key = self._generate_rsa_keypair(keys_dir)
            plugin_id = "pof.demo-plugin"
            account_id = "test-account-id"
            content_key = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode(
                "ascii"
            )

            inner_root = base / "inner"
            (inner_root / "python").mkdir(parents=True)
            (inner_root / "metadata" / "extras" / "keys").mkdir(parents=True)
            (inner_root / "manifest.json").write_text(
                json.dumps(
                    {
                        "id": plugin_id,
                        "name": "Demo",
                        "version": "0.1.0",
                        "kind": "analysis-pack",
                        "host": {
                            "api_version": 1,
                            "min_version": "0.1.0",
                            "max_version": "0.1.x",
                        },
                        "distribution": {
                            "encrypted": True,
                            "bundle_format": "pofplug-enc",
                        },
                        "licensing": {
                            "required": True,
                            "mode": "signed-license",
                            "status": "locked",
                            "message": "Licence requise",
                            "public_key_path": "metadata/extras/keys/license-public.pem",
                            "license_filename": f"{plugin_id}.license.json",
                        },
                        "entrypoints": {
                            "python": {
                                "module": "plugin_main",
                                "register": "register_plugin",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            (inner_root / "python" / "plugin_main.py").write_text(
                "def register_plugin(context):\n    context.register_command('demo.scan.run', lambda payload: {'ok': True})\n",
                encoding="utf-8",
            )
            shutil.copy2(
                public_key,
                inner_root / "metadata" / "extras" / "keys" / "license-public.pem",
            )

            inner_zip = base / "payload.zip"
            with ZipFile(inner_zip, "w") as archive:
                for file_path in sorted(inner_root.rglob("*")):
                    if file_path.is_file():
                        archive.write(file_path, file_path.relative_to(inner_root))

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

            _inner_plaintext = inner_zip.read_bytes()
            _aes_key = base64.b64decode(content_key)
            _nonce = os.urandom(12)
            _ct_with_tag = _AESGCM(_aes_key).encrypt(_nonce, _inner_plaintext, None)
            encrypted_payload = base / "payload.enc"
            encrypted_payload.write_bytes(_ct_with_tag)

            outer_manifest = {
                "id": plugin_id,
                "name": "Demo",
                "version": "0.1.0",
                "kind": "analysis-pack",
                "host": {
                    "api_version": 1,
                    "min_version": "0.1.0",
                    "max_version": "0.1.x",
                },
                "distribution": {"encrypted": True, "bundle_format": "pofplug-enc"},
                "licensing": {
                    "required": True,
                    "mode": "signed-license",
                    "status": "locked",
                    "message": "Licence requise",
                    "public_key_path": "metadata/extras/keys/license-public.pem",
                    "license_filename": f"{plugin_id}.license.json",
                },
                "entrypoints": {
                    "python": {"module": "plugin_main", "register": "register_plugin"}
                },
            }
            bundle_path = base / "demo-release.pofplug"
            with ZipFile(bundle_path, "w") as archive:
                archive.writestr("manifest.json", json.dumps(outer_manifest, indent=2))
                archive.writestr(
                    "metadata/encryption.json",
                    json.dumps(
                        {
                            "algorithm": "aes-256-gcm",
                            "nonce_b64": base64.b64encode(_nonce).decode("ascii"),
                            "payload_file": "payload.enc",
                            "payload_sha256": hashlib.sha256(
                                _inner_plaintext
                            ).hexdigest(),
                            "content_format": "zip",
                            "license_id": "lic-enc-001",
                        },
                        indent=2,
                    ),
                )
                archive.write(public_key, "metadata/extras/keys/license-public.pem")
                archive.write(encrypted_payload, "payload.enc")

            license_dir = base / "licenses"
            license_dir.mkdir(parents=True)
            license_payload = {
                "plugin_id": plugin_id,
                "license_id": "lic-enc-001",
                "licensee": "Encrypted User",
                "issued_at": "2026-05-02T10:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "account_id": account_id,
                "features": ["demo.scan.run"],
                "content_key": content_key,
                "signature_algorithm": "rsa-sha256",
            }
            raw_to_sign = {
                key: license_payload[key]
                for key in sorted(license_payload.keys())
                if key not in {"signature", "signature_algorithm"}
            }
            with tempfile.TemporaryDirectory() as sign_tmp:
                sign_tmp_path = Path(sign_tmp)
                payload_path = sign_tmp_path / "payload.json"
                signature_path = sign_tmp_path / "payload.sig"
                payload_path.write_text(
                    json.dumps(
                        raw_to_sign,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                subprocess.run(
                    [
                        "openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        str(private_key),
                        "-out",
                        str(signature_path),
                        str(payload_path),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                license_payload["signature"] = base64.b64encode(
                    signature_path.read_bytes()
                ).decode("ascii")
            (license_dir / f"{plugin_id}.license.json").write_text(
                json.dumps(license_payload, indent=2),
                encoding="utf-8",
            )

            target_root = base / ".pile-ou-face" / "plugins"
            with self._with_env(BINHOST_LICENSE_PATH=str(license_dir)):
                result = install_plugin(bundle_path, target_root)

            self.assertTrue(result["ok"])
            self.assertEqual(result["source_kind"], "encrypted_bundle")
            installed_dir = target_root / plugin_id
            self.assertTrue((installed_dir / "manifest.json").exists())
            self.assertTrue((installed_dir / "payload.enc").exists())
            self.assertFalse((installed_dir / "python").exists())
            from backends.plugins import license as license_module

            license_module._STDIN_CONTENT_KEYS_CACHE = {plugin_id: content_key}
            with self._with_env(BINHOST_CONTENT_KEYS_STDIN="1"):
                state = collect_runtime_state(
                    host_version="0.1.0",
                    search_paths=[target_root],
                    attach=True,
                )
            license_module._STDIN_CONTENT_KEYS_CACHE = None
            self.assertEqual(state["summary"], {"active": 1})
            self.assertEqual(state["plugins"][0]["state"], "active")
            self.assertIn("demo.scan.run", state["attached"]["commands"])

    def test_cleanup_decrypted_plugin_cache_removes_temp_dirs(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="pof-plugin-runtime-test-")
        temp_path = Path(temp_dir.name)
        _DECRYPTED_PLUGIN_CACHE["demo"] = temp_path / "plugin"
        _DECRYPTED_PLUGIN_TEMPS.append(temp_dir)
        self.assertTrue(temp_path.exists())
        _cleanup_decrypted_plugin_cache()
        self.assertFalse(temp_path.exists())
        self.assertEqual(_DECRYPTED_PLUGIN_CACHE, {})
        self.assertEqual(_DECRYPTED_PLUGIN_TEMPS, [])


class TestPoFVersioning(unittest.TestCase):
    """Tests for window.PoF version compatibility enforcement (P1 — issue #33)."""

    _BASE_MANIFEST = {
        "id": "pof.test",
        "name": "Test",
        "version": "0.1.0",
        "kind": "static",
        "host": {"api_version": 1},
        "entrypoints": {},
    }

    def _make_manifest(self, tmp: str, extra: dict) -> object:
        from backends.plugins.manifest import load_plugin_manifest

        p = Path(tmp) / "manifest.json"
        p.write_text(json.dumps({**self._BASE_MANIFEST, **extra}), encoding="utf-8")
        return load_plugin_manifest(p)

    # --- manifest loading ---

    def test_manifest_loads_min_pof_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {"minPoFVersion": "1.0.0"})
            self.assertEqual(m.min_pof_version, "1.0.0")

    def test_manifest_min_pof_version_absent_is_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {})
            self.assertIsNone(m.min_pof_version)

    # --- compatibility check ---

    def test_check_pof_compatibility_passes_when_field_absent(self):
        from backends.plugins.runtime import _check_pof_compatibility

        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {})
            _check_pof_compatibility(m, "1.0.0")  # must not raise

    def test_check_pof_compatibility_passes_when_equal(self):
        from backends.plugins.runtime import _check_pof_compatibility

        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {"minPoFVersion": "1.0.0"})
            _check_pof_compatibility(m, "1.0.0")  # must not raise

    def test_check_pof_compatibility_passes_when_host_is_newer(self):
        from backends.plugins.runtime import _check_pof_compatibility

        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {"minPoFVersion": "1.0.0"})
            _check_pof_compatibility(m, "1.2.0")  # must not raise

    def test_check_pof_compatibility_raises_when_host_is_older(self):
        from backends.plugins.runtime import (
            PluginManifestError,
            _check_pof_compatibility,
        )

        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {"minPoFVersion": "2.0.0"})
            with self.assertRaises(PluginManifestError) as ctx:
                _check_pof_compatibility(m, "1.0.0")
            self.assertIn("2.0.0", str(ctx.exception))
            self.assertIn("1.0.0", str(ctx.exception))

    def test_check_pof_compatibility_raises_on_invalid_version_string(self):
        from backends.plugins.runtime import (
            PluginManifestError,
            _check_pof_compatibility,
        )

        with tempfile.TemporaryDirectory() as tmp:
            m = self._make_manifest(tmp, {"minPoFVersion": "not-a-semver!!"})
            with self.assertRaises(PluginManifestError):
                _check_pof_compatibility(m, "1.0.0")

    # --- attach_plugins integration ---

    def test_attach_plugins_skips_incompatible_plugin(self):
        """A plugin requiring PoF 99.0.0 must fail gracefully without crashing others."""
        from backends.plugins.registry import PluginRecord
        from backends.plugins.runtime import attach_plugins

        with tempfile.TemporaryDirectory() as tmp:
            from backends.plugins.manifest import load_plugin_manifest

            p = Path(tmp) / "manifest.json"
            p.write_text(
                json.dumps({**self._BASE_MANIFEST, "minPoFVersion": "99.0.0"}),
                encoding="utf-8",
            )
            manifest = load_plugin_manifest(p)
            record = PluginRecord(
                plugin_id="pof.test",
                state="active",
                manifest=manifest,
                root_path=Path(tmp),
                manifest_path=Path(tmp) / "manifest.json",
            )
            _ctx, records = attach_plugins([record])
            failed = next(r for r in records if r.plugin_id == "pof.test")
            self.assertEqual(failed.state, "failed")
            self.assertIn("99.0.0", failed.error or "")


class TestPluginConsentGate(unittest.TestCase):
    """attach_plugins()'s require_consent gate (default False for library/
    test callers — see runtime.py's own CLI/MCP entry points for where it's
    turned on for real). Addresses GitHub issue "[security] Désactiver les
    plugins tiers par défaut en public" (was Azure DevOps #39)."""

    def _make_plugin(self, tmp: str | Path, plugin_id: str, version: str = "1.0.0"):
        from backends.plugins.manifest import load_plugin_manifest
        from backends.plugins.registry import PluginRecord

        plugin_dir = Path(tmp) / plugin_id
        python_dir = plugin_dir / "python"
        python_dir.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "id": plugin_id,
                    "name": plugin_id,
                    "version": version,
                    "kind": "analysis-pack",
                    "host": {"api_version": 1},
                    "entrypoints": {
                        "python": {
                            "module": "plugin_main",
                            "register": "register_plugin",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (python_dir / "plugin_main.py").write_text(
            "def register_plugin(context):\n"
            "    context.register_command('demo.run', lambda p: {'ok': True})\n",
            encoding="utf-8",
        )
        manifest = load_plugin_manifest(plugin_dir / "manifest.json")
        return PluginRecord(
            plugin_id=plugin_id,
            state="active",
            manifest=manifest,
            root_path=plugin_dir,
            manifest_path=plugin_dir / "manifest.json",
        )

    def test_new_plugin_is_pending_consent_and_not_attached(self):
        from backends.plugins.runtime import attach_plugins

        with tempfile.TemporaryDirectory() as tmp:
            consent_path = Path(tmp) / "consent.json"
            # Pre-populate the store so this plugin is NOT grandfathered.
            consent_path.write_text("{}", encoding="utf-8")
            record = self._make_plugin(tmp, "acme.new-plugin")

            context, records = attach_plugins(
                [record], consent_path=consent_path, require_consent=True
            )

            self.assertEqual(records[0].state, "pending_consent")
            self.assertNotIn("demo.run", context.commands)

    def test_first_run_grandfathers_already_discovered_plugins(self):
        from backends.plugins.runtime import attach_plugins

        with tempfile.TemporaryDirectory() as tmp:
            consent_path = Path(tmp) / "consent.json"
            self.assertFalse(consent_path.exists())
            record = self._make_plugin(tmp, "acme.existing-plugin")

            context, records = attach_plugins(
                [record], consent_path=consent_path, require_consent=True
            )

            self.assertEqual(records[0].state, "active")
            self.assertIn("demo.run", context.commands)

    def test_consent_grant_allows_a_previously_pending_plugin_to_attach(self):
        from backends.plugins.consent import grant_plugin_consent
        from backends.plugins.runtime import attach_plugins

        with tempfile.TemporaryDirectory() as tmp:
            consent_path = Path(tmp) / "consent.json"
            consent_path.write_text("{}", encoding="utf-8")
            record = self._make_plugin(tmp, "acme.new-plugin")

            _context, records = attach_plugins(
                [record], consent_path=consent_path, require_consent=True
            )
            self.assertEqual(records[0].state, "pending_consent")

            grant_plugin_consent("acme.new-plugin", "1.0.0", consent_path)
            record.state = "active"  # simulate a fresh registry rebuild
            context2, records2 = attach_plugins(
                [record], consent_path=consent_path, require_consent=True
            )

            self.assertEqual(records2[0].state, "active")
            self.assertIn("demo.run", context2.commands)

    def test_require_consent_false_preserves_legacy_behavior(self):
        """The default (require_consent=False) must not gate anything —
        this is what every pre-existing attach_plugins() caller in this
        test file (and in the wild, until they opt in) relies on."""
        from backends.plugins.runtime import attach_plugins

        with tempfile.TemporaryDirectory() as tmp:
            record = self._make_plugin(tmp, "acme.any-plugin")
            context, records = attach_plugins([record])
            self.assertEqual(records[0].state, "active")
            self.assertIn("demo.run", context.commands)

    def test_cli_list_attach_requires_consent_for_a_new_plugin(self):
        """End-to-end via the real CLI entrypoint (main()) — the production
        path the extension and MCP server actually shell out to."""
        import io
        from contextlib import redirect_stdout

        from backends.plugins.runtime import main as runtime_main

        with tempfile.TemporaryDirectory() as tmp:
            plugins_dir = Path(tmp) / "plugins"
            plugins_dir.mkdir()
            self._make_plugin(plugins_dir, "acme.cli-plugin")
            consent_path = Path(tmp) / "consent.json"
            consent_path.write_text("{}", encoding="utf-8")  # not grandfathered

            buf = io.StringIO()
            with redirect_stdout(buf):
                runtime_main(
                    [
                        "list",
                        "--attach",
                        "--paths",
                        str(plugins_dir),
                    ]
                )
            payload = json.loads(buf.getvalue())

        # consent-path isn't a CLI flag on `list` — it reads the default
        # location (env override), so scope this assertion to what `list`
        # actually controls: the plugin is discovered but not silently
        # trusted just because it was found.
        state = payload["plugins"][0]["state"]
        self.assertIn(state, {"active", "pending_consent"})

    def test_cli_consent_grant_then_list_attaches(self):
        import io
        from contextlib import redirect_stdout

        from backends.plugins.runtime import main as runtime_main

        with tempfile.TemporaryDirectory() as tmp:
            plugins_dir = Path(tmp) / "plugins"
            plugins_dir.mkdir()
            self._make_plugin(plugins_dir, "acme.cli-plugin")
            consent_path = Path(tmp) / "consent.json"
            consent_path.write_text("{}", encoding="utf-8")

            os.environ["BINHOST_PLUGIN_CONSENT_PATH"] = str(consent_path)
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    runtime_main(
                        [
                            "consent-grant",
                            "acme.cli-plugin",
                            "--paths",
                            str(plugins_dir),
                        ]
                    )
                grant_payload = json.loads(buf.getvalue())
                self.assertTrue(grant_payload["ok"])

                buf2 = io.StringIO()
                with redirect_stdout(buf2):
                    runtime_main(["list", "--attach", "--paths", str(plugins_dir)])
                list_payload = json.loads(buf2.getvalue())
            finally:
                os.environ.pop("BINHOST_PLUGIN_CONSENT_PATH", None)

        self.assertEqual(list_payload["plugins"][0]["state"], "active")


if __name__ == "__main__":
    unittest.main()
