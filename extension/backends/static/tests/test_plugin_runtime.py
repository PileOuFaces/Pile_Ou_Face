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

from backends.plugins.install_license import install_license
from backends.plugins.install_plugin import install_plugin
from backends.plugins.license import default_license_search_paths
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

    def test_default_license_search_paths_prefers_workspace_root_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            workspace_root = project / ".pile-ou-face"
            workspace_root.mkdir(parents=True)
            paths = default_license_search_paths(
                cwd=project, home=Path(tmp) / "home", env={}
            )
        self.assertEqual(paths, [(workspace_root / "licenses").resolve()])

    def test_default_license_search_paths_falls_back_to_home_without_workspace_root(
        self,
    ):
        paths = default_license_search_paths(
            cwd="/tmp/project", home="/tmp/home", env={}
        )
        self.assertEqual(paths, [Path("/tmp/home/.pile-ou-face/licenses").resolve()])

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

    def test_valid_signed_account_based_license_unlocks_plugin(self):
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
                build_plugin_registry([base], host_version="0.1.0"),
                search_paths=[license_dir],
            )
            self.assertEqual(records[0].state, "active")
            self.assertEqual(records[0].license_status, "unlocked")
            with self._with_env(BINHOST_LICENSE_PATH=str(license_dir)):
                response, _, _ = invoke_plugin_command(
                    records,
                    "demo.scan.run",
                    {"binaryPath": "/tmp/demo.bin"},
                    host_version="0.1.0",
                )
            self.assertTrue(response["ok"])
            self.assertEqual(response["result"]["binaryPath"], "/tmp/demo.bin")

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

    def test_install_license_copies_license_into_user_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "demo-license.json"
            source.write_text(
                json.dumps(
                    {
                        "plugin_id": "pof.demo-plugin",
                        "license_id": "lic-001",
                        "signature": "ZmFrZQ==",
                    }
                ),
                encoding="utf-8",
            )
            target_root = base / ".pile-ou-face" / "licenses"
            result = install_license(source, target_root)
            self.assertTrue(result["ok"])
            destination = target_root / "pof.demo-plugin.license.json"
            self.assertTrue(destination.exists())
            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8"))["license_id"],
                "lic-001",
            )

    def test_install_encrypted_plugin_bundle_uses_signed_license(self):
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
            state = collect_runtime_state(
                host_version="0.1.0",
                search_paths=[target_root],
                license_search_paths=[license_dir],
                attach=True,
            )
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


if __name__ == "__main__":
    unittest.main()
