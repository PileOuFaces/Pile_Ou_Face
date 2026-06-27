from backends.mcp.tool_scanner import scan_backend_tools


def test_scan_skips_modules_without_flag(tmp_path):
    (tmp_path / "no_flag.py").write_text("def my_func(): pass\n")
    tools = scan_backend_tools(tmp_path)
    assert not any(t["name"].startswith("no_flag.") for t in tools)


def test_scan_discovers_enabled_module(tmp_path):
    (tmp_path / "my_mod.py").write_text(
        "__mcp_enabled__ = True\n"
        "def greet(name: str) -> str:\n"
        "    '''Say hello.'''\n"
        "    return f'Hello {name}'\n"
    )
    tools = scan_backend_tools(tmp_path)
    assert any(t["name"] == "my_mod.greet" for t in tools)


def test_scan_skips_private_functions(tmp_path):
    (tmp_path / "mod.py").write_text(
        "__mcp_enabled__ = True\ndef _private(): pass\ndef public(): pass\n"
    )
    tools = scan_backend_tools(tmp_path)
    names = [t["name"] for t in tools]
    assert "mod._private" not in names
    assert "mod.public" in names


def test_scan_generates_schema_from_type_hints(tmp_path):
    (tmp_path / "patch_mod.py").write_text(
        "__mcp_enabled__ = True\n"
        "def apply(path: str, offset: int, dry_run: bool = False) -> dict:\n"
        "    '''Apply a patch.'''\n"
        "    pass\n"
    )
    tools = scan_backend_tools(tmp_path)
    t = next(t for t in tools if t["name"] == "patch_mod.apply")
    schema = t["inputSchema"]
    assert schema["properties"]["path"] == {"type": "string"}
    assert schema["properties"]["offset"] == {"type": "integer"}
    assert schema["properties"]["dry_run"] == {"type": "boolean"}
    assert "path" in schema["required"]
    assert "offset" in schema["required"]
    assert "dry_run" not in schema["required"]


def test_scan_uses_docstring_first_line(tmp_path):
    (tmp_path / "doc_mod.py").write_text(
        "__mcp_enabled__ = True\ndef fn():\n    '''First line. Second line.'''\n    pass\n"
    )
    tools = scan_backend_tools(tmp_path)
    t = next(t for t in tools if t["name"] == "doc_mod.fn")
    assert "First line" in t["description"]


def test_scan_respects_exclude_names(tmp_path):
    (tmp_path / "conflict.py").write_text("__mcp_enabled__ = True\ndef my_fn(): pass\n")
    tools = scan_backend_tools(tmp_path, exclude_names={"conflict.my_fn"})
    assert not any(t["name"] == "conflict.my_fn" for t in tools)


def test_scan_handles_optional_type_hint(tmp_path):
    (tmp_path / "opt_mod.py").write_text(
        "__mcp_enabled__ = True\ndef fn(x: str | None = None) -> None:\n    pass\n"
    )
    tools = scan_backend_tools(tmp_path)
    t = next(t for t in tools if t["name"] == "opt_mod.fn")
    # str | None should produce {"type": "string"}, not {}
    assert t["inputSchema"]["properties"]["x"] == {"type": "string"}
