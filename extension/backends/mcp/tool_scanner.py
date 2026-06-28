"""
tool_scanner.py — Auto-discover MCP tools from Python modules.

Scans a directory tree for Python modules that declare ``__mcp_enabled__ = True``
and generates MCP tool descriptor dicts from their public function signatures.
"""

import importlib.util
import inspect
import types
from pathlib import Path
from typing import Any, get_args, get_origin

# Mapping from Python primitive types to JSON Schema type strings.
TYPE_MAP: dict[type, dict[str, str]] = {
    str: {"type": "string"},
    int: {"type": "integer"},
    float: {"type": "number"},
    bool: {"type": "boolean"},
}


def _param_schema(annotation: Any) -> dict:
    """Convert a single parameter annotation to a JSON Schema fragment.

    Handles:
    - Primitive types (str, int, float, bool)
    - list[X] — produces {"type": "array", "items": {...}}
    - Optional[X] / Union[X, None] — unwraps to the non-None type schema
    - str | None  (Python 3.10+ native union syntax) — unwraps to the non-None type schema
    - Unknown annotations — returns {} (no schema constraint)
    """
    # Native union syntax: str | None  (Python 3.10+)
    if isinstance(annotation, types.UnionType):
        non_none = [a for a in annotation.__args__ if a is not type(None)]
        if non_none:
            return TYPE_MAP.get(non_none[0], {})
        return {}

    origin = get_origin(annotation)
    args = get_args(annotation)

    # list[X]
    if origin is list and args:
        inner = TYPE_MAP.get(args[0], {})
        return {"type": "array", "items": inner} if inner else {"type": "array"}

    # Optional[X] / Union[X, None] from typing module
    if origin is not None and args:
        non_none = [a for a in args if a is not type(None)]
        if non_none:
            return TYPE_MAP.get(non_none[0], {})

    return TYPE_MAP.get(annotation, {})


def scan_backend_tools(
    root: Path,
    exclude_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Scan *root* for Python modules with ``__mcp_enabled__ = True``.

    For each qualifying module, inspect all public (non-underscore) functions
    and build an MCP tool descriptor dict with:
    - ``name``        — ``"<module_stem>.<function_name>"``
    - ``description`` — first line of the function's docstring (or the name)
    - ``inputSchema`` — JSON Schema object derived from type annotations

    Parameters
    ----------
    root:
        Directory to scan (searched recursively for ``*.py`` files).
    exclude_names:
        Optional set of ``"module.function"`` names to skip.

    Returns
    -------
    list[dict]
        Ordered list of MCP tool descriptor dicts.
    """
    exclude_names = exclude_names or set()
    tools: list[dict[str, Any]] = []

    for path in sorted(root.rglob("*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if not spec or not spec.loader:
            continue

        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except (Exception, SystemExit):
            # Modules with missing dependencies, syntax errors, or that call
            # sys.exit at module level (e.g. argparse in __main__.py) are
            # silently skipped — they can't be registered as tools.
            continue

        if not getattr(module, "__mcp_enabled__", False):
            continue

        slug = path.stem

        for fn_name, fn in inspect.getmembers(module, inspect.isfunction):
            # Skip private helpers and a conventional entry-point.
            if fn_name.startswith("_") or fn_name == "main":
                continue

            # Filter out functions imported from other modules
            if fn.__module__ != slug:
                continue

            tool_name = f"{slug}.{fn_name}"
            if tool_name in exclude_names:
                continue

            sig = inspect.signature(fn)
            doc = (fn.__doc__ or "").strip().split("\n")[0]

            props: dict[str, Any] = {}
            required: list[str] = []

            for pname, param in sig.parameters.items():
                ann = param.annotation
                schema = (
                    _param_schema(ann) if ann is not inspect.Parameter.empty else {}
                )
                props[pname] = schema
                if param.default is inspect.Parameter.empty:
                    required.append(pname)

            tools.append(
                {
                    "name": tool_name,
                    "description": doc or tool_name,
                    "inputSchema": {
                        "type": "object",
                        "properties": props,
                        "required": required,
                        "additionalProperties": False,
                    },
                }
            )

    return tools
