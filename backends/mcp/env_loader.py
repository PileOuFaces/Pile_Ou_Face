import os
from pathlib import Path

_DEFAULT_ENV_PATH = Path.home() / ".pile-ou-face" / ".env"


def _load_env_file(path: Path) -> None:
    """Load key=value pairs from path into os.environ (existing vars take priority)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _write_env_key(key: str, value: str, path: Path = _DEFAULT_ENV_PATH) -> None:
    """Write or update a single key in the .env file. Creates the file if absent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()
    prefix = f"{key}="
    new_line = f"{key}={value}"
    updated = False
    for i, line in enumerate(lines):
        if line.strip().startswith(prefix):
            lines[i] = new_line
            updated = True
            break
    if not updated:
        lines.append(new_line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_pof_env() -> None:
    """Load ~/.pile-ou-face/.env into os.environ at MCP startup."""
    _load_env_file(_DEFAULT_ENV_PATH)
