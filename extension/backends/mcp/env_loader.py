"""Lecture et écriture de ``~/.pile-ou-face/.env`` (clés API IA locales).

Protection du fichier :

- POSIX : le dossier est créé en ``0700`` et le fichier en ``0600`` dès leur
  création ; un dossier ou un fichier existant trop ouvert est resserré à
  l'écriture et un avertissement est journalisé (sans la valeur des clés).
- Windows : les bits de mode POSIX ne s'appliquent pas. Le fichier hérite des
  ACL du dossier parent (par défaut le profil utilisateur ``%USERPROFILE%``) ;
  aucune ACL spécifique n'est posée et aucune vérification n'est faite.
- Dans tous les cas, ces permissions ne protègent pas contre un autre
  processus exécuté sous le même compte utilisateur.

L'écriture est atomique : fichier temporaire dans le même dossier, puis
``os.replace``. En cas d'erreur, le fichier temporaire est supprimé et le
fichier d'origine reste intact.
"""

import logging
import os
import stat
import tempfile
from pathlib import Path

_DEFAULT_ENV_PATH = Path.home() / ".pile-ou-face" / ".env"
_DIR_MODE = 0o700
_FILE_MODE = 0o600
_GROUP_OTHER_BITS = 0o077
_IS_POSIX = os.name == "posix"
_TOO_OPEN_MESSAGE = "Permissions trop ouvertes sur %s (%o), ramenées à %o"

_log = logging.getLogger(__name__)


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


def _too_open_mode(path: Path) -> int | None:
    """Return the current mode if group/other bits are set, else None (POSIX only)."""
    if not _IS_POSIX:
        return None
    current = stat.S_IMODE(path.stat().st_mode)
    return current if current & _GROUP_OTHER_BITS else None


def _ensure_private_dir(directory: Path) -> None:
    """Create the directory in 0700, or tighten an existing too-open one."""
    directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    current = _too_open_mode(directory)
    if current is not None:
        os.chmod(directory, _DIR_MODE)
        _log.warning(_TOO_OPEN_MESSAGE, directory, current, _DIR_MODE)


def _atomic_write_private(path: Path, content: str) -> None:
    """Write content to a 0600 temp file in the same directory, then os.replace."""
    # mkstemp crée le fichier via os.open(O_CREAT | O_EXCL, 0o600) : le mode est
    # posé à la création, pas corrigé après coup.
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _updated_lines(lines: list[str], key: str, value: str) -> list[str]:
    prefix = f"{key}="
    new_line = f"{key}={value}"
    for i, line in enumerate(lines):
        if line.strip().startswith(prefix):
            lines[i] = new_line
            return lines
    lines.append(new_line)
    return lines


def _write_env_key(key: str, value: str, path: Path = _DEFAULT_ENV_PATH) -> None:
    """Write or update a single key in the .env file. Creates the file if absent.

    The write is atomic; on POSIX the file ends up in 0600 inside a 0700
    directory (see the module docstring for the Windows strategy).
    """
    _ensure_private_dir(path.parent)
    lines: list[str] = []
    previous_mode: int | None = None
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()
        previous_mode = _too_open_mode(path)
    content = "\n".join(_updated_lines(lines, key, value)) + "\n"
    _atomic_write_private(path, content)
    if previous_mode is not None:
        _log.warning(_TOO_OPEN_MESSAGE, path, previous_mode, _FILE_MODE)


def load_pof_env() -> None:
    """Load ~/.pile-ou-face/.env into os.environ at MCP startup."""
    _load_env_file(_DEFAULT_ENV_PATH)
