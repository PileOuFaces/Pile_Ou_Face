import errno
import logging
import os
import stat
from unittest.mock import patch

import pytest

from backends.mcp import env_loader
from backends.mcp.env_loader import _load_env_file, _write_env_key

SECRET = "sk-test-secret-value"
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700
GROUP_READABLE_MODE = 0o640  # trop ouvert pour une clé, sans être lisible par tous
GROUP_READABLE_DIR_MODE = 0o750
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
OTHERS_ACCESS_BITS = 0o077


def _reserved_to_current_user(path):
    info = path.stat()
    return (
        info.st_uid == os.getuid()
        and not stat.S_IMODE(info.st_mode) & OTHERS_ACCESS_BITS
    )


@pytest.fixture(autouse=True)
def _fixtures_stay_private(tmp_path):
    """Several tests deliberately create group-readable files (0o640/0o750) holding the
    dummy SECRET, to check that the loader tightens them. That is only safe because
    pytest places tmp_path under a 0o700 directory owned by the current user: nobody
    else can traverse to the fixtures. Fail instead of exposing them otherwise
    (e.g. a shared --basetemp)."""
    if os.name == "posix":
        assert any(
            _reserved_to_current_user(p) for p in (tmp_path, *tmp_path.parents)
        ), f"{tmp_path} is reachable by other users"


@posix_only
def test_privacy_guard_rejects_a_directory_open_to_others(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, GROUP_READABLE_DIR_MODE)
    assert not _reserved_to_current_user(shared)
    os.chmod(shared, PRIVATE_DIR_MODE)
    assert _reserved_to_current_user(shared)


def test_load_sets_missing_vars(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\nBAZ=qux\n")
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("FOO", None)
        os.environ.pop("BAZ", None)
        _load_env_file(env_file)
        assert os.environ["FOO"] == "bar"
        assert os.environ["BAZ"] == "qux"


def test_load_does_not_override_existing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=from_file\n")
    with patch.dict(os.environ, {"FOO": "existing"}, clear=False):
        _load_env_file(env_file)
        assert os.environ["FOO"] == "existing"


def test_load_skips_comments(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("# comment\nVALID=yes\n")
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("VALID", None)
        _load_env_file(env_file)
        assert os.environ.get("VALID") == "yes"


def test_load_strips_quotes(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=\"value\"\nKEY2='value2'\n")
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("KEY", None)
        os.environ.pop("KEY2", None)
        _load_env_file(env_file)
        assert os.environ["KEY"] == "value"
        assert os.environ["KEY2"] == "value2"


def test_load_missing_file_is_noop(tmp_path):
    before = dict(os.environ)
    _load_env_file(tmp_path / "nonexistent.env")
    assert os.environ == before


def test_write_creates_file(tmp_path):
    env_file = tmp_path / ".env"
    _write_env_key("MY_KEY", "my_value", env_file)
    assert "MY_KEY=my_value" in env_file.read_text()


def test_write_updates_existing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("MY_KEY=old\nOTHER=x\n")
    _write_env_key("MY_KEY", "new", env_file)
    content = env_file.read_text()
    assert "MY_KEY=new" in content
    assert "MY_KEY=old" not in content
    assert "OTHER=x" in content


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_write_creates_private_file_and_dir(tmp_path):
    env_dir = tmp_path / "pof"
    env_file = env_dir / ".env"
    _write_env_key("ANTHROPIC_API_KEY", SECRET, env_file)
    assert _mode(env_file) == PRIVATE_FILE_MODE
    assert _mode(env_dir) == PRIVATE_DIR_MODE


@posix_only
def test_write_tightens_existing_open_file(tmp_path, caplog):
    env_file = tmp_path / ".env"
    env_file.write_text("OTHER=x\n")
    os.chmod(env_file, GROUP_READABLE_MODE)
    with caplog.at_level(logging.WARNING, logger=env_loader.__name__):
        _write_env_key("OPENAI_API_KEY", SECRET, env_file)
    assert _mode(env_file) == PRIVATE_FILE_MODE
    assert "OTHER=x" in env_file.read_text()
    assert "Permissions trop ouvertes" in caplog.text
    assert SECRET not in caplog.text


@posix_only
def test_write_tightens_the_old_inode_kept_by_a_hard_link(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("OLD_KEY=old-secret\n")
    os.chmod(env_file, GROUP_READABLE_MODE)
    hard_link = tmp_path / "elsewhere.env"
    os.link(env_file, hard_link)
    _write_env_key("OPENAI_API_KEY", SECRET, env_file)
    assert _mode(env_file) == PRIVATE_FILE_MODE
    assert (
        _mode(hard_link) == PRIVATE_FILE_MODE
    )  # l'ancien contenu n'est plus lisible par le groupe
    assert "OLD_KEY=old-secret" in hard_link.read_text()


@posix_only
def test_write_tightens_existing_open_dir(tmp_path, caplog):
    env_dir = tmp_path / "pof"
    env_dir.mkdir()
    os.chmod(env_dir, GROUP_READABLE_DIR_MODE)
    with caplog.at_level(logging.WARNING, logger=env_loader.__name__):
        _write_env_key("OPENAI_API_KEY", SECRET, env_dir / ".env")
    assert _mode(env_dir) == PRIVATE_DIR_MODE
    assert "Permissions trop ouvertes" in caplog.text


@posix_only
def test_write_through_symlink_tightens_target(tmp_path, caplog):
    external = tmp_path / "external" / "config.env"
    external.parent.mkdir()
    external.write_text("OLD_KEY=old-secret\n")
    os.chmod(external, GROUP_READABLE_MODE)
    link = tmp_path / "pof" / ".env"
    link.parent.mkdir()
    link.symlink_to(external)
    with caplog.at_level(logging.WARNING, logger=env_loader.__name__):
        _write_env_key("OPENAI_API_KEY", SECRET, link)
    assert link.is_symlink()
    assert link.resolve() == external.resolve()
    assert _mode(external) == PRIVATE_FILE_MODE
    content = external.read_text()
    assert "OLD_KEY=old-secret" in content
    assert f"OPENAI_API_KEY={SECRET}" in content
    assert "Permissions trop ouvertes" in caplog.text
    assert SECRET not in caplog.text
    assert [p.name for p in external.parent.iterdir()] == ["config.env"]


@posix_only
def test_write_refuses_dangling_symlink(tmp_path):
    link = tmp_path / ".env"
    link.symlink_to(tmp_path / "missing.env")
    with pytest.raises(FileNotFoundError):
        _write_env_key("OPENAI_API_KEY", SECRET, link)
    assert link.is_symlink()
    assert not (tmp_path / "missing.env").exists()


def test_write_is_atomic_on_error(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("MY_KEY=old\n")

    def failing_replace(*_args):
        raise OSError(errno.EIO, "simulated failure")

    monkeypatch.setattr(env_loader.os, "replace", failing_replace)
    with pytest.raises(OSError) as excinfo:
        _write_env_key("MY_KEY", SECRET, env_file)
    assert SECRET not in str(excinfo.value)
    assert env_file.read_text() == "MY_KEY=old\n"
    assert [p.name for p in tmp_path.iterdir()] == [".env"]


def test_written_keys_are_reloaded(tmp_path):
    env_file = tmp_path / "pof" / ".env"
    _write_env_key("ANTHROPIC_API_KEY", SECRET, env_file)
    _write_env_key("POF_ANTHROPIC_MODEL", "model-x", env_file)
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("POF_ANTHROPIC_MODEL", None)
        _load_env_file(env_file)
        assert os.environ["ANTHROPIC_API_KEY"] == SECRET
        assert os.environ["POF_ANTHROPIC_MODEL"] == "model-x"


def test_write_does_not_log_secret(tmp_path, caplog):
    env_file = tmp_path / ".env"
    env_file.write_text("")
    os.chmod(env_file, GROUP_READABLE_MODE)
    with caplog.at_level(logging.DEBUG):
        _write_env_key("ANTHROPIC_API_KEY", SECRET, env_file)
    assert SECRET not in caplog.text
