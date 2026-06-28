import os
from unittest.mock import patch

from backends.mcp.env_loader import _load_env_file, _write_env_key


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
