import os
import subprocess
import sys
from pathlib import Path

import pytest

from secwatch import db, i18n
from secwatch.config import Settings

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def russian():
    """Most tests assert the Russian texts; English is covered in test_i18n.py."""
    previous = i18n.get_language()
    i18n.set_language("ru")
    yield
    i18n.set_language(previous)


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "host"
    subprocess.run([sys.executable, str(ROOT / "tools" / "gen_samples.py"), str(root)], check=True,
                   capture_output=True)
    return root


@pytest.fixture
def settings(tmp_path, host, monkeypatch):
    for k in list(os.environ):
        if k.startswith("SECWATCH_"):
            monkeypatch.delenv(k)
    s = Settings(host_root=str(host), db_path=str(tmp_path / "data" / "secwatch.db"), timezone="UTC")
    s.web_password = "test-password"
    s.spike_threshold = 30
    db.init_db(s.db_path)
    return s
