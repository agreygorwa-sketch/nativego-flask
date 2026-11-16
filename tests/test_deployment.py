"""Deployment tests — the gunicorn import path (D4 fix).

Under gunicorn on Render the module is imported, never run as ``__main__``,
so init_db() / migrate_passwords() now run at import time. These tests prove
that path works end-to-end using a throwaway COPY of the app directory
(the real app folder and its real nativego.db are never touched):

1. ``test_import_creates_database`` — ``python -c "import app"`` in a fresh
   copy with no database file creates and seeds nativego.db.
2. ``test_gunicorn_serves_homepage`` — ``gunicorn app:app --workers 1``
   (the Procfile/render.yaml setting: one worker for SQLite) serves the
   home page with HTTP 200 from a fresh copy.
"""
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

import pytest

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PY = "/tmp/nativego-venv/bin/python"

IGNORE = ("nativego.db", "secret.key", "__pycache__", "tests", ".git")


def _fresh_app_copy(tmp_path):
    """Copy the app (code + templates + static) without its DB/secrets."""
    dest = tmp_path / "appcopy"
    shutil.copytree(
        APP_DIR, dest,
        ignore=shutil.ignore_patterns(*IGNORE, "*.pyc"))
    assert not (dest / "nativego.db").exists()
    return dest


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_http(port, timeout=30):
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=2) as r:
                return r.status, r.read()
        except Exception as exc:  # server not up yet
            last_exc = exc
            time.sleep(0.5)
    raise AssertionError(f"server did not answer within {timeout}s: {last_exc}")


def _env():
    env = dict(os.environ)
    env["NATIVEGO_SECRET"] = "test-only-secret-for-gunicorn-check"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def test_import_creates_database(tmp_path):
    """Importing the app module (the gunicorn path) creates + seeds the DB."""
    dest = _fresh_app_copy(tmp_path)
    proc = subprocess.run(
        [VENV_PY, "-c", "import app; print('imported ok')"],
        cwd=dest, env=_env(), capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "imported ok" in proc.stdout
    db = dest / "nativego.db"
    assert db.exists(), "import did not create nativego.db"
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM providers").fetchone()[0] == 8
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 6
    finally:
        conn.close()


def test_gunicorn_serves_homepage(tmp_path):
    """gunicorn app:app --workers 1 serves / with 200 from a fresh copy."""
    dest = _fresh_app_copy(tmp_path)
    port = _free_port()
    proc = subprocess.Popen(
        [VENV_PY, "-m", "gunicorn", "app:app",
         "--bind", f"127.0.0.1:{port}", "--workers", "1", "--timeout", "30"],
        cwd=dest, env=_env(),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        status, body = _wait_for_http(port, timeout=30)
        assert status == 200
        assert b"NativeGo" in body
        # The import-time init must have seeded the copy's DB too.
        conn = sqlite3.connect(dest / "nativego.db")
        try:
            assert conn.execute(
                "SELECT COUNT(*) FROM providers WHERE verified=1"
            ).fetchone()[0] == 6
        finally:
            conn.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
