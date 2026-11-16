"""Shared fixtures for the NativeGo test suite.

IMPORTANT: importing ``app`` runs init_db() / migrate_passwords() at import
time (deployment fix: under gunicorn the module is imported, never run as
``__main__``). Against the real ``nativego.db`` that is a no-op — the file
already exists and is fully seeded — but every test below still runs
against a FRESH throwaway database: the ``db_path`` fixture points the
module-level ``app.DB`` at a tmp file and re-runs ``init_db()`` there, so
the real database is never written to by the suite.
"""
import os
import re
import sqlite3
import sys

import pytest

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import app as app_module  # noqa: E402  (import runs import-time init_db)
from app import app  # noqa: E402

REAL_DB = app_module.DB

CSRF_RE = re.compile(r'name="_csrf" value="([0-9a-f]+)"')

TOURIST = ("tourist@demo.co.ke", "demo123")
PROVIDER = ("david@demo.co.ke", "demo123")  # owns provider id 1
ADMIN = ("admin@nativego.co.ke", "admin123")


@pytest.fixture()
def db_path(tmp_path):
    """Fresh seeded throwaway DB; restores the real DB path afterwards."""
    path = str(tmp_path / "test.db")
    old = app_module.DB
    app_module.DB = path
    app_module.init_db()
    yield path
    app_module.DB = old


@pytest.fixture(autouse=True)
def reset_login_attempts():
    """Login rate limiting is in-memory (5 fails / IP / 5 min); the test
    client always comes from 127.0.0.1, so clear it before every test."""
    app_module._login_attempts.clear()
    yield
    app_module._login_attempts.clear()


@pytest.fixture()
def client(db_path):
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ------------------------------------------------------------ DB helpers ---
def db_one(db_path, sql, args=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, args).fetchone()
    finally:
        conn.close()


def db_count(db_path, sql, args=()):
    row = db_one(db_path, sql, args)
    return row[0] if row else 0


def db_all(db_path, sql, args=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------- HTTP helpers ---
def get_csrf(client, path="/login"):
    """GET a page and pull the per-session CSRF token out of its form."""
    resp = client.get(path)
    assert resp.status_code == 200, f"GET {path} -> {resp.status_code}"
    m = CSRF_RE.search(resp.get_data(as_text=True))
    assert m, f"no CSRF token found on {path}"
    return m.group(1)


def post(client, path, data=None, csrf_path="/login"):
    """POST with a valid CSRF token (fetched fresh — login rotates it)."""
    data = dict(data or {})
    data.setdefault("_csrf", get_csrf(client, csrf_path))
    return client.post(path, data=data, follow_redirects=False)


def login(client, email, password):
    resp = post(client, "/login", {"email": email, "password": password})
    assert resp.status_code == 302, (
        f"login as {email} -> {resp.status_code}: "
        f"{resp.get_data(as_text=True)[:300]}")
    return resp


def login_as_tourist(client):
    return login(client, *TOURIST)


def login_as_provider(client):
    return login(client, *PROVIDER)


def login_as_admin(client):
    return login(client, *ADMIN)
