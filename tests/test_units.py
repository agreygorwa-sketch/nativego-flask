"""Unit tests — pure helpers and password handling, no HTTP.

Covers: clean(), valid_email(), booking_value(), provider_avg(),
password hashing round-trip, migrate_passwords().
"""
import sqlite3

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

import app as app_module
from app import app, booking_value, clean, migrate_passwords, provider_avg, valid_email


# ---------------------------------------------------------------- clean() ---
@pytest.mark.parametrize("raw,expected", [
    ("  hello  ", "hello"),
    ("no-space", "no-space"),
    ("", ""),
    (None, ""),
    ("   ", ""),
    ("\n\t padded \n", "padded"),
])
def test_clean_strips_whitespace(raw, expected):
    assert clean(raw) == expected


def test_clean_truncates_to_max_len():
    assert clean("x" * 600) == "x" * 500
    assert clean("y" * 600, max_len=10) == "y" * 10
    assert clean("short", max_len=10) == "short"


# ----------------------------------------------------------- valid_email() ---
@pytest.mark.parametrize("email", [
    "tourist@demo.co.ke",
    "first.last+tag@example.com",
    "a@b.co",
    "  spaced@example.org  ",
])
def test_valid_email_accepts_good_addresses(email):
    assert valid_email(email) is True


@pytest.mark.parametrize("email", [
    "not-an-email",
    "a@b",            # no TLD
    "a@b.c",          # TLD too short (< 2 chars)
    "@example.com",   # no local part
    "plain@",
    "a b@example.com",
    "",
    None,
    "x" * 115 + "@example.com",  # over the 120-char cap
])
def test_valid_email_rejects_bad_addresses(email):
    assert valid_email(email) is False


# --------------------------------------------------------- booking_value() ---
@pytest.mark.parametrize("price,guests,expected", [
    (8500, 2, 17000),
    (8500, 1, 8500),
    (6000, 6, 36000),
    (8500, None, 8500),   # missing guest count counts as 1
    (None, 3, 0),         # missing price -> 0
    (0, 5, 0),
    (None, None, 0),
])
def test_booking_value(price, guests, expected):
    assert booking_value(price, guests) == expected


# ---------------------------------------------------------- provider_avg() ---
def test_provider_avg_with_reviews(db_path):
    # Seeded: provider 1 has two 5-star reviews; provider 2 has one 4-star.
    with app.app_context():
        assert provider_avg(1) == (5.0, 2)
        assert provider_avg(2) == (4.0, 1)


def test_provider_avg_no_reviews(db_path):
    # Provider 3 (Mt Kenya Treks) has no seeded reviews.
    with app.app_context():
        assert provider_avg(3) == (None, 0)


# --------------------------------------------------- password hashing (pbkdf2) ---
def test_password_hash_round_trip():
    pw = "s3cret-password!"
    hashed = generate_password_hash(pw, method="pbkdf2")
    assert hashed != pw
    assert hashed.startswith("pbkdf2:")
    assert check_password_hash(hashed, pw) is True
    assert check_password_hash(hashed, "wrong-password") is False


def test_seeded_users_have_pbkdf2_hashes(db_path):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT email, password FROM users").fetchall()
    finally:
        conn.close()
    assert len(rows) == 3
    for email, pw in rows:
        assert pw.startswith("pbkdf2:"), f"{email} password is not a pbkdf2 hash"
    assert check_password_hash(
        dict(rows)["tourist@demo.co.ke"], "demo123") is True


def test_migrate_passwords_hashes_plaintext_row(db_path):
    # Plant a legacy plaintext password, run the migration, verify it is
    # now a pbkdf2 hash that still verifies — and that hashed rows are
    # left untouched.
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO users(name,email,password,role,active,created_at)"
        " VALUES('Legacy User','legacy@example.com','plaintext-pw','tourist',1,"
        " '2026-01-01 00:00')")
    conn.commit()
    before = conn.execute(
        "SELECT password FROM users WHERE email='tourist@demo.co.ke'"
    ).fetchone()[0]
    conn.close()

    migrate_passwords()

    conn = sqlite3.connect(db_path)
    try:
        legacy = conn.execute(
            "SELECT password FROM users WHERE email='legacy@example.com'"
        ).fetchone()[0]
        after = conn.execute(
            "SELECT password FROM users WHERE email='tourist@demo.co.ke'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert legacy.startswith("pbkdf2:")
    assert check_password_hash(legacy, "plaintext-pw") is True
    assert after == before, "migrate_passwords must not re-hash hashed rows"


def test_migrate_passwords_noop_when_nothing_plaintext(db_path):
    # Second run on an already-hashed DB changes nothing.
    migrate_passwords()
    migrate_passwords()
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT password FROM users").fetchall()
    finally:
        conn.close()
    assert all(pw.startswith("pbkdf2:") for (pw,) in rows)
