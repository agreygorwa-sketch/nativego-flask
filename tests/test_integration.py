"""Integration tests — full request/response flows against a fresh
seeded throwaway DB per test (see conftest.py).
"""
from datetime import date, timedelta

import sqlite3

import pytest

import app as app_module
from conftest import (
    db_all,
    db_count,
    db_one,
    get_csrf,
    login_as_admin,
    login_as_provider,
    login_as_tourist,
    post,
)

PUBLIC_PAGES = [
    "/", "/discover", "/provider/1", "/login", "/signup", "/about",
    "/destinations", "/contact", "/faq", "/privacy", "/terms", "/safety",
    "/providers",
]

ADMIN_PAGES = [
    "/admin", "/admin/users", "/admin/verifications", "/admin/providers",
    "/admin/bookings", "/admin/reviews", "/admin/messages",
]

FUTURE_DATE = (date.today() + timedelta(days=30)).isoformat()
PAST_DATE = (date.today() - timedelta(days=1)).isoformat()


def _booking_count(db_path, **where):
    sql = "SELECT COUNT(*) FROM requests"
    args = []
    if where:
        sql += " WHERE " + " AND ".join(f"{k}=?" for k in where)
        args = list(where.values())
    return db_count(db_path, sql, args)


# ------------------------------------------------------- public pages / 404 ---
@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_public_pages_return_200(client, path):
    assert client.get(path).status_code == 200


def test_unknown_url_returns_404_page(client):
    resp = client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
    assert "Page not found" in resp.get_data(as_text=True)


def test_unverified_provider_page_is_404_for_public(client):
    # Provider 5 (Diani Dive School) is unverified in the seed data.
    assert client.get("/provider/5").status_code == 404


# ------------------------------------------------------------------- auth ---
def test_admin_anonymous_redirects_to_login(client):
    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_tourist_login_works_and_admin_is_forbidden(client):
    login_as_tourist(client)
    assert client.get("/my-requests").status_code == 200
    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code == 403


def test_provider_login_and_dashboard(client):
    login_as_provider(client)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Mara Savannah Safaris" in resp.get_data(as_text=True)


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_admin_pages_return_200(client, path):
    login_as_admin(client)
    assert client.get(path).status_code == 200


def test_login_wrong_password_stays_on_login_page(client):
    token = get_csrf(client, "/login")
    resp = client.post("/login", data={
        "email": "tourist@demo.co.ke", "password": "not-the-password",
        "_csrf": token}, follow_redirects=True)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Wrong email or password" in body
    # Still anonymous: a protected page must redirect to /login.
    assert client.get("/my-requests", follow_redirects=False).status_code == 302


def test_signup_validation_errors_return_400(client, db_path):
    resp = post(client, "/signup", {
        "name": "A", "email": "not-an-email", "password": "short",
        "role": "tourist"}, csrf_path="/signup")
    assert resp.status_code == 400
    assert db_count(db_path, "SELECT COUNT(*) FROM users") == 3


def test_signup_duplicate_email_returns_400(client, db_path):
    resp = post(client, "/signup", {
        "name": "Copy Cat", "email": "tourist@demo.co.ke",
        "password": "password123", "role": "tourist"}, csrf_path="/signup")
    assert resp.status_code == 400
    assert db_count(db_path, "SELECT COUNT(*) FROM users") == 3


def test_signup_success_creates_user_and_logs_in(client, db_path):
    resp = post(client, "/signup", {
        "name": "Test Tourist", "email": "new.tourist@example.com",
        "password": "password123", "role": "tourist"}, csrf_path="/signup")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT * FROM users WHERE email=?",
                 ("new.tourist@example.com",))
    assert row is not None and row["role"] == "tourist"
    assert client.get("/my-requests").status_code == 200


# ------------------------------------------------------------- admin audit ---
def test_admin_activity_page_and_action_filter(client):
    login_as_admin(client)
    resp = client.get("/admin/activity")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Tourist account created" in body  # seeded signup entry

    filtered = client.get("/admin/activity?action=signup")
    assert filtered.status_code == 200
    fbody = filtered.get_data(as_text=True)
    assert "Tourist account created" in fbody
    # NOTE: the action <select> still lists every action as an option, so
    # assert on the seeded row's detail text, not the action slug.
    assert "Accepted booking #3" not in fbody
    assert "Reviewed Mara Savannah Safaris" not in fbody


def test_admin_activity_search_and_pagination(client):
    login_as_admin(client)
    resp = client.get("/admin/activity?q=Wanjiku")
    assert resp.status_code == 200
    assert "Wanjiku Tourist" in resp.get_data(as_text=True)
    assert client.get("/admin/activity?page=1").status_code == 200
    assert client.get("/admin/activity?page=99").status_code == 200


def test_admin_verify_approve_makes_provider_verified(client, db_path):
    login_as_admin(client)
    assert db_one(db_path, "SELECT verified FROM providers WHERE id=5")[0] == 0
    _add_doc(db_path, 5)
    resp = post(client, "/admin/verify/5/approve", {},
                csrf_path="/admin/verifications")
    assert resp.status_code == 302
    assert db_one(db_path, "SELECT verified FROM providers WHERE id=5")[0] == 1
    assert client.get("/provider/5").status_code == 200


def _add_doc(db_path, pid):
    """Insert one verification document row for a provider (test helper)."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO verification_docs(provider_id,doc_type,filename,original_name,uploaded_at)"
        " VALUES(?,?,?,?,?)",
        (pid, "National ID", "test_id.pdf", "test_id.pdf", "2026-11-27 10:00"))
    conn.commit()
    conn.close()


def test_admin_verify_blocked_without_document(client, db_path):
    login_as_admin(client)
    resp = post(client, "/admin/verify/5/approve", {},
                csrf_path="/admin/verifications")
    assert resp.status_code == 302
    assert db_one(db_path, "SELECT verified FROM providers WHERE id=5")[0] == 0
    body = client.get("/admin/verifications").get_data(as_text=True)
    assert "no verification document" in body


PROVIDER_SIGNUP = {
    "name": "Test Provider", "email": "verify.provider@example.com",
    "password": "password123", "role": "provider",
    "business": "Verify Tours", "category": "City Tour",
    "location": "Nairobi", "description": "Test tours for verification.",
    "phone": "+254700000000", "price": "5000",
}


def test_provider_signup_sets_email_token(client, db_path):
    resp = post(client, "/signup", PROVIDER_SIGNUP, csrf_path="/signup")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT * FROM users WHERE email=?",
                 ("verify.provider@example.com",))
    assert row is not None and row["role"] == "provider"
    assert row["email_verified"] == 0
    assert row["email_token"]
    prov = db_one(db_path, "SELECT * FROM providers WHERE user_id=?", (row["id"],))
    assert prov is not None and prov["verified"] == 0


def test_provider_email_verification_flow(client, db_path, monkeypatch):
    """Email verification, then document, then admin approval — in that order."""
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "user@example.com")
    monkeypatch.setenv("SMTP_PASS", "secret")
    monkeypatch.setattr(app_module, "_send_email", lambda *a, **k: True)
    resp = post(client, "/signup", PROVIDER_SIGNUP, csrf_path="/signup")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT * FROM users WHERE email=?",
                 ("verify.provider@example.com",))
    token = row["email_token"]
    assert token
    prov = db_one(db_path, "SELECT id FROM providers WHERE user_id=?", (row["id"],))
    _add_doc(db_path, prov["id"])
    # Admin cannot approve before the email is verified, even with a document.
    login_as_admin(client)
    post(client, f"/admin/verify/{prov['id']}/approve", {},
         csrf_path="/admin/verifications")
    assert db_one(db_path, "SELECT verified FROM providers WHERE id=?",
                  (prov["id"],))[0] == 0
    body = client.get("/admin/verifications").get_data(as_text=True)
    assert "not verified their email" in body
    # Verify the email via the link, then approval works.
    resp = client.get(f"/verify-email/{token}")
    assert resp.status_code == 302
    assert db_one(db_path, "SELECT email_verified FROM users WHERE email=?",
                  ("verify.provider@example.com",))[0] == 1
    post(client, f"/admin/verify/{prov['id']}/approve", {},
         csrf_path="/admin/verifications")
    assert db_one(db_path, "SELECT verified FROM providers WHERE id=?",
                  (prov["id"],))[0] == 1


# ----------------------------------------------------------------- booking ---
def _book(client, db_path, pid=1, when=FUTURE_DATE, guests=2, notes="Test trip"):
    resp = post(client, f"/request/{pid}", {
        "date": when, "guests": str(guests), "notes": notes},
        csrf_path="/provider/1")
    return resp


def test_booking_valid_date_creates_pending_request(client, db_path):
    login_as_tourist(client)
    before = _booking_count(db_path)
    resp = _book(client, db_path)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/my-requests")
    assert _booking_count(db_path) == before + 1
    row = db_one(db_path,
                 "SELECT * FROM requests ORDER BY id DESC LIMIT 1")
    assert row["status"] == "pending"
    assert row["provider_id"] == 1 and row["tourist_id"] == 1
    assert row["date"] == FUTURE_DATE and row["guests"] == 2


def test_booking_impossible_date_rejected(client, db_path):
    login_as_tourist(client)
    before = _booking_count(db_path)
    resp = _book(client, db_path, when="2026-02-30")
    assert resp.status_code == 302  # redirected back with a flash
    assert _booking_count(db_path) == before
    assert "valid date" in client.get("/provider/1").get_data(as_text=True)


def test_booking_past_date_rejected(client, db_path):
    login_as_tourist(client)
    before = _booking_count(db_path)
    resp = _book(client, db_path, when=PAST_DATE)
    assert resp.status_code == 302
    assert _booking_count(db_path) == before


@pytest.mark.parametrize("guests", ["0", "51", "-3", "abc"])
def test_booking_bad_guest_count_rejected(client, db_path, guests):
    login_as_tourist(client)
    before = _booking_count(db_path)
    resp = _book(client, db_path, guests=guests)
    assert resp.status_code == 302
    assert _booking_count(db_path) == before


def test_booking_unverified_provider_is_404(client, db_path):
    login_as_tourist(client)
    before = _booking_count(db_path)
    resp = _book(client, db_path, pid=5)  # Diani Dive School, unverified
    assert resp.status_code == 404
    assert _booking_count(db_path) == before


def test_provider_accept_then_complete_booking(client, db_path):
    # Tourist books provider 1 (owned by david@demo.co.ke).
    login_as_tourist(client)
    assert _book(client, db_path).status_code == 302
    rid = db_one(db_path,
                 "SELECT id FROM requests WHERE provider_id=1 "
                 "AND status='pending' ORDER BY id DESC LIMIT 1")["id"]

    # Provider accepts, then completes.
    c2 = client.application.test_client()
    login_as_provider(c2)
    assert post(c2, f"/request/{rid}/accept", {},
                csrf_path="/dashboard").status_code == 302
    assert db_one(db_path, "SELECT status FROM requests WHERE id=?",
                  (rid,))[0] == "accepted"
    assert post(c2, f"/request/{rid}/complete", {},
                csrf_path="/dashboard").status_code == 302
    assert db_one(db_path, "SELECT status FROM requests WHERE id=?",
                  (rid,))[0] == "completed"


# ------------------------------------------------------------------ review ---
def test_review_post_creates_review(client, db_path):
    login_as_tourist(client)
    before = db_count(db_path, "SELECT COUNT(*) FROM reviews")
    resp = post(client, "/review/1", {
        "rating": "5", "comment": "Wonderful safari, highly recommended!"},
        csrf_path="/provider/1")
    assert resp.status_code == 302
    assert db_count(db_path, "SELECT COUNT(*) FROM reviews") == before + 1
    row = db_one(db_path, "SELECT * FROM reviews ORDER BY id DESC LIMIT 1")
    assert row["rating"] == 5 and row["tourist_id"] == 1
    assert "Wonderful safari" in row["comment"]


def test_review_bad_rating_rejected(client, db_path):
    login_as_tourist(client)
    before = db_count(db_path, "SELECT COUNT(*) FROM reviews")
    resp = post(client, "/review/1", {"rating": "9", "comment": "Too high"},
                csrf_path="/provider/1")
    assert resp.status_code == 302
    assert db_count(db_path, "SELECT COUNT(*) FROM reviews") == before


# ---------------------------------------------------------------- favorite ---
def test_favorite_toggle_adds_and_removes(client, db_path):
    login_as_tourist(client)
    # Seeded: tourist already favorites provider 1, not provider 2.
    assert db_one(db_path, "SELECT 1 FROM favorites WHERE user_id=1 "
                            "AND provider_id=1") is not None
    post(client, "/favorite/1", {}, csrf_path="/provider/1")
    assert db_one(db_path, "SELECT 1 FROM favorites WHERE user_id=1 "
                            "AND provider_id=1") is None
    post(client, "/favorite/1", {}, csrf_path="/provider/1")
    assert db_one(db_path, "SELECT 1 FROM favorites WHERE user_id=1 "
                            "AND provider_id=1") is not None


def test_favorite_evil_referer_redirects_to_provider_page(client):
    login_as_tourist(client)
    token = get_csrf(client, "/provider/2")
    resp = client.post("/favorite/2", data={"_csrf": token},
                       headers={"Referer": "https://evil.example/x"},
                       follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert "evil.example" not in loc
    assert loc.endswith("/provider/2")


# ------------------------------------------------------------------ search ---
def test_discover_search_finds_mara(client):
    resp = client.get("/discover?q=Mara")
    assert resp.status_code == 200
    assert "Mara Savannah Safaris" in resp.get_data(as_text=True)


def test_discover_search_no_match(client):
    resp = client.get("/discover?q=ZanzibarNoSuchPlace")
    assert resp.status_code == 200
    assert "Mara Savannah Safaris" not in resp.get_data(as_text=True)


# ----------------------------------------------------------------- contact ---
def test_contact_bad_email_returns_400(client, db_path):
    resp = post(client, "/contact", {
        "name": "Tester", "email": "not-an-email", "subject": "General",
        "message": "This message is long enough to pass."},
        csrf_path="/contact")
    assert resp.status_code == 400
    assert db_count(db_path, "SELECT COUNT(*) FROM messages") == 0


def test_contact_valid_message_saved(client, db_path):
    resp = post(client, "/contact", {
        "name": "Tester", "email": "tester@example.com", "subject": "General",
        "message": "This message is long enough to pass."},
        csrf_path="/contact")
    assert resp.status_code == 302
    assert db_count(db_path, "SELECT COUNT(*) FROM messages") == 1
