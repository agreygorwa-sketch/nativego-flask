"""Security tests — CSRF, authz boundaries, rate limiting, open redirects.

Every POST in the app is checked in ``before_request`` against the
per-session CSRF token; a missing/wrong token must give 400.
"""
import pytest

from conftest import (
    ADMIN,
    TOURIST,
    get_csrf,
    login_as_admin,
    login_as_tourist,
    post,
)


def test_csrf_post_login_without_token_is_400(client):
    resp = client.post("/login", data={
        "email": TOURIST[0], "password": TOURIST[1]},
        follow_redirects=False)
    assert resp.status_code == 400


def test_csrf_post_with_wrong_token_is_400(client):
    client.get("/login")
    resp = client.post("/login", data={
        "email": TOURIST[0], "password": TOURIST[1],
        "_csrf": "0" * 64}, follow_redirects=False)
    assert resp.status_code == 400


def test_csrf_booking_without_token_is_400(client):
    login_as_tourist(client)
    resp = client.post("/request/1", data={
        "date": "2027-01-15", "guests": "2", "notes": ""},
        follow_redirects=False)
    assert resp.status_code == 400


def test_csrf_admin_action_without_token_is_400(client):
    login_as_admin(client)
    resp = client.post("/admin/verify/5/approve", data={},
                       follow_redirects=False)
    assert resp.status_code == 400


# ------------------------------------------------------- role boundaries ---
@pytest.mark.parametrize("path", [
    "/admin", "/admin/users", "/admin/activity", "/admin/bookings",
    "/admin/reviews", "/admin/messages", "/admin/verifications",
    "/admin/providers",
])
def test_tourist_cannot_reach_admin_pages(client, path):
    login_as_tourist(client)
    assert client.get(path).status_code == 403


def test_provider_cannot_reach_admin_pages(client):
    from conftest import login_as_provider
    login_as_provider(client)
    assert client.get("/admin").status_code == 403


def test_tourist_cannot_use_provider_dashboard(client):
    login_as_tourist(client)
    assert client.get("/dashboard").status_code == 403


def test_admin_cannot_use_provider_dashboard(client):
    login_as_admin(client)
    assert client.get("/dashboard").status_code == 403


def test_anonymous_cannot_book_or_review(client):
    assert client.post("/request/1", data={"_csrf": "x"},
                       follow_redirects=False).status_code in (302, 400)
    # With a valid token but no login, the auth redirect must win over
    # any booking logic: fetch a token first, then POST anonymously.
    token = get_csrf(client, "/login")
    resp = client.post("/request/1", data={
        "date": "2027-01-15", "guests": "2", "_csrf": token},
        follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_provider_cannot_book_as_tourist(client):
    from conftest import login_as_provider
    login_as_provider(client)
    # NOTE: /provider/1 shows its forms only to tourists, so there is no
    # CSRF token on that page for a provider — fetch it from /login.
    resp = post(client, "/request/1", {
        "date": "2027-01-15", "guests": "2", "notes": ""},
        csrf_path="/login")
    assert resp.status_code == 403


def test_tourist_cannot_accept_bookings(client):
    login_as_tourist(client)
    resp = post(client, "/request/1/accept", {}, csrf_path="/provider/1")
    assert resp.status_code == 403


# --------------------------------------------------------- rate limiting ---
def test_login_rate_limit_blocks_after_five_failures(client):
    import app as app_module
    for _ in range(5):
        token = get_csrf(client, "/login")
        resp = client.post("/login", data={
            "email": TOURIST[0], "password": "wrong-every-time",
            "_csrf": token}, follow_redirects=False)
        assert resp.status_code == 200  # failed login, page re-rendered
    # 6th attempt in the same 5-minute window: 429.
    token = get_csrf(client, "/login")
    resp = client.post("/login", data={
        "email": TOURIST[0], "password": "wrong-every-time",
        "_csrf": token}, follow_redirects=False)
    assert resp.status_code == 429
    # And the block is per-IP in-memory state, not the account: clearing it
    # restores normal login (what the autouse fixture does between tests).
    app_module._login_attempts.clear()
    login_as_tourist(client)
    assert client.get("/my-requests").status_code == 200


# ------------------------------------------------------- open-redirect fix ---
def test_favorite_same_site_referer_is_followed(client):
    login_as_tourist(client)
    token = get_csrf(client, "/provider/2")
    resp = client.post("/favorite/2", data={"_csrf": token},
                       headers={"Referer": "http://localhost/discover"},
                       follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"] == "http://localhost/discover"


def test_favorite_evil_referer_never_leaves_the_site(client):
    login_as_tourist(client)
    for evil in ("https://evil.example/x",
                 "http://evil.example/phish",
                 "//evil.example/x"):
        token = get_csrf(client, "/provider/2")
        resp = client.post("/favorite/2", data={"_csrf": token},
                           headers={"Referer": evil},
                           follow_redirects=False)
        assert resp.status_code == 302
        assert "evil.example" not in resp.headers["Location"]
        assert resp.headers["Location"].endswith("/provider/2")


# -------------------------------------------------------- security headers ---
def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_login_sets_httponly_session_cookie(client):
    # The session cookie is set on the login POST response itself.
    token = get_csrf(client, "/login")
    resp = client.post("/login", data={
        "email": TOURIST[0], "password": TOURIST[1], "_csrf": token},
        follow_redirects=False)
    assert resp.status_code == 302
    cookies = resp.headers.getlist("Set-Cookie")
    session_cookies = [c for c in cookies if c.startswith("session=")]
    assert session_cookies, f"no session cookie set: {cookies}"
    assert "HttpOnly" in session_cookies[0]
    assert "SameSite=Lax" in session_cookies[0]
