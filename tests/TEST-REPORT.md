# NativeGo — Test Report (Deliverable 4)

## How to run

```bash
cd /home/hatch/workspace/nativego-flask-v2
/tmp/nativego-venv/bin/python -m pytest tests/ -q
```

No system-wide install: the venv at `/tmp/nativego-venv` already has
Flask 3.1.3, gunicorn 26.2.0 and pytest 9.2.0. A single test file can be
run with e.g. `pytest tests/test_units.py -q`. The suite takes ~2 minutes,
mostly the cost of pbkdf2 password checks on every login.

## Results

| | |
|---|---|
| Total tests | **107** |
| Passed | **107** |
| Failed | **0** |
| Real app bugs found | **None** |

Verified 2026-11-05: full suite green from a clean state
(`107 passed in 117.62s`).

## How the suite is set up

- `tests/conftest.py` — fixtures and helpers. Every test runs against a
  **fresh throwaway SQLite DB** (`tmp_path/test.db`): the fixture points
  the module-level `app.DB` at that file and calls `init_db()` there, then
  restores the real path. The real `nativego.db` is never written to —
  verified after the run: SHA-256 unchanged
  (`b8d4ae0b…f1327f8`) and row counts unchanged
  (users 3, providers 8, requests 6, reviews 4, favorites 2,
  activity_log 6, messages 0).
- Importing `app` runs `init_db()` / `migrate_passwords()` at import time
  (the D4 deployment fix: under gunicorn the module is imported, never run
  as `__main__`). Against the existing real DB that is a no-op.
- `tests/conftest.py` also provides `get_csrf()` (every POST needs the
  per-session `_csrf` token, fetched from a rendered page), `post()`,
  `login_as_tourist / _provider / _admin`, and direct SQLite helpers.
  The in-memory login rate limiter (`app._login_attempts`, 5 fails / IP /
  5 min) is cleared before every test, so failed-login tests can't poison
  later ones.

## What each group proves

### `test_units.py` (33 tests) — pure helpers, no HTTP
- `clean()`: strips whitespace, truncates to `max_len`, `None` → `""`.
- `valid_email()`: accepts normal addresses, rejects missing `@`/TLD,
  1-char TLD, spaces, empty/`None`, and >120-char addresses.
- `booking_value()`: `price × guests`, with `None` price → 0 and
  `None` guests → 1.
- `provider_avg()`: seeded data — provider 1 → `(5.0, 2)`, provider 2 →
  `(4.0, 1)`, provider 3 (no reviews) → `(None, 0)`.
- Passwords: pbkdf2 hash round-trip (correct verifies, wrong doesn't,
  hash ≠ plaintext); all 3 seeded users hold pbkdf2 hashes;
  `migrate_passwords()` hashes a planted plaintext row (still verifies
  afterwards) and leaves already-hashed rows untouched / is a no-op on
  repeat runs.

### `test_integration.py` (49 tests) — request/response flows
- All 13 public pages return 200 (`/`, `/discover`, `/provider/1`,
  `/login`, `/signup`, `/about`, `/destinations`, `/contact`, `/faq`,
  `/privacy`, `/terms`, `/safety`, `/providers`); unknown URL → 404
  page containing "Page not found"; unverified provider page → 404.
- Auth: anonymous `/admin` → 302 to `/login`; tourist login works and
  tourist `GET /admin` → 403; provider login → `/dashboard` 200;
  admin login → all 7 admin pages 200 (`/admin`, `/admin/users`,
  `/admin/verifications`, `/admin/providers`, `/admin/bookings`,
  `/admin/reviews`, `/admin/messages`).
- Audit log: `/admin/activity` 200, `?action=signup` filter shows only
  signup rows, `?q=Wanjiku` search works, `?page=` pagination clamps
  (page 99 → 200).
- Bookings: valid future date → `requests` row with status `pending`;
  impossible date `2026-02-30`, past date, and guests 0 / 51 / -3 /
  non-numeric → rejected with no row; booking unverified provider 5 →
  404 with no row; provider accepts then completes a booking
  (pending → accepted → completed).
- Reviews: valid POST creates a review; rating 9 rejected.
- Favorites: toggle adds/removes; evil `Referer: https://evil.example/x`
  redirects to the provider page, never off-site.
- Search: `/discover?q=Mara` finds Mara Savannah Safaris; a nonsense
  query finds nothing.
- Signup: validation errors → 400 with no user created; duplicate email
  → 400; valid signup creates the user and logs them in.
- Contact: bad email → 400 with no message saved; valid message → 302
  and one row saved.
- Wrong-password login stays on the login page with the error flash and
  the user stays anonymous.

### `test_security.py` (23 tests) — CSRF, authorization, rate limiting
- CSRF: POST `/login` with no token → 400, with a wrong token → 400,
  booking and admin-verify POSTs without a token → 400.
- Role boundaries: tourist (and provider) get 403 on every admin page;
  tourist and admin get 403 on `/dashboard`; a provider cannot book
  (403); a tourist cannot accept bookings (403); anonymous booking
  POSTs redirect to `/login`.
- Rate limiting: 5 failed logins → the 6th returns 429; clearing the
  in-memory attempts restores normal login.
- Open-redirect fix: a same-site `Referer` is followed; three evil
  referers (`https://evil.example/x`, `http://evil.example/phish`,
  `//evil.example/x`) all redirect back to the provider page.
- Headers/cookies: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy` present; the session
  cookie is `HttpOnly` + `SameSite=Lax`.

### `test_deployment.py` (2 tests) — the gunicorn import path
Both run against a throwaway **copy** of the app directory (no DB, no
secrets copied in), so the real app folder is untouched:
- `test_import_creates_database`: `python -c "import app"` in a fresh
  copy creates and seeds `nativego.db` (3 users, 8 providers,
  6 requests) — proving the import-time `init_db()` fix.
- `test_gunicorn_serves_homepage`: `gunicorn app:app --workers 1`
  (the Procfile/`render.yaml` setting — one worker is correct for
  SQLite and avoids a first-start seed race) serves `/` with HTTP 200
  and a seeded DB, without ever running `python3 app.py`.

## Real app bugs found

**None.** Two failures appeared during development and both turned out
to be test-side mistakes, fixed in the tests (not in `app.py`):
1. The `?action=signup` activity test asserted the slug
   `booking_accepted` was absent from the filtered page — but the filter
   `<select>` legitimately lists every action as an option. The test
   now asserts on row detail text instead.
2. The provider-cannot-book test fetched its CSRF token from
   `/provider/1`, but that page only renders forms for tourists, so a
   logged-in provider sees no token there. The test now fetches the
   token from `/login`.

`app.py` was not modified at any point during this work.
