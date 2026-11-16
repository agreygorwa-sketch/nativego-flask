# NativeGo — Web Platform

A tourism marketplace that connects tourists with verified local providers
across Kenya. Built with Python Flask and SQLite for the Software Engineering
course (Group B) — Deliverable 4: final implementation and testing.

## Run it locally

```bash
cd nativego-flask-v2
pip install -r requirements.txt   # once (Flask + gunicorn)
python3 app.py                    # → http://localhost:5050
```

The database (`nativego.db`) is created automatically on first start and seeded
with demo data. A `secret.key` file is created next to `app.py` on first run so
logins survive restarts — never share or upload it (it is gitignored).

On the demo MacBook the app lives at `~/nativego-flask-v2`. Restart it with
`cd ~/nativego-flask-v2 && python3 app.py`. Stop it with
`lsof -nP -iTCP:5050 -sTCP:LISTEN -t | xargs kill`.

## Demo accounts

| Role     | Email                    | Password |
| -------- | ------------------------ | -------- |
| Tourist  | tourist@demo.co.ke       | demo123  |
| Provider | david@demo.co.ke         | demo123  |
| Admin    | admin@nativego.co.ke     | admin123 |

## Deploy on Render (free plan)

1. Push this folder to a GitHub repository (e.g. `nativego-flask`).
2. In Render, create a **New Web Service** from that repository.
   `render.yaml` in this folder does the rest: Python 3.11, `pip install -r
   requirements.txt`, then `gunicorn app:app --bind 0.0.0.0:$PORT
   --workers 1 --timeout 60`. Render generates `NATIVEGO_SECRET` for you.
3. The free plan sleeps after inactivity — the first visit after a pause is
   slow (about a minute), then it is fast.

## Tests

```bash
python -m pytest tests/ -v
```

Unit + integration tests run against a throwaway test database, never the real
`nativego.db`. See `tests/TEST-REPORT.md` for the results.

## Project layout

```
app.py            Flask app: routes, auth, validation, CSRF, audit logging
templates/        30 Jinja templates (28 pages + base and admin layouts)
static/style.css  Site styling
nativego.db       SQLite database (created on first run, gitignored)
requirements.txt  Flask, gunicorn
Procfile          gunicorn start command (Render/Heroku style)
render.yaml       Render free-plan service definition
tests/            pytest suite + test report
```

## Security notes

- Passwords are hashed with pbkdf2 (Werkzeug). Old plaintext passwords are
  migrated to hashes on start.
- Every POST carries a per-session CSRF token; posts without one are rejected.
- Logins are rate-limited (5 failed attempts per IP per 5 minutes).
- Roles are enforced server-side (`tourist`, `provider`, `admin`); a logged-in
  user opening a page outside their role gets a 403 page.
- All database queries use parameterised statements. Sessions are HttpOnly,
  SameSite=Lax, 2-hour lifetime.
- All admin actions and bookings are written to the `activity_log` table and
  listed at `/admin/activity`.

## What is not built yet

M-Pesa payments are **prospective** — the payment step is designed (a provider
can be paid, a record can be stored) but no payment code exists in this
version. Prices are shown per day in KES; the 10% platform figure on the
admin overview is a reporting number only.
