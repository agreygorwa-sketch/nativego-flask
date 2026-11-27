# NativeGo — Web Platform

A tourism marketplace that connects tourists with verified local providers across Kenya. Built with Python Flask and SQLite, for the Software Engineering course (Group B).

## Run it

```bash
pip install -r requirements.txt   # once
python3 app.py                    # → http://localhost:5050
```

The database is created on first start, with demo data. A `secret.key` file is created next to `app.py` — never share or upload it.

## Demo accounts

| Role | Email | Password |
| --- | --- | --- |
| Tourist | tourist@demo.co.ke | demo123 |
| Provider | david@demo.co.ke | demo123 |
| Admin | admin@nativego.co.ke | admin123 |

## Tests

```bash
python -m pytest tests/ -v
```

## Provider verification (email, then document, then admin approval)

New providers must verify their email, then upload a verification document,
before the admin can approve them. Email is sent through SMTP — set these
variables (Vercel → Settings → Environment Variables, or a local `.env`):

- `SMTP_HOST` (e.g. `smtp.resend.com` or `smtp.gmail.com`)
- `SMTP_PORT` (465 for SSL, 587 for TLS)
- `SMTP_USER` and `SMTP_PASS` (for Resend SMTP the user is `resend` and the
  password is the API key; for Gmail the password is an app password)
- `SMTP_FROM` (optional — defaults to SMTP_USER)

If SMTP is not configured, the email step is skipped and only the document
check applies, so signups never get stuck waiting for a mail that cannot go
out. Accounts created before verification existed are treated as verified.

## Notes

- Passwords are hashed, every form carries a CSRF token, and logins are rate-limited. All admin actions are written to an audit log (`/admin/activity`).
- M-Pesa payments are not built yet — the payment step is designed, but no payment code exists in this version.
