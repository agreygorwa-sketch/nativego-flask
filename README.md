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

## Notes

- Passwords are hashed, every form carries a CSRF token, and logins are rate-limited. All admin actions are written to an audit log (`/admin/activity`).
- M-Pesa payments are not built yet — the payment step is designed, but no payment code exists in this version.
