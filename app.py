"""NativeGo v2 — local tourism platform connecting tourists with verified
local providers across Kenya. Secure Flask rebuild.

Run:  NATIVEGO_SECRET=<long-random> python3 app.py   →  http://localhost:5050
Demo logins: tourist@demo.co.ke / demo123 · david@demo.co.ke / demo123
             admin@nativego.co.ke / admin123
"""
import hmac
import json
import os
import re
import secrets
import urllib.request
import sqlite3
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------- config ---
app = Flask(__name__)

_secret = os.environ.get("NATIVEGO_SECRET")
if _secret:
    app.secret_key = _secret
else:
    # Local demo: keep the key in a small file next to app.py so logins
    # survive restarts. The file is never committed or packed (see .gitignore);
    # on Render the NATIVEGO_SECRET env var is used instead.
    _here = os.path.dirname(os.path.abspath(__file__))
    _secret_file = os.path.join(_here, "secret.key")
    try:
        with open(_secret_file) as _fh:
            _secret = _fh.read().strip()
    except OSError:
        _secret = ""
    if not _secret:
        _secret = secrets.token_hex(32)
        try:
            with open(_secret_file, "w") as _fh:
                _fh.write(_secret)
            os.chmod(_secret_file, 0o600)
        except OSError:
            pass
        print("Generated a local secret key (secret.key) so sessions survive restarts.")
    app.secret_key = _secret

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # verification-document uploads (FR-11)
)

BASE = os.path.dirname(os.path.abspath(__file__))
# On Vercel the app directory is read-only, so the database and uploads move
# to /tmp via NATIVEGO_DB / NATIVEGO_UPLOADS. Locally the defaults below keep
# the files next to app.py, exactly as before.
DB = os.environ.get("NATIVEGO_DB", os.path.join(BASE, "nativego.db"))

# Provider verification documents (FR-11) live on disk, never in the DB.
UPLOAD_DIR = os.environ.get("NATIVEGO_UPLOADS",
                            os.path.join(BASE, "uploads", "verifications"))
ALLOWED_DOC_EXTS = {"pdf", "jpg", "jpeg", "png"}
DOC_TYPES = ["National ID", "Passport", "Certificate", "Licence"]
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ------------------------------------------------------------- db helpers ---
# Database backend: Postgres on Neon when DATABASE_URL is set (Vercel), the
# local SQLite file otherwise. The wrapper below gives both backends one
# interface, so the 120 db.execute() calls in the app do not change: "?"
# placeholders are translated to "%s" on Postgres, and rows support both
# row["col"] and row[0], like sqlite3.Row.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
# Backend by URL scheme: postgres:// or postgresql:// -> Neon Postgres,
# mysql:// -> XAMPP/MySQL, anything else (or unset) -> local SQLite file.
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
USE_MYSQL = DATABASE_URL.startswith("mysql://")
USE_SQL = USE_PG or USE_MYSQL

class Row(tuple):
    """A result row supporting both row['col'] and row[0]."""
    def __new__(cls, cols, vals):
        self = super().__new__(cls, vals)
        self._cols = list(cols)
        return self
    def __getitem__(self, key):
        if isinstance(key, str):
            return super().__getitem__(self._cols.index(key))
        return super().__getitem__(key)
    def keys(self):
        return list(self._cols)

class _Cursor:
    """Wraps a DB-API cursor; translates ? to %s on Postgres/MySQL and returns Row."""
    def __init__(self, cur, pg, mysql=False):
        self._cur = cur
        self._pg = pg
        self._mysql = mysql
    def execute(self, sql, params=()):
        if self._pg or self._mysql:
            sql = sql.replace("?", "%s")
        if self._mysql:
            # MySQL has no NULLS FIRST/LAST syntax; for DESC it already puts
            # NULLs last (NULL is the smallest value), so just drop the words.
            sql = sql.replace(" NULLS LAST", "").replace(" NULLS FIRST", "")
            # `read` is a reserved word in MySQL; quote it when used as a
            # column (the messages table), outside string literals.
            import re as _re
            _parts = sql.split("'")
            for _i in range(0, len(_parts), 2):
                # only quote a bare `read`, not one already backticked
                _parts[_i] = _re.sub(r"(?<!`)\bread\b(?!`)", "`read`", _parts[_i])
            sql = "'".join(_parts)
        self._cur.execute(sql, params or ())
        return self
    def __iter__(self):
        # sqlite3 cursors are iterable; several call sites do
        # "[r[0] for r in db.execute(...)]", so the wrapper must be too.
        return iter(self.fetchall())
    @property
    def lastrowid(self):
        # Postgres has no lastrowid; the one call site that needs the new id
        # uses RETURNING id instead (see signup).
        if self._pg:
            return None
        return self._cur.lastrowid
    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self._cur.description]
        return Row(cols, row)
    def fetchall(self):
        rows = self._cur.fetchall()
        if not rows:
            return []
        cols = [d[0] for d in self._cur.description]
        return [Row(cols, r) for r in rows]

class _Connection:
    """Wraps a DB-API connection (sqlite3, psycopg2 or PyMySQL) with one interface."""
    def __init__(self, pg, mysql=False):
        self._pg = pg
        self._mysql = mysql
        if pg:
            import psycopg2
            self._conn = psycopg2.connect(DATABASE_URL)
        elif mysql:
            import pymysql
            from urllib.parse import urlparse
            u = urlparse(DATABASE_URL)
            self._conn = pymysql.connect(
                host=u.hostname or "127.0.0.1", port=u.port or 3306,
                user=u.username or "root", password=u.password or "",
                database=(u.path or "/nativego").lstrip("/"),
                charset="utf8mb4", autocommit=False)
        else:
            self._conn = sqlite3.connect(DB)
    def execute(self, sql, params=()):
        cur = self._conn.cursor()
        return _Cursor(cur, self._pg, self._mysql).execute(sql, params)
    def executescript(self, script):
        for stmt in script.split(";"):
            stmt = stmt.strip()
            if stmt:
                self.execute(stmt)
        return self
    def commit(self):
        return self._conn.commit()
    def close(self):
        return self._conn.close()

def connect_db():
    """A fresh database connection: Postgres on Neon or MySQL on XAMPP when
    DATABASE_URL is set (scheme decides), otherwise the local SQLite file."""
    return _Connection(USE_PG, USE_MYSQL)

def get_db():
    if "db" not in g:
        g.db = connect_db()
    return g.db

@app.teardown_appcontext
def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ------------------------------------------------------- security helpers ---
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def clean(s, max_len=500):
    """Strip + length-limit any text input."""
    return (s or "").strip()[:max_len]

def valid_email(e):
    return bool(EMAIL_RE.match((e or "").strip())) and len(e) <= 120

# --- CSRF: per-session token, validated on every POST via before_request ---
@app.context_processor
def inject_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": lambda: session["csrf_token"]}

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf_token", "")
        form_token = request.form.get("_csrf", "")
        if not token or not hmac.compare_digest(token, form_token):
            abort(400, description="CSRF validation failed")

# --- login rate limiting: 5 failed attempts per IP per 5 minutes ---
_login_attempts = {}  # ip -> [epoch timestamps]

def _prune(ip):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts.get(ip, []) if now - t < 300]
    return _login_attempts[ip]

def rate_limited(ip):
    return len(_prune(ip)) >= 5

def record_failed_login(ip):
    _login_attempts.setdefault(ip, []).append(time.time())

def clear_failed_logins(ip):
    _login_attempts.pop(ip, None)

# --- auth helpers / decorators ---
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

@app.context_processor
def inject_user():
    try:
        return {"me": current_user()}
    except Exception:
        # Never let a DB hiccup break page rendering (e.g. error pages).
        return {"me": None}

@app.context_processor
def inject_admin_extras():
    """Unread contact-message count and open-report count for the admin
    sidebar badges."""
    try:
        me = current_user()
        if me and me["role"] == "admin" and me["active"]:
            n = get_db().execute(
                "SELECT COUNT(*) FROM messages WHERE read=0").fetchone()[0]
            r = get_db().execute(
                "SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0]
            return {"unread_msgs": n, "open_reports": r}
    except Exception:
        pass
    return {"unread_msgs": 0, "open_reports": 0}

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not u["active"]:
            flash("Please log in first.", "err")
            nxt = request.path
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = ""
            return redirect(url_for("login", next=nxt))
        return f(*a, **kw)
    return wrapper

def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            u = current_user()
            if not u or not u["active"]:
                flash("Please log in first.", "err")
                return redirect(url_for("login"))
            if u["role"] not in roles:
                abort(403, description="Not authorized for that page.")
            return f(*a, **kw)
        return wrapper
    return deco

# --- error pages ---
@app.errorhandler(400)
def err_400(e):
    msg = getattr(e, "description", "") or "The request could not be understood."
    return render_template("error.html", code=400, title="Bad request",
                           message=msg), 400

@app.errorhandler(413)
def err_413(e):
    return render_template(
        "error.html", code=413, title="File too large",
        message="That file is over the 5 MB limit. Please upload a smaller file."), 413

@app.errorhandler(403)
def err_403(e):
    return render_template(
        "error.html", code=403, title="Not allowed",
        message="You are logged in, but your account does not have permission "
                "to view this page. If you think this is a mistake, contact the "
                "administrator."), 403

@app.errorhandler(404)
def err_404(e):
    return render_template(
        "error.html", code=404, title="Page not found",
        message="The page you are looking for doesn't exist or was moved. "
                "Check the address, or head back to the home page."), 404

@app.errorhandler(500)
def err_500(e):
    return render_template(
        "error.html", code=500, title="Something went wrong",
        message="Something went wrong on our side. Please try again in a "
                "moment — and if it keeps happening, contact the administrator."), 500

# --- security headers ---
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

# --- activity log ---
def log_activity(actor, action, detail=""):
    db = get_db()
    db.execute(
        "INSERT INTO activity_log(actor, action, detail, created_at) VALUES(?,?,?,?)",
        (clean(actor, 120), clean(action, 60), clean(detail, 300),
         datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()

# --- shared query helpers ---
def provider_avg(pid):
    row = get_db().execute(
        "SELECT AVG(rating), COUNT(*) FROM reviews WHERE provider_id=?", (pid,)).fetchone()
    return (round(row[0], 1) if row[0] else None, row[1])

def booking_value(price_per_day, guests):
    return (price_per_day or 0) * (guests or 1)

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

REPORT_REASONS = ["No-show", "Misleading listing", "Rude or unsafe behaviour",
                  "Asked for payment outside NativeGo", "Fake profile", "Other"]

def availability_text(p):
    """Plain-English availability line for a provider row (FR-12)."""
    if not p["available"]:
        return "Currently not taking new bookings."
    days = (p["availability_days"] or "").strip()
    note = (p["availability_note"] or "").strip()
    parts = []
    if days:
        parts.append("Available " + days.replace(",", ", "))
    if note:
        parts.append(note)
    return (" · ".join(parts) if parts
            else "Available — message the provider to confirm times.")

# ------------------------------------------------------------ schema/seed ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'tourist',
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS providers(
  id INTEGER PRIMARY KEY, user_id INTEGER, business_name TEXT NOT NULL,
  category TEXT NOT NULL, location TEXT NOT NULL, description TEXT NOT NULL,
  price_per_day INTEGER NOT NULL, phone TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  available INTEGER NOT NULL DEFAULT 1,
  availability_days TEXT NOT NULL DEFAULT '',
  availability_note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY, tourist_id INTEGER NOT NULL, provider_id INTEGER NOT NULL,
  date TEXT NOT NULL, guests INTEGER NOT NULL, notes TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews(
  id INTEGER PRIMARY KEY, provider_id INTEGER NOT NULL, tourist_id INTEGER NOT NULL,
  rating INTEGER NOT NULL, comment TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS favorites(
  user_id INTEGER NOT NULL, provider_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, provider_id));
CREATE TABLE IF NOT EXISTS activity_log(
  id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
  subject TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL,
  read INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS request_messages(
  id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
  sender_role TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL, provider_id INTEGER NOT NULL,
  reason TEXT NOT NULL, details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  action TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  resolved_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS verification_docs(
  id INTEGER PRIMARY KEY, provider_id INTEGER NOT NULL, doc_type TEXT NOT NULL,
  filename TEXT NOT NULL, original_name TEXT NOT NULL, uploaded_at TEXT NOT NULL);
"""

# Postgres version of the schema: the only change is SERIAL primary keys.
SCHEMA_PG = SCHEMA.replace("id INTEGER PRIMARY KEY", "id SERIAL PRIMARY KEY")

# MySQL version: AUTO_INCREMENT primary keys, and VARCHAR in place of TEXT
# where a DEFAULT is needed (MySQL TEXT columns cannot have a default value).
SCHEMA_MYSQL = SCHEMA.replace("id INTEGER PRIMARY KEY", "id INT AUTO_INCREMENT PRIMARY KEY")
for _col, _typ in (("availability_days", "VARCHAR(255)"),
                   ("availability_note", "VARCHAR(255)"),
                   ("action", "VARCHAR(255)"),
                   ("resolved_at", "VARCHAR(255)"),
                   ("notes", "VARCHAR(1000)"),
                   ("detail", "VARCHAR(1000)")):
    SCHEMA_MYSQL = SCHEMA_MYSQL.replace(
        f"{_col} TEXT NOT NULL DEFAULT ''", f"{_col} {_typ} NOT NULL DEFAULT ''")
# `read` is a reserved word in MySQL/MariaDB; quote it in the DDL.
SCHEMA_MYSQL = SCHEMA_MYSQL.replace(
    "  read INTEGER NOT NULL DEFAULT 0);", "  `read` INTEGER NOT NULL DEFAULT 0);")

SEED_USERS = [
    ("Wanjiku Tourist", "tourist@demo.co.ke", "demo123", "tourist"),
    ("David Mwangi", "david@demo.co.ke", "demo123", "provider"),
    ("NativeGo Admin", "admin@nativego.co.ke", "admin123", "admin"),
]
SEED_PROVIDERS = [
    (2, "Mara Savannah Safaris", "Safari Guide", "Maasai Mara",
     "10+ years guiding in the Mara. Big Five game drives, photography support, full-day and multi-day packages.",
     8500, "+254 722 000 101", 1),
    (None, "Lamu Dhow Adventures", "Water Sports", "Lamu Island",
     "Sunset dhow cruises and snorkeling trips around the Lamu archipelago. Swahili seafood lunch on board.",
     12000, "+254 733 000 102", 1),
    (None, "Mt Kenya Treks", "Mountain Guide", "Nanyuki",
     "Certified mountain guide for Sirimon–Chogoria routes. Gear hire and acclimatization planning included.",
     6000, "+254 733 000 103", 1),
    (None, "Nairobi by Foot", "City Tour", "Nairobi",
     "Half-day walking tours: KICC rooftop, Maasai Market, street food tasting in the CBD.",
     3500, "+254 733 000 104", 1),
    (None, "Diani Dive School", "Water Sports", "Diani Beach",
     "PADI instructor. Beginner dives, reef trips and kite-surf lessons on Diani's white sands.",
     9000, "+254 722 000 105", 0),
    (None, "Maasai Culture Experience", "Cultural Experience", "Kajiado",
     "Authentic manyatta visit: beadwork, jumping dance, storytelling and traditional meals with a Maasai family.",
     4000, "+254 733 000 106", 1),
    (None, "Victoria Fishing Charters", "Fishing", "Kisumu",
     "Nile perch fishing on Lake Victoria. Boat, gear and guide included; catch-and-cook option.",
     5500, "+254 722 000 107", 0),
    (None, "Amboseli Photo Walks", "Photography", "Amboseli",
     "Pro wildlife photographer. Sunrise shoots with Kilimanjaro backdrop; editing masterclass included.",
     7500, "+254 733 000 108", 1),
]
SEED_REVIEWS = [
    (1, 1, 5, "David spotted leopards twice in one day. Best safari of my life!"),
    (1, 1, 5, "Professional, punctual, and knows the Mara like the back of his hand."),
    (2, 1, 4, "Magical sunset cruise. The seafood lunch was incredible."),
    (4, 1, 5, "Saw Nairobi in a whole new light. The street food stops were a highlight."),
]

def _months_ago(n):
    d = datetime.now() - timedelta(days=30 * n)
    return d.strftime("%Y-%m-%d %H:%M")

def init_db():
    db = connect_db()
    db.executescript(SCHEMA_PG if USE_PG else (SCHEMA_MYSQL if USE_MYSQL else SCHEMA))
    # Upgrade databases created before the FR-06/08/11/12/18 tables and the
    # provider availability columns existed (e.g. the live nativego.db).
    if USE_PG or USE_MYSQL:
        cols = {r[0] for r in db.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='providers'").fetchall()}
    else:
        cols = {r[1] for r in db.execute("PRAGMA table_info(providers)").fetchall()}
    _txt = "VARCHAR(255) NOT NULL DEFAULT ''" if USE_MYSQL else "TEXT NOT NULL DEFAULT ''"
    for col, ddl in (("available", "INTEGER NOT NULL DEFAULT 1"),
                     ("availability_days", _txt),
                     ("availability_note", _txt)):
        if col not in cols:
            db.execute(f"ALTER TABLE providers ADD COLUMN {col} {ddl}")
    db.commit()
    # Seed only on a fresh database (the users table is empty).
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        for name, email, pw, role in SEED_USERS:
            db.execute(
                "INSERT INTO users(name,email,password,role,active,created_at)"
                " VALUES(?,?,?,?,1,?)",
                (name, email, generate_password_hash(pw, method="pbkdf2"), role, now))
        for p in SEED_PROVIDERS:
            db.execute(
                "INSERT INTO providers(user_id,business_name,category,location,"
                "description,price_per_day,phone,verified) VALUES(?,?,?,?,?,?,?,?)", p)
        for pid, tid, rating, comment in SEED_REVIEWS:
            db.execute(
                "INSERT INTO reviews(provider_id,tourist_id,rating,comment,created_at)"
                " VALUES(?,?,?,?,?)", (pid, tid, rating, comment, now))
        # sample bookings spread over recent months (feeds the admin chart)
        seed_bookings = [
            (1, 1, "2026-09-12", 2, "Anniversary trip!", "completed", 5),
            (1, 2, "2026-08-20", 4, "", "completed", 4),
            (1, 4, "2026-10-18", 2, "Vegetarian options please", "accepted", 2),
            (1, 6, "2026-07-05", 6, "School group", "completed", 3),
            (1, 8, "2026-10-25", 1, "", "pending", 1),
            (1, 3, "2026-06-15", 2, "", "completed", 0),
        ]
        for tid, pid, date, guests, notes, status, months in seed_bookings:
            db.execute(
                "INSERT INTO requests(tourist_id,provider_id,date,guests,notes,status,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (tid, pid, date, guests, notes, status, _months_ago(months)))
        db.execute("INSERT INTO favorites(user_id,provider_id) VALUES(1,1),(1,4)")
        for actor, action, detail, m in [
            ("Wanjiku Tourist", "signup", "Tourist account created", 5),
            ("NativeGo Admin", "verification", "Verified Mara Savannah Safaris", 4),
            ("NativeGo Admin", "verification", "Verified Lamu Dhow Adventures", 4),
            ("David Mwangi", "booking_accepted", "Accepted booking #3 (Nairobi by Foot)", 2),
            ("Wanjiku Tourist", "review", "Reviewed Mara Savannah Safaris ★5", 5),
        ]:
            db.execute(
                "INSERT INTO activity_log(actor,action,detail,created_at) VALUES(?,?,?,?)",
                (actor, action, detail, _months_ago(m)))
        db.commit()
    db.close()

def migrate_passwords():
    """Hash any plaintext passwords left in the DB (one-way upgrade)."""
    db = connect_db()
    changed = 0
    for uid, pw in db.execute("SELECT id, password FROM users").fetchall():
        pw = pw or ""
        if not (pw.startswith("pbkdf2:") or pw.startswith("scrypt:")):
            db.execute("UPDATE users SET password=? WHERE id=?",
                       (generate_password_hash(pw, method="pbkdf2"), uid))
            changed += 1
    db.commit()
    db.close()
    if changed:
        print(f"Migrated {changed} plaintext password(s) to pbkdf2 hashes.")

# ============================================================ public/auth ===
CAT_EMOJI = {"Safari Guide": "🦁", "Water Sports": "🌊", "Mountain Guide": "⛰️",
             "City Tour": "🏙️", "Cultural Experience": "🥁", "Fishing": "🎣",
             "Photography": "📸"}

@app.route("/")
def index():
    """Marketing landing page."""
    db = get_db()
    prov_n = db.execute(
        "SELECT COUNT(*) FROM providers WHERE verified=1").fetchone()[0]
    book_n = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    avg = db.execute("SELECT AVG(rating) FROM reviews").fetchone()[0]
    featured = db.execute(
        "SELECT p.*, (SELECT AVG(rating) FROM reviews r WHERE r.provider_id=p.id) AS avg_r,"
        " (SELECT COUNT(*) FROM reviews r WHERE r.provider_id=p.id) AS n_r"
        " FROM providers p WHERE p.verified=1"
        " ORDER BY avg_r DESC NULLS LAST, n_r DESC LIMIT 4").fetchall()
    testimonials = db.execute(
        "SELECT r.*, u.name AS tourist, p.business_name FROM reviews r"
        " JOIN users u ON u.id=r.tourist_id"
        " JOIN providers p ON p.id=r.provider_id"
        " ORDER BY r.id DESC LIMIT 3").fetchall()
    cats = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM providers ORDER BY category")]
    return render_template("index.html", prov_n=prov_n, book_n=book_n, avg=avg,
                           featured=featured, testimonials=testimonials,
                           cats=cats, cat_emoji=CAT_EMOJI)

@app.route("/discover")
def discover():
    q = clean(request.args.get("q", ""), 80)
    cat = clean(request.args.get("category", ""), 60)
    loc = clean(request.args.get("location", ""), 60)
    sort = request.args.get("sort", "rating")
    avail_only = request.args.get("available") == "1"  # FR-12 filter
    db = get_db()
    cats = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM providers ORDER BY category")]
    locs = [r[0] for r in db.execute(
        "SELECT DISTINCT location FROM providers WHERE verified=1 ORDER BY location")]
    sql = ("SELECT p.*, (SELECT AVG(rating) FROM reviews r WHERE r.provider_id=p.id) AS avg_r,"
           " (SELECT COUNT(*) FROM reviews r WHERE r.provider_id=p.id) AS n_r"
           " FROM providers p WHERE p.verified=1")
    args = []
    if q:
        sql += " AND (p.business_name LIKE ? OR p.location LIKE ? OR p.description LIKE ?)"
        args += [f"%{q}%"] * 3
    if cat:
        sql += " AND p.category=?"; args.append(cat)
    if loc:
        sql += " AND p.location=?"; args.append(loc)
    if avail_only:
        sql += " AND p.available=1"
    order = {"price_asc": "p.price_per_day ASC", "price_desc": "p.price_per_day DESC",
             "name": "p.business_name ASC"}.get(sort, "avg_r DESC NULLS LAST, n_r DESC")
    providers = db.execute(sql + f" ORDER BY {order}", args).fetchall()
    favs = set()
    me = current_user()
    if me:
        favs = {r[0] for r in db.execute(
            "SELECT provider_id FROM favorites WHERE user_id=?", (me["id"],))}
    return render_template("discover.html", providers=providers, cats=cats, locs=locs,
                           q=q, cat=cat, loc=loc, sort=sort, favs=favs,
                           avail_only=avail_only)

@app.route("/about")
def about():
    db = get_db()
    prov_n = db.execute(
        "SELECT COUNT(*) FROM providers WHERE verified=1").fetchone()[0]
    book_n = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    cats = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM providers ORDER BY category")]
    return render_template("about.html", prov_n=prov_n, book_n=book_n, cats=cats)

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/guide")
def guide():
    return render_template("guide_index.html")

@app.route("/guide/requirements")
def guide_requirements():
    return render_template("guide_requirements.html")

@app.route("/guide/database")
def guide_database():
    return render_template("guide_database.html")

@app.route("/guide/how-it-works")
def guide_how_it_works():
    return render_template("guide_how_it_works.html")

DESTINATIONS = [
    ("Maasai Mara", "🦁", "Maasai Mara",
     "Endless savannah, the Great Migration and the Big Five. Kenya's most iconic safari destination, best with a seasoned local guide."),
    ("Diani Beach", "🏖️", "Diani",
     "Powder-white sand and turquoise water on the south coast. Diving, kite-surfing and dhow trips at every turn."),
    ("Lamu Island", "⛵", "Lamu",
     "A UNESCO-listed Swahili old town with no cars — just dhows, donkeys and centuries of culture. Sunset cruises are a must."),
    ("Amboseli", "🐘", "Amboseli",
     "Huge elephant herds beneath the snow-capped dome of Kilimanjaro. A photographer's dream at sunrise."),
    ("Mt. Kenya · Nanyuki", "⛰️", "Nanyuki",
     "Africa's second-highest peak. Trek ancient moorlands and glaciers with certified mountain guides from Nanyuki."),
    ("Nairobi", "🏙️", "Nairobi",
     "The world's only capital with a national park. Street food, markets, museums and nightlife — best explored on foot with a local."),
    ("Lake Victoria · Kisumu", "🎣", "Kisumu",
     "Africa's largest lake and home of the giant Nile perch. Fishing charters, lakeside culture and fiery sunsets."),
    ("Kajiado", "🥁", "Kajiado",
     "Maasai heartland south of Nairobi. Manyatta visits, beadwork, jumping dances and stories around the fire."),
]

@app.route("/destinations")
def destinations():
    db = get_db()
    cards = []
    for name, emoji, q, blurb in DESTINATIONS:
        n = db.execute(
            "SELECT COUNT(*) FROM providers WHERE verified=1 AND location LIKE ?",
            (f"%{q}%",)).fetchone()[0]
        cards.append({"name": name, "emoji": emoji, "q": q, "blurb": blurb, "n": n})
    return render_template("destinations.html", cards=cards)

# --- contact email (Resend) -------------------------------------------------
# Contact messages are saved to the DB and also emailed to the company so
# nothing is missed. Set RESEND_API_KEY and CONTACT_EMAIL in the environment
# (Vercel). Without a key the message is still saved; the email is skipped.
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "agrey.gorwa@strathmore.edu")

def send_contact_email(name, email, subject, message):
    """Send a contact-form message to the company via Resend. Fail-soft:
    returns True on success, False otherwise; never raises."""
    key = os.environ.get("RESEND_API_KEY", "")
    if not key:
        return False
    payload = {
        "from": "NativeGo <onboarding@resend.dev>",
        "to": [CONTACT_EMAIL],
        "reply_to": email,
        "subject": f"NativeGo contact \u2014 {subject}",
        "text": f"Name: {name}\nEmail: {email}\nSubject: {subject}\n\n{message}",
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False

CONTACT_SUBJECTS = ["General", "Booking help", "Provider support", "Safety concern"]

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = clean(request.form.get("name", ""), 80)
        email = clean(request.form.get("email", ""), 120).lower()
        subject = request.form.get("subject", "")
        message = clean(request.form.get("message", ""), 2000)
        errors = []
        if len(name) < 2:
            errors.append("Please enter your name.")
        if not valid_email(email):
            errors.append("Please enter a valid email address.")
        if subject not in CONTACT_SUBJECTS:
            errors.append("Please choose a subject.")
        if len(message) < 10:
            errors.append("Please write a message (10+ characters).")
        if errors:
            for e in errors:
                flash(e, "err")
            return render_template("contact.html", subjects=CONTACT_SUBJECTS,
                                   form=request.form), 400
        db = get_db()
        db.execute(
            "INSERT INTO messages(name,email,subject,message,created_at)"
            " VALUES(?,?,?,?,?)",
            (name, email, subject, message,
             datetime.now().strftime("%Y-%m-%d %H:%M")))
        db.commit()
        me = current_user()
        log_activity(me["name"] if me else name, "contact_message",
                     f"{subject} from {email}")
        send_contact_email(name, email, subject, message)
        flash("Message sent! We'll get back to you within 24 hours.", "ok")
        return redirect(url_for("contact"))
    return render_template("contact.html", subjects=CONTACT_SUBJECTS, form={})

@app.route("/providers")
def for_providers():
    db = get_db()
    prov_n = db.execute(
        "SELECT COUNT(*) FROM providers WHERE verified=1").fetchone()[0]
    return render_template("for_providers.html", prov_n=prov_n)

@app.route("/safety")
def safety():
    return render_template("safety.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if rate_limited(ip):
            flash("Too many failed attempts. Try again in a few minutes.", "err")
            return render_template("login.html"), 429
        email = clean(request.form.get("email", ""), 120).lower()
        pw = request.form.get("password", "")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and u["active"] and check_password_hash(u["password"], pw):
            clear_failed_logins(ip)
            session.clear()
            session["user_id"] = u["id"]
            session["csrf_token"] = secrets.token_hex(32)
            session.permanent = True
            flash(f"Karibu, {u['name']}!", "ok")
            nxt = request.args.get("next", "")
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = url_for("index")
            return redirect(nxt)
        record_failed_login(ip)
        flash("Wrong email or password.", "err")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("index"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    db = get_db()
    cats = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM providers ORDER BY category")] or \
        ["Safari Guide", "Water Sports", "Mountain Guide", "City Tour",
         "Cultural Experience", "Fishing", "Photography"]
    if request.method == "POST":
        name = clean(request.form.get("name", ""), 80)
        email = clean(request.form.get("email", ""), 120).lower()
        pw = request.form.get("password", "")
        role = request.form.get("role", "tourist")
        if role not in ("tourist", "provider"):
            role = "tourist"
        errors = []
        if len(name) < 2:
            errors.append("Please enter your name.")
        if not valid_email(email):
            errors.append("Please enter a valid email address.")
        if len(pw) < 8:
            errors.append("Password must be at least 8 characters.")
        if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            errors.append("That email is already registered — log in instead.")
        biz = {}
        if role == "provider":
            biz = {
                "business": clean(request.form.get("business", ""), 120),
                "category": clean(request.form.get("category", ""), 60),
                "location": clean(request.form.get("location", ""), 80),
                "description": clean(request.form.get("description", ""), 1000),
                "phone": clean(request.form.get("phone", ""), 30),
            }
            try:
                biz["price"] = int(request.form.get("price", "0"))
            except ValueError:
                biz["price"] = 0
            if len(biz["business"]) < 2:
                errors.append("Business name is required.")
            if not biz["location"]:
                errors.append("Location is required.")
            if biz["price"] <= 0:
                errors.append("Price per day must be a positive number.")
            if len(biz["phone"]) < 7:
                errors.append("Please enter a valid phone number.")
            if len(biz["description"]) < 10:
                errors.append("Please describe your services (10+ characters).")
        if errors:
            for e in errors:
                flash(e, "err")
            return render_template("signup.html", cats=cats,
                                   form=request.form), 400
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        if USE_PG:
            cur = db.execute(
                "INSERT INTO users(name,email,password,role,active,created_at)"
                " VALUES(?,?,?,?,1,?) RETURNING id",
                (name, email, generate_password_hash(pw, method="pbkdf2"), role, now))
            uid = cur.fetchone()[0]
        else:
            cur = db.execute(
                "INSERT INTO users(name,email,password,role,active,created_at)"
                " VALUES(?,?,?,?,1,?)",
                (name, email, generate_password_hash(pw, method="pbkdf2"), role, now))
            uid = cur.lastrowid
        if role == "provider":
            db.execute(
                "INSERT INTO providers(user_id,business_name,category,location,"
                "description,price_per_day,phone,verified)"
                " VALUES(?,?,?,?,?,?,?,0)",
                (uid, biz["business"], biz["category"] or cats[0], biz["location"],
                 biz["description"], biz["price"], biz["phone"]))
        db.commit()
        log_activity(name, "signup",
                     f"{role.capitalize()} account created ({email})")
        session.clear()
        session["user_id"] = uid
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True
        if role == "provider":
            flash("Account created! Your listing is pending admin verification.", "ok")
        else:
            flash(f"Karibu, {name}! Your account is ready.", "ok")
        return redirect(url_for("index"))
    return render_template("signup.html", cats=cats, form={})

# ================================================================ tourist ===
@app.route("/provider/<int:pid>")
def provider_detail(pid):
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=?", (pid,)).fetchone()
    if not p or not p["verified"]:
        me = current_user()
        if not (me and me["role"] == "admin"):
            abort(404)
    reviews = db.execute(
        "SELECT r.*, u.name FROM reviews r JOIN users u ON u.id=r.tourist_id"
        " WHERE r.provider_id=? ORDER BY r.id DESC", (pid,)).fetchall()
    avg, n = provider_avg(pid)
    fav = False
    me = current_user()
    if me:
        fav = db.execute("SELECT 1 FROM favorites WHERE user_id=? AND provider_id=?",
                         (me["id"], pid)).fetchone() is not None
    return render_template("provider_detail.html", p=p, reviews=reviews,
                           avg=avg, n=n, fav=fav, avail_text=availability_text(p),
                           report_reasons=REPORT_REASONS,
                           today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/favorite/<int:pid>", methods=["POST"])
@login_required
def favorite(pid):
    me = current_user()
    db = get_db()
    if not db.execute("SELECT id FROM providers WHERE id=? AND verified=1",
                      (pid,)).fetchone():
        abort(404)
    exists = db.execute("SELECT 1 FROM favorites WHERE user_id=? AND provider_id=?",
                        (me["id"], pid)).fetchone()
    if exists:
        db.execute("DELETE FROM favorites WHERE user_id=? AND provider_id=?",
                   (me["id"], pid))
    else:
        db.execute("INSERT OR IGNORE INTO favorites(user_id,provider_id) VALUES(?,?)",
                   (me["id"], pid))
    db.commit()
    # Only follow the referrer when it is a page on this site; otherwise
    # fall back to the provider page (never redirect to an outside URL).
    ref = request.referrer or ""
    if not ref.startswith(request.host_url):
        ref = url_for("provider_detail", pid=pid)
    return redirect(ref)

@app.route("/favorites")
@login_required
def favorites_page():
    me = current_user()
    db = get_db()
    providers = db.execute(
        "SELECT p.*, (SELECT AVG(rating) FROM reviews r WHERE r.provider_id=p.id) AS avg_r"
        " FROM providers p JOIN favorites f ON f.provider_id=p.id"
        " WHERE f.user_id=? ORDER BY p.business_name", (me["id"],)).fetchall()
    return render_template("favorites.html", providers=providers)

@app.route("/request/<int:pid>", methods=["POST"])
@login_required
@role_required("tourist")
def make_request(pid):
    me = current_user()
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=? AND verified=1", (pid,)).fetchone()
    if not p:
        abort(404)
    date = clean(request.form.get("date", ""), 10)
    try:
        guests = int(request.form.get("guests", "1"))
    except ValueError:
        guests = 0
    notes = clean(request.form.get("notes", ""), 500)
    try:
        # strptime rejects impossible dates (e.g. 2026-02-30) that a
        # plain YYYY-MM-DD pattern check would let through.
        _day = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        _day = None
    if _day is None or date < datetime.now().strftime("%Y-%m-%d"):
        flash("Please pick a valid date (today or later).", "err")
        return redirect(url_for("provider_detail", pid=pid))
    if not 1 <= guests <= 50:
        flash("Guests must be between 1 and 50.", "err")
        return redirect(url_for("provider_detail", pid=pid))
    db.execute(
        "INSERT INTO requests(tourist_id,provider_id,date,guests,notes,status,created_at)"
        " VALUES(?,?,?,?,?,'pending',?)",
        (me["id"], pid, date, guests, notes,
         datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
    log_activity(me["name"], "booking_request",
                 f"Requested {p['business_name']} on {date} ({guests} guests)")
    flash("Request sent! The provider will confirm shortly.", "ok")
    return redirect(url_for("my_requests"))

@app.route("/request/<int:rid>/cancel", methods=["POST"])
@login_required
@role_required("tourist")
def cancel_request(rid):
    _cancel_booking(current_user(), rid)
    return redirect(url_for("my_requests"))

@app.route("/booking/<int:rid>/cancel", methods=["POST"])
@login_required
@role_required("tourist")
def booking_cancel(rid):
    _cancel_booking(current_user(), rid)
    return redirect(url_for("booking_detail", rid=rid))

def _cancel_booking(me, rid):
    """Attempt to cancel a tourist's pending request; flashes outcome."""
    db = get_db()
    r = db.execute("SELECT * FROM requests WHERE id=? AND tourist_id=?",
                   (rid, me["id"])).fetchone()
    if not r:
        abort(404)
    if r["status"] != "pending":
        flash("Only pending requests can be cancelled.", "err")
        return False
    db.execute("UPDATE requests SET status='cancelled' WHERE id=?", (rid,))
    db.commit()
    p = db.execute("SELECT business_name FROM providers WHERE id=?",
                   (r["provider_id"],)).fetchone()
    log_activity(me["name"], "booking_cancelled",
                 f"Cancelled request #{rid} ({p['business_name'] if p else '?'})")
    flash("Booking request cancelled.", "ok")
    return True

@app.route("/booking/<int:rid>")
@login_required
def booking_detail(rid):
    me = current_user()
    db = get_db()
    r = db.execute(
        "SELECT r.*, p.business_name, p.location, p.phone, p.price_per_day,"
        " u.name AS tourist FROM requests r"
        " JOIN providers p ON p.id=r.provider_id"
        " JOIN users u ON u.id=r.tourist_id"
        " WHERE r.id=?", (rid,)).fetchone()
    if not r:
        abort(404)
    allowed = me["role"] == "admin" or r["tourist_id"] == me["id"]
    if not allowed and me["role"] == "provider":
        prov = _my_provider(me)
        allowed = bool(prov and prov["id"] == r["provider_id"])
    if not allowed:
        abort(404)
    # FR-06: message thread on the request (tourist + provider parties only).
    msgs = db.execute(
        "SELECT m.*, u.name AS sender FROM request_messages m"
        " JOIN users u ON u.id=m.sender_id"
        " WHERE m.request_id=? ORDER BY m.id", (rid,)).fetchall()
    can_message = False
    if me["role"] == "tourist":
        can_message = r["tourist_id"] == me["id"]
    elif me["role"] == "provider":
        prov = _my_provider(me)
        can_message = bool(prov and prov["id"] == r["provider_id"])
    return render_template("booking_detail.html", r=r, msgs=msgs,
                           can_message=can_message)


@app.route("/booking/<int:rid>/message", methods=["POST"])
@login_required
def booking_message(rid):
    """FR-06: tourist or provider posts a message on their request."""
    me = current_user()
    db = get_db()
    r = db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    if not r:
        abort(404)
    prov = _my_provider(me) if me["role"] == "provider" else None
    is_party = ((me["role"] == "tourist" and r["tourist_id"] == me["id"]) or
                (me["role"] == "provider" and prov
                 and prov["id"] == r["provider_id"]))
    if not is_party:
        abort(404)
    body = clean(request.form.get("body", ""), 500)
    if len(body) < 1:
        flash("Write a message first.", "err")
        return redirect(url_for("booking_detail", rid=rid))
    db.execute(
        "INSERT INTO request_messages(request_id,sender_id,sender_role,body,created_at)"
        " VALUES(?,?,?,?,?)",
        (rid, me["id"], me["role"], body,
         datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
    log_activity(me["name"], "request_message", f"Messaged on booking #{rid}")
    flash("Message sent.", "ok")
    return redirect(url_for("booking_detail", rid=rid))

@app.route("/my-requests")
@login_required
def my_requests():
    me = current_user()
    db = get_db()
    rows = db.execute(
        "SELECT r.*, p.business_name, p.location, p.price_per_day,"
        " (SELECT COUNT(*) FROM request_messages m WHERE m.request_id=r.id) AS msg_n"
        " FROM requests r"
        " JOIN providers p ON p.id=r.provider_id"
        " WHERE r.tourist_id=? ORDER BY r.id DESC", (me["id"],)).fetchall()
    return render_template("my_requests.html", rows=rows)

@app.route("/review/<int:pid>", methods=["POST"])
@login_required
@role_required("tourist")
def add_review(pid):
    me = current_user()
    db = get_db()
    if not db.execute("SELECT id FROM providers WHERE id=? AND verified=1",
                      (pid,)).fetchone():
        abort(404)
    try:
        rating = int(request.form.get("rating", "0"))
    except ValueError:
        rating = 0
    comment = clean(request.form.get("comment", ""), 1000)
    if not 1 <= rating <= 5:
        flash("Rating must be between 1 and 5.", "err")
    elif len(comment) < 3:
        flash("Please write a short comment.", "err")
    else:
        db.execute(
            "INSERT INTO reviews(provider_id,tourist_id,rating,comment,created_at)"
            " VALUES(?,?,?,?,?)",
            (pid, me["id"], rating, comment,
             datetime.now().strftime("%Y-%m-%d")))
        db.commit()
        log_activity(me["name"], "review",
                     f"Reviewed provider #{pid} ★{rating}")
        flash("Asante for the review!", "ok")
    return redirect(url_for("provider_detail", pid=pid))

@app.route("/provider/<int:pid>/report", methods=["POST"])
@login_required
@role_required("tourist")
def report_provider(pid):
    """FR-08: tourist reports a misbehaving account; case queued for admin."""
    me = current_user()
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    reason = request.form.get("reason", "")
    details = clean(request.form.get("details", ""), 1000)
    if reason not in REPORT_REASONS or len(details) < 3:
        flash("Please choose a reason and describe what happened "
              "(3+ characters).", "err")
        return redirect(url_for("provider_detail", pid=pid))
    db.execute(
        "INSERT INTO reports(reporter_id,provider_id,reason,details,status,action,created_at)"
        " VALUES(?,?,?,?,'open','',?)",
        (me["id"], pid, reason, details,
         datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
    log_activity(me["name"], "report",
                 f"Reported {p['business_name']}: {reason}")
    flash("Report received — our team will review it. Thank you.", "ok")
    return redirect(url_for("provider_detail", pid=pid))

@app.route("/profile")
@login_required
def profile():
    me = current_user()
    db = get_db()
    if me["role"] == "tourist":
        bookings = db.execute(
            "SELECT r.*, p.business_name FROM requests r"
            " JOIN providers p ON p.id=r.provider_id"
            " WHERE r.tourist_id=? ORDER BY r.id DESC LIMIT 10", (me["id"],)).fetchall()
        fav_n = db.execute("SELECT COUNT(*) FROM favorites WHERE user_id=?",
                           (me["id"],)).fetchone()[0]
        return render_template("profile.html", bookings=bookings, fav_n=fav_n,
                               extra=None)
    prov = db.execute("SELECT * FROM providers WHERE user_id=?", (me["id"],)).fetchone()
    return render_template("profile.html", bookings=[], fav_n=0, extra=prov)

# ================================================================ provider =
def _my_provider(me):
    return get_db().execute("SELECT * FROM providers WHERE user_id=?",
                            (me["id"],)).fetchone()

@app.route("/dashboard")
@login_required
@role_required("provider")
def provider_dashboard():
    me = current_user()
    db = get_db()
    prov = _my_provider(me)
    if not prov:
        flash("No provider profile linked to this account yet.", "err")
        return redirect(url_for("index"))
    rows = db.execute(
        "SELECT r.*, u.name AS tourist FROM requests r JOIN users u ON u.id=r.tourist_id"
        " WHERE r.provider_id=? ORDER BY r.id DESC", (prov["id"],)).fetchall()
    pending = sum(1 for r in rows if r["status"] == "pending")
    accepted = sum(1 for r in rows if r["status"] == "accepted")
    completed = sum(1 for r in rows if r["status"] == "completed")
    earnings = sum(booking_value(prov["price_per_day"], r["guests"]) for r in rows
                   if r["status"] in ("accepted", "completed"))
    reviews = db.execute(
        "SELECT r.*, u.name FROM reviews r JOIN users u ON u.id=r.tourist_id"
        " WHERE r.provider_id=? ORDER BY r.id DESC", (prov["id"],)).fetchall()
    avg, n = provider_avg(prov["id"])
    docs = db.execute(
        "SELECT * FROM verification_docs WHERE provider_id=? ORDER BY id DESC",
        (prov["id"],)).fetchall()
    days_set = set((prov["availability_days"] or "").split(",")) - {""}
    return render_template("provider_dashboard.html", prov=prov, rows=rows,
                           pending=pending, accepted=accepted, completed=completed,
                           earnings=earnings, reviews=reviews, avg=avg, n=n,
                           docs=docs, days=DAYS, days_set=days_set,
                           doc_types=DOC_TYPES)

@app.route("/request/<int:rid>/<action>", methods=["POST"])
@login_required
@role_required("provider")
def request_action(rid, action):
    me = current_user()
    prov = _my_provider(me)
    db = get_db()
    r = db.execute(
        "SELECT * FROM requests WHERE id=? AND provider_id=?",
        (rid, prov["id"] if prov else -1)).fetchone()
    if not r:
        abort(404)
    allowed = {"accept": ("pending", "accepted"),
               "decline": ("pending", "declined"),
               "complete": ("accepted", "completed")}
    if action not in allowed:
        abort(400)
    need, new = allowed[action]
    if r["status"] != need:
        flash(f"Request is {r['status']}, cannot {action} it.", "err")
    else:
        db.execute("UPDATE requests SET status=? WHERE id=?", (new, rid))
        db.commit()
        t = db.execute("SELECT name FROM users WHERE id=?", (r["tourist_id"],)).fetchone()
        log_activity(me["name"], f"booking_{new}",
                     f"{new.capitalize()} booking #{rid} for {t['name'] if t else '?'}")
        flash(f"Request {new}.", "ok")
    return redirect(url_for("provider_dashboard"))

@app.route("/dashboard/edit", methods=["GET", "POST"])
@login_required
@role_required("provider")
def provider_edit():
    me = current_user()
    db = get_db()
    prov = _my_provider(me)
    if not prov:
        abort(404)
    cats = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM providers ORDER BY category")]
    if request.method == "POST":
        business = clean(request.form.get("business_name", ""), 120)
        category = clean(request.form.get("category", ""), 60)
        location = clean(request.form.get("location", ""), 80)
        description = clean(request.form.get("description", ""), 1000)
        phone = clean(request.form.get("phone", ""), 30)
        try:
            price = int(request.form.get("price_per_day", "0"))
        except ValueError:
            price = 0
        errors = []
        if len(business) < 2:
            errors.append("Business name is required.")
        if not location:
            errors.append("Location is required.")
        if price <= 0:
            errors.append("Price per day must be positive.")
        if len(phone) < 7:
            errors.append("Enter a valid phone number.")
        if len(description) < 10:
            errors.append("Description needs at least 10 characters.")
        if errors:
            for e in errors:
                flash(e, "err")
            return render_template("provider_edit.html", prov=prov, cats=cats), 400
        db.execute(
            "UPDATE providers SET business_name=?, category=?, location=?,"
            " description=?, price_per_day=?, phone=? WHERE id=?",
            (business, category, location, description, price, phone, prov["id"]))
        db.commit()
        log_activity(me["name"], "profile_update", f"Updated {business} profile")
        flash("Profile updated.", "ok")
        return redirect(url_for("provider_dashboard"))
    return render_template("provider_edit.html", prov=prov, cats=cats)

@app.route("/dashboard/availability", methods=["POST"])
@login_required
@role_required("provider")
def provider_availability():
    """FR-12: provider sets available days/times; shown in search results."""
    me = current_user()
    prov = _my_provider(me)
    if not prov:
        abort(404)
    db = get_db()
    days = [d for d in request.form.getlist("days") if d in DAYS]
    note = clean(request.form.get("note", ""), 200)
    available = 1 if request.form.get("available") else 0
    db.execute(
        "UPDATE providers SET available=?, availability_days=?, availability_note=?"
        " WHERE id=?",
        (available, ",".join(days), note, prov["id"]))
    db.commit()
    log_activity(me["name"], "availability_update",
                 f"Set availability for {prov['business_name']}")
    flash("Availability saved.", "ok")
    return redirect(url_for("provider_dashboard"))

@app.route("/dashboard/documents", methods=["POST"])
@login_required
@role_required("provider")
def provider_upload_doc():
    """FR-11: provider uploads an identity document or certificate for
    admin verification review. Files are type-checked and stored on disk."""
    me = current_user()
    prov = _my_provider(me)
    if not prov:
        abort(404)
    doc_type = request.form.get("doc_type", "")
    if doc_type not in DOC_TYPES:
        flash("Choose a document type.", "err")
        return redirect(url_for("provider_dashboard"))
    f = request.files.get("document")
    if not f or not f.filename:
        flash("Choose a file to upload.", "err")
        return redirect(url_for("provider_dashboard"))
    ext = (f.filename.rsplit(".", 1)[-1] if "." in f.filename else "").lower()
    if ext not in ALLOWED_DOC_EXTS:
        flash("Only PDF, JPG and PNG files are accepted.", "err")
        return redirect(url_for("provider_dashboard"))
    safe = secure_filename(f.filename)
    stored = f"{prov['id']}_{int(time.time())}_{safe}"
    f.save(os.path.join(UPLOAD_DIR, stored))
    db = get_db()
    db.execute(
        "INSERT INTO verification_docs(provider_id,doc_type,filename,original_name,uploaded_at)"
        " VALUES(?,?,?,?,?)",
        (prov["id"], doc_type, stored, safe,
         datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
    log_activity(me["name"], "verification_upload",
                 f"Uploaded {doc_type} for {prov['business_name']}")
    flash("Document uploaded — queued for admin review.", "ok")
    return redirect(url_for("provider_dashboard"))

# =================================================================== admin ==
def _admin_stats(db):
    stats = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "providers": db.execute("SELECT COUNT(*) FROM providers").fetchone()[0],
        "pending_verif": db.execute(
            "SELECT COUNT(*) FROM providers WHERE verified=0").fetchone()[0],
        "bookings": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
        "reviews": db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0],
        "open_reports": db.execute(
            "SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0],
    }
    rev = db.execute(
        "SELECT r.guests, p.price_per_day FROM requests r"
        " JOIN providers p ON p.id=r.provider_id"
        " WHERE r.status IN ('accepted','completed')").fetchall()
    gross = sum(booking_value(x["price_per_day"], x["guests"]) for x in rev)
    stats["revenue"] = int(gross * 0.10)
    return stats

def _bookings_chart(db):
    """Bookings per month, last 6 months → (labels, values) for SVG."""
    labels, values = [], []
    now = datetime.now()
    for i in range(5, -1, -1):
        y = now.year + (now.month - 1 - i) // 12
        m = (now.month - 1 - i) % 12 + 1
        ym = f"{y:04d}-{m:02d}"
        labels.append(datetime(y, m, 1).strftime("%b"))
        values.append(db.execute(
            "SELECT COUNT(*) FROM requests WHERE substr(created_at,1,7)=?",
            (ym,)).fetchone()[0])
    return labels, values

@app.route("/admin")
@login_required
@role_required("admin")
def admin_overview():
    db = get_db()
    stats = _admin_stats(db)
    labels, values = _bookings_chart(db)
    activity = db.execute(
        "SELECT * FROM activity_log ORDER BY id DESC LIMIT 10").fetchall()
    return render_template("admin_overview.html", stats=stats, labels=labels,
                           values=values, activity=activity,
                           maxv=max(values) if values else 1)

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    q = clean(request.args.get("q", ""), 80)
    db = get_db()
    if q:
        users = db.execute(
            "SELECT * FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY id DESC",
            (f"%{q}%", f"%{q}%")).fetchall()
    else:
        users = db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return render_template("admin_users.html", users=users, q=q)

@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@login_required
@role_required("admin")
def admin_user_role(uid):
    me = current_user()
    role = request.form.get("role", "")
    if role not in ("tourist", "provider", "admin"):
        abort(400)
    if uid == me["id"]:
        flash("You can't change your own role.", "err")
        return redirect(url_for("admin_users"))
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    db.commit()
    log_activity(me["name"], "role_change",
                 f"Changed {u['name']} ({u['email']}) role to {role}")
    flash(f"{u['name']} is now {role}.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def admin_user_toggle(uid):
    me = current_user()
    if uid == me["id"]:
        flash("You can't deactivate yourself.", "err")
        return redirect(url_for("admin_users"))
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    new = 0 if u["active"] else 1
    db.execute("UPDATE users SET active=? WHERE id=?", (new, uid))
    db.commit()
    log_activity(me["name"], "user_deactivated" if not new else "user_reactivated",
                 f"{u['name']} ({u['email']})")
    flash(f"{u['name']} {'deactivated' if not new else 'reactivated'}.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/verifications")
@login_required
@role_required("admin")
def admin_verifications():
    db = get_db()
    pending = db.execute(
        "SELECT p.*, u.name AS owner, u.email FROM providers p"
        " LEFT JOIN users u ON u.id=p.user_id"
        " WHERE p.verified=0 ORDER BY p.id").fetchall()
    docs = db.execute(
        "SELECT * FROM verification_docs ORDER BY uploaded_at DESC, id DESC").fetchall()
    return render_template("admin_verifications.html", pending=pending, docs=docs)

@app.route("/admin/verifications/doc/<int:doc_id>")
@login_required
@role_required("admin")
def admin_verification_doc(doc_id):
    """Serve an uploaded verification document (FR-11) to the admin."""
    db = get_db()
    d = db.execute("SELECT * FROM verification_docs WHERE id=?",
                   (doc_id,)).fetchone()
    if not d:
        abort(404)
    return send_from_directory(UPLOAD_DIR, d["filename"])

@app.route("/admin/verify/<int:pid>/<decision>", methods=["POST"])
@login_required
@role_required("admin")
def admin_verify(pid, decision):
    me = current_user()
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if decision == "approve":
        db.execute("UPDATE providers SET verified=1 WHERE id=?", (pid,))
        db.commit()
        log_activity(me["name"], "verification",
                     f"Approved {p['business_name']} ({p['location']})")
        flash(f"{p['business_name']} verified and live. ✓", "ok")
    elif decision == "reject":
        db.execute("DELETE FROM providers WHERE id=?", (pid,))
        db.commit()
        log_activity(me["name"], "verification",
                     f"Rejected application: {p['business_name']}")
        flash("Application rejected and removed.", "ok")
    else:
        abort(400)
    return redirect(url_for("admin_verifications"))

@app.route("/admin/reports")
@login_required
@role_required("admin")
def admin_reports():
    """FR-18: reported cases queue — open first, with dismiss / warn /
    suspend decisions."""
    status = request.args.get("status", "open")
    db = get_db()
    base = ("SELECT rep.*, u.name AS reporter, p.business_name FROM reports rep"
            " JOIN users u ON u.id=rep.reporter_id"
            " JOIN providers p ON p.id=rep.provider_id")
    if status in ("open", "closed"):
        rows = db.execute(base + " WHERE rep.status=? ORDER BY rep.id DESC",
                          (status,)).fetchall()
    else:
        status = "all"
        rows = db.execute(base + " ORDER BY rep.id DESC").fetchall()
    open_n = db.execute(
        "SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0]
    return render_template("admin_reports.html", rows=rows, status=status,
                           open_n=open_n)

@app.route("/admin/reports/<int:rep_id>/<action>", methods=["POST"])
@login_required
@role_required("admin")
def admin_report_action(rep_id, action):
    """FR-18: close a reported case — dismiss it, warn the provider, or
    suspend the account (deactivate the login and hide the listing)."""
    me = current_user()
    db = get_db()
    rep = db.execute("SELECT * FROM reports WHERE id=?", (rep_id,)).fetchone()
    if not rep:
        abort(404)
    if action not in ("dismiss", "warn", "suspend"):
        abort(400)
    if rep["status"] != "open":
        flash("That case is already closed.", "err")
        return redirect(url_for("admin_reports"))
    p = db.execute("SELECT * FROM providers WHERE id=?",
                   (rep["provider_id"],)).fetchone()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    if action == "dismiss":
        db.execute(
            "UPDATE reports SET status='closed', action='dismissed', resolved_at=?"
            " WHERE id=?", (now, rep_id))
        detail = f"Dismissed report #{rep_id} ({rep['reason']})"
        flash("Report dismissed.", "ok")
    elif action == "warn":
        db.execute(
            "UPDATE reports SET status='closed', action='warning', resolved_at=?"
            " WHERE id=?", (now, rep_id))
        detail = (f"Warned {p['business_name'] if p else 'provider'} over "
                  f"report #{rep_id} ({rep['reason']})")
        flash("Warning recorded and case closed.", "ok")
    else:  # suspend
        if p:
            if p["user_id"]:
                db.execute("UPDATE users SET active=0 WHERE id=?", (p["user_id"],))
            db.execute("UPDATE providers SET verified=0 WHERE id=?", (p["id"],))
        db.execute(
            "UPDATE reports SET status='closed', action='suspended', resolved_at=?"
            " WHERE id=?", (now, rep_id))
        detail = (f"Suspended {p['business_name'] if p else 'provider'} over "
                  f"report #{rep_id} ({rep['reason']})")
        flash("Account suspended and case closed.", "ok")
    db.commit()
    log_activity(me["name"], "report_" + action, detail)
    return redirect(url_for("admin_reports"))

@app.route("/admin/providers")
@login_required
@role_required("admin")
def admin_providers():
    db = get_db()
    providers = db.execute(
        "SELECT p.*, (SELECT AVG(rating) FROM reviews r WHERE r.provider_id=p.id) AS avg_r,"
        " (SELECT COUNT(*) FROM requests rq WHERE rq.provider_id=p.id) AS n_b"
        " FROM providers p ORDER BY p.verified, p.business_name").fetchall()
    return render_template("admin_providers.html", providers=providers)

@app.route("/admin/providers/<int:pid>/toggle-verify", methods=["POST"])
@login_required
@role_required("admin")
def admin_provider_toggle(pid):
    me = current_user()
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    new = 0 if p["verified"] else 1
    db.execute("UPDATE providers SET verified=? WHERE id=?", (new, pid))
    db.commit()
    log_activity(me["name"], "verification",
                 f"{'Verified' if new else 'Unverified'} {p['business_name']}")
    flash(f"{p['business_name']} {'verified' if new else 'unverified'}.", "ok")
    return redirect(url_for("admin_providers"))

@app.route("/admin/providers/<int:pid>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_provider_delete(pid):
    me = current_user()
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    db.execute("DELETE FROM reviews WHERE provider_id=?", (pid,))
    db.execute("DELETE FROM requests WHERE provider_id=?", (pid,))
    db.execute("DELETE FROM favorites WHERE provider_id=?", (pid,))
    db.execute("DELETE FROM providers WHERE id=?", (pid,))
    db.commit()
    log_activity(me["name"], "provider_deleted", f"Deleted {p['business_name']}")
    flash(f"{p['business_name']} deleted with its bookings and reviews.", "ok")
    return redirect(url_for("admin_providers"))

@app.route("/admin/bookings")
@login_required
@role_required("admin")
def admin_bookings():
    status = request.args.get("status", "all")
    db = get_db()
    base = ("SELECT r.*, p.business_name, p.price_per_day, u.name AS tourist"
            " FROM requests r JOIN providers p ON p.id=r.provider_id"
            " JOIN users u ON u.id=r.tourist_id")
    if status in ("pending", "accepted", "declined", "completed", "cancelled"):
        rows = db.execute(base + " WHERE r.status=? ORDER BY r.id DESC",
                          (status,)).fetchall()
    else:
        status = "all"
        rows = db.execute(base + " ORDER BY r.id DESC").fetchall()
    return render_template("admin_bookings.html", rows=rows, status=status)

@app.route("/admin/reviews")
@login_required
@role_required("admin")
def admin_reviews():
    db = get_db()
    reviews = db.execute(
        "SELECT r.*, p.business_name, u.name AS tourist FROM reviews r"
        " JOIN providers p ON p.id=r.provider_id"
        " JOIN users u ON u.id=r.tourist_id"
        " ORDER BY r.id DESC").fetchall()
    return render_template("admin_reviews.html", reviews=reviews)

@app.route("/admin/reviews/<int:rid>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_review_delete(rid):
    me = current_user()
    db = get_db()
    r = db.execute("SELECT * FROM reviews WHERE id=?", (rid,)).fetchone()
    if not r:
        abort(404)
    db.execute("DELETE FROM reviews WHERE id=?", (rid,))
    db.commit()
    log_activity(me["name"], "review_deleted",
                 f"Deleted review #{rid} (provider #{r['provider_id']}): “{(r['comment'] or '')[:60]}”")
    flash("Review deleted.", "ok")
    return redirect(url_for("admin_reviews"))

@app.route("/admin/activity")
@login_required
@role_required("admin")
def admin_activity():
    """Full audit log, newest first, with action/actor filters + pagination."""
    action = clean(request.args.get("action", ""), 60)
    q = clean(request.args.get("q", ""), 80)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    page = max(1, page)
    per = 25
    db = get_db()
    where, args = [], []
    if action:
        where.append("action=?")
        args.append(action)
    if q:
        where.append("(actor LIKE ? OR detail LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.execute("SELECT COUNT(*) FROM activity_log" + clause, args).fetchone()[0]
    pages = max(1, (total + per - 1) // per)
    page = min(page, pages)
    rows = db.execute(
        "SELECT * FROM activity_log" + clause +
        " ORDER BY id DESC LIMIT ? OFFSET ?",
        args + [per, (page - 1) * per]).fetchall()
    actions = [r[0] for r in db.execute(
        "SELECT DISTINCT action FROM activity_log ORDER BY action")]
    return render_template("admin_activity.html", rows=rows, action=action, q=q,
                           page=page, pages=pages, total=total, actions=actions)

@app.route("/admin/messages")
@login_required
@role_required("admin")
def admin_messages():
    db = get_db()
    msgs = db.execute("SELECT * FROM messages ORDER BY id DESC").fetchall()
    return render_template("admin_messages.html", msgs=msgs)

@app.route("/admin/messages/<int:mid>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def admin_message_toggle(mid):
    db = get_db()
    m = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not m:
        abort(404)
    db.execute("UPDATE messages SET read=? WHERE id=?",
               (0 if m["read"] else 1, mid))
    db.commit()
    return redirect(url_for("admin_messages"))

@app.route("/admin/messages/<int:mid>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_message_delete(mid):
    me = current_user()
    db = get_db()
    m = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not m:
        abort(404)
    db.execute("DELETE FROM messages WHERE id=?", (mid,))
    db.commit()
    log_activity(me["name"], "message_deleted",
                 f"Deleted contact message #{mid} ({m['subject']} from {m['email']})")
    flash("Message deleted.", "ok")
    return redirect(url_for("admin_messages"))

# ==================================================================== main =
# Initialise the database at import time, not only under __main__: under
# gunicorn (Render) the module is imported, never run as __main__, so the
# tables would otherwise never be created and every page would fail.
init_db()
migrate_passwords()

# ------------------------------------------------------------------ vercel --
# Vercel rewrites every request to /api/index, so Flask sees that path
# instead of the real one and no route matches (every page 404s). This
# middleware restores the original path. It lives here, on the app object
# itself, so it applies no matter how the app is served (Vercel, gunicorn,
# or the local dev server) — wrapping it only in api/index.py was bypassed.
# The original path reaches us in one of two ways: Vercel's edge sets an
# X-Forwarded-Uri header, and vercel.json also passes it as a __path query
# parameter on the rewrite (see vercel.json).
from urllib.parse import unquote as _unquote
from urllib.parse import urlparse as _urlparse


class _RestoreOriginalPath:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        original = (
            environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("HTTP_X_VERCEL_REWRITE")
            or environ.get("HTTP_X_ORIGINAL_URL")
        )
        if not original:
            # Fall back to the __path query parameter set by vercel.json.
            qs = environ.get("QUERY_STRING", "")
            parts = qs.split("&") if qs else []
            kept = []
            for part in parts:
                if part.startswith("__path="):
                    original = part[len("__path="):]
                else:
                    kept.append(part)
            # Drop __path so Flask never sees it as a real query parameter.
            environ["QUERY_STRING"] = "&".join(kept)
        if original:
            # The __path value arrives URL-encoded (%2Flogin), so decode it.
            path = _urlparse(_unquote(original)).path or "/"
            environ["PATH_INFO"] = path
            environ["SCRIPT_NAME"] = ""
        elif environ.get("PATH_INFO", "").startswith("/api/index"):
            rest = environ["PATH_INFO"][len("/api/index"):]
            environ["PATH_INFO"] = rest or "/"
            environ["SCRIPT_NAME"] = ""
        return self.wsgi_app(environ, start_response)


app.wsgi_app = _RestoreOriginalPath(app.wsgi_app)

if __name__ == "__main__":
    print("NativeGo v2 running → http://localhost:5050")
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
