"""Tests for the five FRs added after D4 (proposal Table 4.1):
FR-06 request messages, FR-08 reports, FR-11 verification uploads,
FR-12 availability, FR-18 admin report handling.
"""
import io
from datetime import date, timedelta

import pytest

import app as app_module
from conftest import (db_count, db_one, get_csrf, login, login_as_admin,
                      login_as_provider, login_as_tourist, post)

FUTURE_DATE = (date.today() + timedelta(days=30)).isoformat()


def _book(client, db_path, pid=1):
    resp = post(client, f"/request/{pid}", {
        "date": FUTURE_DATE, "guests": "2", "notes": "Test trip"},
        csrf_path="/provider/1")
    assert resp.status_code == 302
    return db_one(db_path,
                  "SELECT id FROM requests WHERE provider_id=? "
                  "AND status='pending' ORDER BY id DESC LIMIT 1",
                  (pid,))["id"]


def _report(client, db_path, pid=1, reason="No-show",
            details="Provider never turned up."):
    resp = post(client, f"/provider/{pid}/report", {
        "reason": reason, "details": details}, csrf_path=f"/provider/{pid}")
    assert resp.status_code == 302
    return db_one(db_path,
                  "SELECT * FROM reports ORDER BY id DESC LIMIT 1")


# ------------------------------------------------------------------ FR-06 ---
def test_request_message_thread_tourist_and_provider(client, db_path):
    login_as_tourist(client)
    rid = _book(client, db_path)
    resp = post(client, f"/booking/{rid}/message",
                {"body": "Hi, can we start at 7am?"},
                csrf_path=f"/booking/{rid}")
    assert resp.status_code == 302
    assert db_count(db_path,
                    "SELECT COUNT(*) FROM request_messages") == 1

    c2 = client.application.test_client()
    login_as_provider(c2)
    resp = post(c2, f"/booking/{rid}/message",
                {"body": "7am works, see you at the gate."},
                csrf_path=f"/booking/{rid}")
    assert resp.status_code == 302
    assert db_count(db_path,
                    "SELECT COUNT(*) FROM request_messages") == 2

    page = client.get(f"/booking/{rid}").get_data(as_text=True)
    assert "can we start at 7am?" in page
    assert "7am works" in page
    assert "💬 2 messages" in client.get("/my-requests").get_data(as_text=True)


def test_request_message_stranger_and_admin_cannot_post(client, db_path):
    login_as_tourist(client)
    rid = _book(client, db_path)

    c2 = client.application.test_client()
    login_as_admin(c2)  # admin may read the thread, not post to it
    resp = post(c2, f"/booking/{rid}/message", {"body": "Hello"},
                csrf_path="/login")  # /booking page has no form for admins
    assert resp.status_code == 404
    assert db_count(db_path,
                    "SELECT COUNT(*) FROM request_messages") == 0

    c3 = client.application.test_client()  # not logged in at all
    resp = c3.post(f"/booking/{rid}/message", data={"body": "Hello"})
    assert resp.status_code in (302, 400)  # login redirect or CSRF block


def test_request_message_empty_rejected(client, db_path):
    login_as_tourist(client)
    rid = _book(client, db_path)
    resp = post(client, f"/booking/{rid}/message", {"body": "   "},
                csrf_path=f"/booking/{rid}")
    assert resp.status_code == 302
    assert db_count(db_path,
                    "SELECT COUNT(*) FROM request_messages") == 0


# ------------------------------------------------------------------ FR-08 ---
def test_report_provider_creates_open_case(client, db_path):
    login_as_tourist(client)
    row = _report(client, db_path)
    assert row["status"] == "open" and row["action"] == ""
    assert row["reason"] == "No-show" and row["provider_id"] == 1
    assert row["reporter_id"] == 1
    assert "Report received" in client.get("/provider/1").get_data(as_text=True)
    assert client.get("/admin/reports").status_code == 403  # tourists kept out
    login_as_admin(client)
    page = client.get("/admin/reports").get_data(as_text=True)
    assert "No-show" in page and "Mara Savannah Safaris" in page


def test_report_bad_reason_or_short_details_rejected(client, db_path):
    login_as_tourist(client)
    _report(client, db_path, reason="Made up", details="Provider never turned up.")
    assert db_count(db_path, "SELECT COUNT(*) FROM reports") == 0
    _report(client, db_path, reason="No-show", details="ok")
    assert db_count(db_path, "SELECT COUNT(*) FROM reports") == 0


def test_report_provider_role_forbidden(client, db_path):
    login_as_provider(client)
    resp = post(client, "/provider/1/report",
                {"reason": "No-show", "details": "Testing."},
                csrf_path="/login")  # provider page has no form for providers
    assert resp.status_code == 403
    assert db_count(db_path, "SELECT COUNT(*) FROM reports") == 0


# ------------------------------------------------------------------ FR-11 ---
def test_provider_upload_doc_and_admin_can_view(client, db_path, tmp_path,
                                                monkeypatch):
    monkeypatch.setattr(app_module, "UPLOAD_DIR", str(tmp_path))
    login_as_provider(client)
    resp = post(client, "/dashboard/documents", {
        "doc_type": "National ID",
        "document": (io.BytesIO(b"%PDF-1.4 fake id"), "my-id.pdf")},
        csrf_path="/dashboard")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT * FROM verification_docs")
    assert row["doc_type"] == "National ID"
    assert row["original_name"] == "my-id.pdf"
    assert row["provider_id"] == 1
    assert (tmp_path / row["filename"]).exists()

    login_as_admin(client)
    page = client.get("/admin/verifications").get_data(as_text=True)
    assert "my-id.pdf" in page
    dl = client.get(f"/admin/verifications/doc/{row['id']}")
    assert dl.status_code == 200
    assert dl.get_data() == b"%PDF-1.4 fake id"


def test_provider_upload_bad_extension_rejected(client, db_path):
    login_as_provider(client)
    resp = post(client, "/dashboard/documents", {
        "doc_type": "Certificate",
        "document": (io.BytesIO(b"MZ..."), "evil.exe")},
        csrf_path="/dashboard")
    assert resp.status_code == 302
    assert db_count(db_path, "SELECT COUNT(*) FROM verification_docs") == 0
    assert "Only PDF, JPG and PNG" in client.get(
        "/dashboard").get_data(as_text=True)


# ------------------------------------------------------------------ FR-12 ---
def test_provider_sets_availability_shown_and_filtered(client, db_path):
    login_as_provider(client)
    resp = post(client, "/dashboard/availability", {
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
        "note": "8am-6pm EAT", "available": "1"},
        csrf_path="/dashboard")
    assert resp.status_code == 302
    row = db_one(db_path,
                 "SELECT available, availability_days, availability_note"
                 " FROM providers WHERE id=1")
    assert row["available"] == 1
    assert row["availability_days"] == "Mon,Tue,Wed,Thu,Fri"
    assert row["availability_note"] == "8am-6pm EAT"

    page = client.get("/provider/1").get_data(as_text=True)
    assert "Available Mon, Tue, Wed, Thu, Fri" in page
    assert "8am-6pm EAT" in page
    assert "Mara Savannah Safaris" in client.get(
        "/discover?available=1").get_data(as_text=True)

    # Switch off: hidden from the availability-filtered search, still listed.
    resp = post(client, "/dashboard/availability", {"days": [], "note": ""},
                csrf_path="/dashboard")
    assert resp.status_code == 302
    assert db_one(db_path,
                  "SELECT available FROM providers WHERE id=1")[0] == 0
    assert "Mara Savannah Safaris" not in client.get(
        "/discover?available=1").get_data(as_text=True)
    assert "Mara Savannah Safaris" in client.get(
        "/discover").get_data(as_text=True)
    assert "Currently not taking new bookings" in client.get(
        "/provider/1").get_data(as_text=True)


# ------------------------------------------------------------------ FR-18 ---
def test_admin_reports_dismiss_closes_case(client, db_path):
    login_as_tourist(client)
    row = _report(client, db_path)
    login_as_admin(client)
    resp = post(client, f"/admin/reports/{row['id']}/dismiss", {},
                csrf_path="/admin/reports")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT status, action FROM reports WHERE id=?",
                 (row["id"],))
    assert row["status"] == "closed" and row["action"] == "dismissed"


def test_admin_reports_warn_closes_case(client, db_path):
    login_as_tourist(client)
    row = _report(client, db_path)
    login_as_admin(client)
    resp = post(client, f"/admin/reports/{row['id']}/warn", {},
                csrf_path="/admin/reports")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT status, action FROM reports WHERE id=?",
                 (row["id"],))
    assert row["status"] == "closed" and row["action"] == "warning"


def test_admin_reports_suspend_deactivates_account(client, db_path):
    login_as_tourist(client)
    row = _report(client, db_path)  # provider 1, owned by david@demo.co.ke
    login_as_admin(client)
    resp = post(client, f"/admin/reports/{row['id']}/suspend", {},
                csrf_path="/admin/reports")
    assert resp.status_code == 302
    row = db_one(db_path, "SELECT status, action FROM reports WHERE id=?",
                 (row["id"],))
    assert row["status"] == "closed" and row["action"] == "suspended"
    assert db_one(db_path,
                  "SELECT active FROM users WHERE id=2")[0] == 0
    assert db_one(db_path,
                  "SELECT verified FROM providers WHERE id=1")[0] == 0
    # Suspended provider can no longer log in.
    c2 = client.application.test_client()
    resp = post(c2, "/login", {"email": "david@demo.co.ke",
                               "password": "demo123"})
    assert resp.status_code == 200
    assert "Wrong email or password" in resp.get_data(as_text=True)


def test_admin_reports_requires_admin(client, db_path):
    login_as_tourist(client)
    assert client.get("/admin/reports").status_code == 403
    c2 = client.application.test_client()  # anonymous -> login redirect
    assert c2.get("/admin/reports").status_code == 302


def test_admin_reports_open_count_on_overview(client, db_path):
    login_as_tourist(client)
    _report(client, db_path)
    login_as_admin(client)
    page = client.get("/admin").get_data(as_text=True)
    assert "open reports" in page
