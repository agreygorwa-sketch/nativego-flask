"""Vercel entry point: exposes the NativeGo Flask app as a serverless function."""
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app


class RestoreOriginalPath:
    """Vercel rewrites every request to /api/index, so Flask sees that path
    instead of the real one and no route matches (every page 404s).
    Restore the original path from the header Vercel's edge network sets,
    so the app's routes can match again."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # Try the headers a proxy may use for the original request URI.
        original = (
            environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("HTTP_X_VERCEL_REWRITE")
            or environ.get("HTTP_X_ORIGINAL_URL")
        )
        if original:
            path = urlparse(original).path or "/"
            environ["PATH_INFO"] = path
            environ["SCRIPT_NAME"] = ""
        elif environ.get("PATH_INFO", "").startswith("/api/index"):
            # No header: at least strip the rewrite prefix so "/" works.
            rest = environ["PATH_INFO"][len("/api/index"):]
            environ["PATH_INFO"] = rest or "/"
            environ["SCRIPT_NAME"] = ""
        return self.wsgi_app(environ, start_response)


app.wsgi_app = RestoreOriginalPath(app.wsgi_app)
