"""Vercel entry point: exposes the NativeGo Flask app as a serverless function."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app
