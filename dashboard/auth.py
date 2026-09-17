"""Dashboard authentication.

Deliberately minimal: one role ("analyst"), no OAuth, no password-reset
flow. Passwords are hashed with Werkzeug's `generate_password_hash`
(PBKDF2), which ships with Flask — no extra dependency.

There's no hardcoded default account. On first run, with zero users in
the database, every route redirects to /setup, which creates exactly one
analyst account and then behaves like a normal login from then on. This
avoids shipping (and forgetting to change) a well-known default
credential, which is the same advice this platform would flag if it saw
it in someone else's environment.
"""
from __future__ import annotations

from functools import wraps

from flask import g, redirect, session, url_for

from soc import database as db


def no_users_exist() -> bool:
    return db.count_users(g.db) == 0


def current_user() -> dict | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.get_user(g.db, user_id)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if no_users_exist():
            return redirect(url_for("setup"))
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped
