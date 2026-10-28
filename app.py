
import os
import re
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, g
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

DATABASE = os.environ.get("DATABASE_PATH", "users.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

with app.app_context():
    get_db().execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    get_db().commit()

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Authentication Lab</title>
<style>
body{font-family:Arial,sans-serif;max-width:440px;margin:50px auto;
padding:20px;background:#f3f6fb;color:#172554}
main{background:white;padding:25px;border-radius:14px}
input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0}
button{background:#1957c2;color:white;border:0;border-radius:6px}
a{color:#1957c2} .msg{overflow-wrap:anywhere}
</style>
</head>
<body><main>
<h1>{{ title }}</h1>
{% if message %}<p class="msg">{{ message }}</p>{% endif %}
{{ content|safe }}
</main></body></html>
"""

def page(title, content, message=""):
    return render_template_string(
        PAGE, title=title, content=content, message=message
    )

def csrf_field():
    from flask_wtf.csrf import generate_csrf
    return '<input type="hidden" name="csrf_token" value="' + \
        generate_csrf() + '">'

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            message = "Username must be 3–30 letters, numbers or underscores."
        elif len(password) < 12 or len(password) > 128:
            message = "Password must contain 12–128 characters."
        else:
            password_hash = generate_password_hash(password)
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                message = "That username is unavailable."

    form = f"""
    <p>Create an account. Use a unique password.</p>
    <form method="post">{csrf_field()}
    <label>Username</label>
    <input name="username" minlength="3" maxlength="30"
           pattern="[A-Za-z0-9_]+" required>
    <label>Password (12–128 characters)</label>
    <input type="password" name="password" minlength="12"
           maxlength="128" required>
    <button type="submit">Register</button></form>
    <p><a href="/login">Already registered? Log in</a></p>
    """
    return page("Create account", form, message)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        message = "Invalid username or password."

    form = f"""
    <form method="post">{csrf_field()}
    <label>Username</label>
    <input name="username" maxlength="30" required>
    <label>Password</label>
    <input type="password" name="password" maxlength="128" required>
    <button type="submit">Log in</button></form>
    <p><a href="/register">Create an account</a></p>
    """
    return page("Secure login", form, message)

@app.route("/dashboard")
@login_required
def dashboard():
    username = secrets.token_hex(1)  # replaced below with escaped text
    from markupsafe import escape
    username = escape(session.get("username", "User"))
    content = f"""
    <p>Welcome, <strong>{username}</strong>!</p>
    <p>You have successfully logged in.</p>
    <form method="post" action="/logout">{csrf_field()}
    <button type="submit">Log out</button></form>
    """
    return page("Dashboard", content)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=False)

    
