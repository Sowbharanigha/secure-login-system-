from flask import Flask, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-local-development-key")

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def create_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

@app.route("/")
def home():
    if "user_id" in session:
        return """
        <h1>Welcome!</h1>
        <p>You are logged in.</p>
        <a href="/logout">Logout</a>
        """
    return """
    <h1>Secure Login System</h1>
    <a href="/register">Create Account</a><br><br>
    <a href="/login">Login</a>
    """

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            message = "Enter a valid email address."
        elif len(password) < 8:
            message = "Password must contain at least 8 characters."
        else:
            conn = get_db()
            try:
                hashed_password = generate_password_hash(password)
                conn.execute(
                    "INSERT INTO users (email, password) VALUES (?, ?)",
                    (email, hashed_password)
                )
                conn.commit()
                conn.close()
                return redirect("/login")
            except sqlite3.IntegrityError:
                conn.close()
                message = "This email is already registered."

    return """
    <h1>Create Account</h1>
    <p style="color:red;">""" + message + """</p>
    <form method="POST">
        <label>Email:</label><br>
        <input type="email" name="email" required><br><br>
        <label>Password (minimum 8 characters):</label><br>
        <input type="password" name="password" minlength="8" required><br><br>
        <button type="submit">Register</button>
    </form>
    <br><a href="/">Home</a>
    """

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect("/")
        message = "Invalid email or password."

    return """
    <h1>Login</h1>
    <p style="color:red;">""" + message + """</p>
    <form method="POST">
        <label>Email:</label><br>
        <input type="email" name="email" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <br><a href="/">Home</a>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    create_table()
    app.run(debug=True)
