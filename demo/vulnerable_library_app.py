"""
Intentionally vulnerable Flask application used as a demo target for ph.

This file is not production code. It exists so judges can immediately see the
types of issues the review agents are meant to catch inside a pull request.
"""

from pathlib import Path
import base64
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, redirect, render_template_string, request, send_file, session

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key-12345"

DB_PATH = Path(__file__).resolve().with_name("library.db")


def get_db_connection() -> sqlite3.Connection:
    """Keep the fixture database local to the demo folder."""
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    """Create a tiny fixture database for demos."""
    conn = get_db_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            genre TEXT,
            copies INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        INSERT OR IGNORE INTO books (id, title, author, genre, copies) VALUES
            (1, 'Clean Code', 'Robert C. Martin', 'Technology', 2),
            (2, 'Dune', 'Frank Herbert', 'Sci-Fi', 2),
            (3, '1984', 'George Orwell', 'Dystopian', 5);
        INSERT OR IGNORE INTO users (id, username, password, role) VALUES
            (1, 'admin', 'admin123', 'admin'),
            (2, 'alice', 'password', 'user');
        """
    )
    conn.commit()
    conn.close()


HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerable Library App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f7f7f7; }
        .card { background: white; padding: 24px; border-radius: 12px; max-width: 700px; }
        nav a { margin-right: 12px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Vulnerable Library App</h1>
        <p>This app is intentionally insecure and should only be used for demos.</p>
        <nav>
            <a href="/">Home</a>
            <a href="/books">Books</a>
            <a href="/search">Search</a>
            <a href="/login">Login</a>
            <a href="/admin/dashboard">Admin</a>
        </nav>
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HOME_TEMPLATE)


@app.route("/books")
def list_books():
    conn = get_db_connection()
    books = conn.execute("SELECT * FROM books").fetchall()
    conn.close()
    rows = "".join(
        f"<tr><td>{book[0]}</td><td>{book[1]}</td><td>{book[2]}</td><td>{book[4]}</td></tr>"
        for book in books
    )
    return (
        "<h1>Books</h1>"
        "<table border='1'><tr><th>ID</th><th>Title</th><th>Author</th><th>Copies</th></tr>"
        f"{rows}</table>"
    )


@app.route("/search")
def search_books():
    title = request.args.get("title", "")
    conn = get_db_connection()
    query = f"SELECT * FROM books WHERE title = '{title}'"
    books = conn.execute(query).fetchall()
    conn.close()

    if books:
        result = "<br>".join(f"<b>{book[1]}</b> by {book[2]}" for book in books)
        return f"<h1>Search</h1><p>Results for <b>{title}</b>:</p><div>{result}</div>"
    return f"<h1>Search</h1><p>No books found for '{title}'.</p>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = get_db_connection()
        user = conn.execute(
            f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        ).fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            return redirect("/")
        return "<p>Invalid credentials.</p>", 401

    return """
    <h1>Login</h1>
    <form method="POST">
        <input name="username" placeholder="Username">
        <input name="password" placeholder="Password" type="password">
        <button type="submit">Login</button>
    </form>
    """


@app.route("/admin/dashboard")
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    rows = "".join(f"<li>{user[0]} - {user[1]} ({user[2]})</li>" for user in users)
    return f"<h1>Admin Dashboard</h1><ul>{rows}</ul>"


@app.route("/admin/delete-book", methods=["POST"])
def delete_book():
    book_id = request.form.get("id")
    conn = get_db_connection()
    conn.execute(f"DELETE FROM books WHERE id = {book_id}")
    conn.commit()
    conn.close()
    return "Book deleted"


@app.route("/backup", methods=["POST"])
def restore_backup():
    data = request.form.get("backup_data", "")
    decoded = base64.b64decode(data)
    state = pickle.loads(decoded)
    return f"Backup restored: {state}"


@app.route("/debug")
def debug_info():
    return {
        "environment": dict(os.environ),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    return send_file(Path("uploads") / filename)


@app.route("/report")
def generate_report():
    fmt = request.args.get("format", "txt")
    output = subprocess.check_output(
        f"echo 'Library Report' > report.{fmt} && cat report.{fmt}",
        shell=True,
    )
    return output.decode()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
