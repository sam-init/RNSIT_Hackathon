"""
==========================================================
  LIBRARY MANAGEMENT SYSTEM — VULNERABLE VERSION
  ⚠️  FOR AI-DRIVEN CODE REVIEW TESTING ONLY ⚠️
  DO NOT DEPLOY IN PRODUCTION
==========================================================
Intentional vulnerabilities embedded for PR diff analysis:
  [V1]  Hardcoded Secret Key
  [V2]  Insecure Relative DB Path
  [V3]  SQL Injection (Search, Delete, Borrow)
  [V4]  Broken Access Control (No Auth on Admin Routes)
  [V5]  Insecure Deserialization via pickle (RCE)
  [V6]  Sensitive Information Exposure (/debug)
  [V7]  Code Smell — Business Logic in Route Layer
  [V8]  Debug Mode in Production (app.run)
  [V9]  XSS via unescaped template rendering
  [V10] Path Traversal on File Download
  [V11] IDOR (Insecure Direct Object Reference) on User Profile
  [V12] Missing Rate Limiting (Brute-force friendly)
==========================================================
"""

import os
import sqlite3
import pickle
import base64
import subprocess
from flask import Flask, request, render_template_string, redirect, session, send_file

app = Flask(__name__)

# ---------------------------------------------------------------
# [V1] HARDCODED SECRET KEY — Never hardcode secrets in source.
#      Attacker can forge Flask session cookies with this key.
# ---------------------------------------------------------------
app.config['SECRET_KEY'] = "super-secret-key-12345"


# ---------------------------------------------------------------
# [V2] INSECURE DB PATH — Relative path breaks when the working
#      directory changes (e.g., running as a service). Also no
#      WAL mode, no timeout, no row_factory set.
# ---------------------------------------------------------------
def get_db_connection():
    conn = sqlite3.connect('library.db')   # relative path — fragile
    return conn


def init_db():
    """Initialize the database with sample data."""
    conn = get_db_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS books (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            title    TEXT NOT NULL,
            author   TEXT NOT NULL,
            genre    TEXT,
            copies   INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,       -- [V12-related] stored as plain text
            role     TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS borrows (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            book_id   INTEGER,
            due_date  TEXT
        );
        INSERT OR IGNORE INTO books (title, author, genre, copies)
        VALUES
            ('The Great Gatsby', 'F. Scott Fitzgerald', 'Fiction', 3),
            ('Clean Code', 'Robert C. Martin', 'Technology', 2),
            ('1984', 'George Orwell', 'Dystopian', 5),
            ('Python Crash Course', 'Eric Matthes', 'Technology', 4),
            ('Dune', 'Frank Herbert', 'Sci-Fi', 2);
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES
            ('admin', 'admin123', 'admin'),
            ('alice', 'password', 'user'),
            ('bob',   'bob123',   'user');
    """)
    conn.commit()
    conn.close()


# ======================== TEMPLATES ========================

HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Library Management System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1   { color: #333; }
        nav a { margin-right: 15px; color: #0066cc; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <h1>📚 Library Management System</h1>
    <nav>
        <a href="/">Home</a>
        <a href="/books">All Books</a>
        <a href="/search">Search</a>
        <a href="/login">Login</a>
        <a href="/borrow">Borrow</a>
        <a href="/admin/dashboard">Admin</a>
    </nav>
    <div class="card">
        <h2>Welcome to the Library</h2>
        <p>Browse our collection, search for books, and manage your borrowings.</p>
    </div>
</body>
</html>
"""

BOOKS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>All Books</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #0066cc; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
    </style>
</head>
<body>
    <h1>📖 All Books</h1>
    <a href="/">← Back Home</a>
    <br><br>
    <table>
        <tr><th>ID</th><th>Title</th><th>Author</th><th>Genre</th><th>Copies</th></tr>
        {% for book in books %}
        <tr>
            <td>{{ book[0] }}</td>
            <td>{{ book[1] }}</td>
            <td>{{ book[2] }}</td>
            <td>{{ book[3] }}</td>
            <td>{{ book[4] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

# [V9] XSS — `search_result` is injected directly via |safe, allowing stored/reflected XSS
SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Books</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        input, button { padding: 8px 12px; font-size: 14px; }
        button { background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .result { background: white; padding: 15px; margin-top: 20px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <h1>🔍 Search Books</h1>
    <a href="/">← Back Home</a>
    <br><br>
    <form method="GET" action="/search">
        <input type="text" name="title" placeholder="Enter book title..." value="{{ query }}">
        <button type="submit">Search</button>
    </form>
    {% if search_result %}
    <div class="result">
        <!-- [V9] Unescaped output — XSS possible -->
        <p>{{ search_result | safe }}</p>
    </div>
    {% endif %}
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; display: flex; justify-content: center; }
        .box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); width: 320px; }
        input { width: 100%; padding: 8px; margin: 8px 0 16px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }
        .error { color: red; font-size: 13px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>🔐 Login</h2>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form method="POST" action="/login">
            <label>Username</label>
            <input type="text" name="username" required>
            <label>Password</label>
            <input type="password" name="password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""


# ======================== ROUTES ========================

@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE)


@app.route('/books')
def list_books():
    conn = get_db_connection()
    books = conn.execute("SELECT * FROM books").fetchall()
    conn.close()
    return render_template_string(BOOKS_TEMPLATE, books=books)


# ---------------------------------------------------------------
# [V3] SQL INJECTION — User input directly interpolated into SQL.
#      Payload: ' OR '1'='1  → dumps all rows.
#      Payload: ' UNION SELECT username,password,3,4,5 FROM users--
# ---------------------------------------------------------------
@app.route('/search', methods=['GET'])
def search_books():
    title = request.args.get('title', '')
    conn = get_db_connection()
    cursor = conn.cursor()

    # Vulnerable query — never do this
    query = f"SELECT * FROM books WHERE title = '{title}'"
    cursor.execute(query)

    books = cursor.fetchall()
    conn.close()

    if books:
        # [V9] XSS: result piped through |safe in template
        result = "<br>".join(
            f"<b>{b[1]}</b> by {b[2]} (Genre: {b[3]}, Copies: {b[4]})"
            for b in books
        )
        search_result = f"Results for '<b>{title}</b>':<br>{result}"
    else:
        search_result = f"No books found for '{title}'."

    return render_template_string(SEARCH_TEMPLATE, query=title, search_result=search_result)


# ---------------------------------------------------------------
# [V12] NO RATE LIMITING — Brute-force login is trivial.
#       Passwords are stored in plaintext in the DB (see init_db).
# ---------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()

        # [V3-b] SQL Injection also here
        user = conn.execute(
            f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        ).fetchone()
        conn.close()

        if user:
            session['user_id']  = user[0]
            session['username'] = user[1]
            session['role']     = user[3]
            return redirect('/')
        else:
            error = "Invalid credentials."
    return render_template_string(LOGIN_TEMPLATE, error=error)


# ---------------------------------------------------------------
# [V3-c] SQL Injection on Borrow route
# [V7]   Business logic (due date calc, copy check) inlined in route
# ---------------------------------------------------------------
@app.route('/borrow', methods=['GET', 'POST'])
def borrow_book():
    message = ""
    if request.method == 'POST':
        book_id = request.form.get('book_id')
        user_id = request.form.get('user_id')
        due_date = request.form.get('due_date')

        conn = get_db_connection()
        # [V3-c] No parameterisation
        conn.execute(
            f"INSERT INTO borrows (user_id, book_id, due_date) "
            f"VALUES ({user_id}, {book_id}, '{due_date}')"
        )
        conn.commit()
        conn.close()
        message = "Book borrowed successfully!"

    return f"""
    <h2>Borrow a Book</h2>
    <form method='POST'>
        Book ID:  <input name='book_id'><br>
        User ID:  <input name='user_id'><br>
        Due Date: <input name='due_date' type='date'><br>
        <button type='submit'>Borrow</button>
    </form>
    <p>{message}</p>
    """


# ---------------------------------------------------------------
# [V4] BROKEN ACCESS CONTROL — No authentication or role check.
#      Any anonymous user can POST to delete any book.
# [V3-d] SQL Injection on delete as well.
# ---------------------------------------------------------------
@app.route('/admin/delete-book', methods=['GET', 'POST'])
def delete_book():
    if request.method == 'POST':
        book_id = request.form.get('id')
        conn = get_db_connection()
        # Vulnerable: no parameterisation + no auth check
        conn.execute(f"DELETE FROM books WHERE id = {book_id}")
        conn.commit()
        conn.close()
        return "✅ Book deleted successfully."

    return """
    <h2>Delete a Book (Admin)</h2>
    <form method='POST'>
        Book ID: <input name='id' type='number' required>
        <button type='submit' style='background:red;color:white;padding:6px 12px;border:none;'>Delete</button>
    </form>
    """


# ---------------------------------------------------------------
# [V4-b] Admin Dashboard — No role or auth check whatsoever
# ---------------------------------------------------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    # Should check: if session.get('role') != 'admin': abort(403)
    conn = get_db_connection()
    books = conn.execute("SELECT * FROM books").fetchall()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()

    book_rows = "".join(
        f"<tr><td>{b[0]}</td><td>{b[1]}</td><td>{b[2]}</td><td>{b[4]}</td></tr>"
        for b in books
    )
    user_rows = "".join(
        f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td></tr>"
        for u in users
    )

    return f"""
    <h1>🛠 Admin Dashboard</h1>
    <h3>Books</h3>
    <table border='1'><tr><th>ID</th><th>Title</th><th>Author</th><th>Copies</th></tr>
    {book_rows}
    </table>
    <br>
    <a href='/admin/delete-book'>Delete a Book</a>
    <h3>Users (⚠️ Exposed — no auth check)</h3>
    <table border='1'><tr><th>ID</th><th>Username</th><th>Role</th></tr>
    {user_rows}
    </table>
    """


# ---------------------------------------------------------------
# [V5] INSECURE DESERIALIZATION — Accepts base64-encoded pickle
#      from untrusted user input. Allows full Remote Code Execution.
#      e.g.: pickle.loads can execute os.system('calc.exe')
# ---------------------------------------------------------------
@app.route('/backup', methods=['POST'])
def restore_backup():
    data = request.form.get('backup_data')
    try:
        decoded_data = base64.b64decode(data)
        # ⚠️ RCE: attacker can craft a malicious pickle payload
        state = pickle.loads(decoded_data)
        return f"Backup restored. State: {str(state)}"
    except Exception as e:
        return f"Error restoring backup: {str(e)}", 500


# ---------------------------------------------------------------
# [V6] SENSITIVE INFORMATION EXPOSURE — Dumps ALL environment
#      variables (DB URLs, API keys, secrets) to any HTTP client.
# ---------------------------------------------------------------
@app.route('/debug')
def debug_info():
    sys_info = {
        "environment": dict(os.environ),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }
    return str(sys_info)


# ---------------------------------------------------------------
# [V10] PATH TRAVERSAL — `filename` param not sanitised.
#       Attacker can request: /download?file=../../etc/passwd
# ---------------------------------------------------------------
@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    # No sanitisation — allows directory traversal
    filepath = os.path.join('uploads', filename)
    return send_file(filepath)


# ---------------------------------------------------------------
# [V11] IDOR — User profile fetched by raw user-supplied `id`.
#       Attacker can enumerate any user's data by changing the id.
# ---------------------------------------------------------------
@app.route('/profile')
def user_profile():
    user_id = request.args.get('id')     # No session check
    conn = get_db_connection()
    # Also injectable
    user = conn.execute(
        f"SELECT id, username, role FROM users WHERE id = {user_id}"
    ).fetchone()
    conn.close()
    if user:
        return f"User #{user[0]}: {user[1]} (role: {user[2]})"
    return "User not found.", 404


# ---------------------------------------------------------------
# [V7-b] CODE SMELL + COMMAND INJECTION — os.popen / subprocess
#         with user-supplied input is never safe.
# ---------------------------------------------------------------
@app.route('/report')
def generate_report():
    fmt = request.args.get('format', 'txt')
    # Direct shell injection possible: ?format=txt; rm -rf /
    output = subprocess.check_output(
        f"echo 'Library Report' > report.{fmt} && cat report.{fmt}",
        shell=True   # shell=True with user input = command injection
    )
    return output.decode()


# ======================== STARTUP ========================

if __name__ == "__main__":
    init_db()
    # [V8] debug=True exposes Werkzeug interactive debugger (allows
    #      arbitrary Python execution). host='0.0.0.0' exposes to
    #      all network interfaces — dangerous on public machines.
    app.run(host='0.0.0.0', port=5000, debug=True)
