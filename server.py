"""BCTS server (Python + MySQL).
Serves the website files in this folder and stores accounts, sessions and history in MySQL (XAMPP).
Run:  python server.py     then open http://localhost:3000
Needs: pip install mysql-connector-python   and MySQL started in the XAMPP Control Panel.
"""
import hashlib, hmac, json, os, re, secrets, sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
import mysql.connector

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", 3000))
DB_NAME = os.environ.get("DB_NAME", "bcts")
# XAMPP defaults: user "root", empty password. Change here (or with environment variables) if yours differ.
DB = dict(host=os.environ.get("DB_HOST", "localhost"), port=int(os.environ.get("DB_PORT", 3306)),
          user=os.environ.get("DB_USER", "root"), password=os.environ.get("DB_PASSWORD", ""))

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(190) PRIMARY KEY, name VARCHAR(100) NOT NULL, salt VARCHAR(64),
        password_hash VARCHAR(128) NOT NULL DEFAULT '', provider VARCHAR(20), joined VARCHAR(30) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token VARCHAR(64) PRIMARY KEY, email VARCHAR(190) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS history (
        id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(190) NOT NULL, title VARCHAR(150), category VARCHAR(30),
        result VARCHAR(20), date VARCHAR(30),
        FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]

def q(sql, args=()):
    """Run one SQL statement. Returns (rows, rowcount, lastrowid)."""
    c = mysql.connector.connect(database=DB_NAME, **DB)
    try:
        cur = c.cursor(dictionary=True)
        cur.execute(sql, args)
        rows = cur.fetchall() if cur.with_rows else []
        c.commit()
        return rows, cur.rowcount, cur.lastrowid
    finally:
        c.close()

def one(sql, args=()):
    rows = q(sql, args)[0]
    return rows[0] if rows else None

def setup():
    c = mysql.connector.connect(**DB)
    c.cursor().execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4")
    c.close()
    for stmt in SCHEMA:
        q(stmt)
    # One-time import of the old SQLite database (bcts.db), if present and MySQL is still empty
    old = os.path.join(ROOT, "bcts.db")
    if os.path.exists(old) and not one("SELECT 1 FROM users LIMIT 1"):
        import sqlite3
        s = sqlite3.connect(old); s.row_factory = sqlite3.Row
        for u in s.execute("SELECT * FROM users"):
            q("INSERT INTO users (email, name, salt, password_hash, provider, joined) VALUES (%s,%s,%s,%s,%s,%s)",
              (u["email"], u["name"], u["salt"], u["password_hash"], u["provider"], u["joined"]))
        for h in s.execute("SELECT * FROM history ORDER BY id"):
            q("INSERT INTO history (email, title, category, result, date) VALUES (%s,%s,%s,%s,%s)",
              (h["email"], h["title"], h["category"], h["result"], h["date"]))
        s.close()
        print("Imported your accounts and history from bcts.db into MySQL.")

# ---------- Helpers ----------
def pw_hash(pw, salt):  # same scrypt settings as the old Node version, so old passwords still work
    return hashlib.scrypt(pw.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32).hex()

def pw_ok(pw, user):
    return bool(user["password_hash"]) and hmac.compare_digest(pw_hash(pw, user["salt"]), user["password_hash"])

# Accepted email providers (add more here). School emails (.edu / .edu.ph) are also accepted.
DOMAINS = {"gmail.com", "googlemail.com", "yahoo.com", "yahoo.com.ph", "ymail.com", "outlook.com", "outlook.ph",
           "hotmail.com", "live.com", "msn.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com"}

def valid_email(e):
    if not re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+", e):
        return False
    d = e.split("@")[1]
    return d in DOMAINS or re.search(r"\.edu(\.[a-z]{2})?$", d) is not None

def start_session(u):
    token = secrets.token_hex(24)
    q("INSERT INTO sessions (token, email) VALUES (%s,%s)", (token, u["email"]))
    return 200, {"token": token, "user": {"name": u["name"], "email": u["email"], "joined": u["joined"]}}

def new_user(email, name, pw, provider):
    salt, joined = secrets.token_hex(16), datetime.now().strftime("%B %Y")
    q("INSERT INTO users (email, name, salt, password_hash, provider, joined) VALUES (%s,%s,%s,%s,%s,%s)",
      (email, name, salt, pw_hash(pw, salt), provider, joined))
    return {"email": email, "name": name, "joined": joined}

def err(msg, code=400):
    return code, {"error": msg}

# ---------- API ----------
def api(method, path, b, tok):
    email = str(b.get("email") or "").strip().lower()
    key = f"{method} {path}"
    if key == "POST /api/register":
        name, pw = str(b.get("name") or "").strip(), str(b.get("password") or "")
        if not name: return err("Enter your full name.")
        if not valid_email(email): return err("Use a valid email from a real provider, e.g. name@gmail.com.")
        if len(pw) < 6: return err("Use at least 6 characters for your password.")
        if one("SELECT 1 FROM users WHERE email=%s", (email,)): return err("An account with this email already exists. Try logging in.", 409)
        return start_session(new_user(email, name, pw, None))
    if key == "POST /api/login":
        u = one("SELECT * FROM users WHERE email=%s", (email,))
        if not u or not pw_ok(str(b.get("password") or ""), u): return err("Email or password is incorrect.")
        return start_session(u)
    if key == "POST /api/social":  # DEMO: not real Google/Facebook; the account has its own password
        pw = str(b.get("password") or "")
        if b.get("provider") not in ("google", "facebook") or not valid_email(email): return err("Enter a valid email address.")
        u = one("SELECT * FROM users WHERE email=%s", (email,))
        if not u:
            if len(pw) < 6: return err("Use at least 6 characters for the password.")
            return start_session(new_user(email, email.split("@")[0], pw, b["provider"]))
        if not u["password_hash"]: return err("This account was made without a password. Use another email.")
        if not pw_ok(pw, u): return err("Email or password is incorrect.")
        return start_session(u)
    if key == "POST /api/logout":
        q("DELETE FROM sessions WHERE token=%s", (tok,)); return 200, {}

    me = one("SELECT u.* FROM users u JOIN sessions s ON s.email=u.email WHERE s.token=%s", (tok,))
    if not me: return err("Not logged in.", 401)
    e = me["email"]
    if key == "GET /api/history":
        return 200, {"history": q("SELECT id, title, category, result, date FROM history WHERE email=%s ORDER BY id DESC", (e,))[0]}
    if key == "POST /api/history":    # CREATE
        _, _, new_id = q("INSERT INTO history (email, title, category, result, date) VALUES (%s,%s,%s,%s,%s)",
                         (e, str(b.get("title")), str(b.get("category")), str(b.get("result")), str(b.get("date"))))
        return 200, {"id": new_id}
    if key == "DELETE /api/history":
        q("DELETE FROM history WHERE email=%s", (e,)); return 200, {}
    if key == "PUT /api/profile":     # UPDATE name
        name = str(b.get("name") or "").strip()
        if not name or len(name) > 60: return err("Enter your full name (up to 60 characters).")
        q("UPDATE users SET name=%s WHERE email=%s", (name, e))
        return 200, {"user": {"name": name, "email": e, "joined": me["joined"]}}
    if key == "PUT /api/password":    # UPDATE password
        cur, new = str(b.get("currentPassword") or ""), str(b.get("newPassword") or "")
        if not pw_ok(cur, me): return err("Your current password is incorrect.")
        if len(new) < 6: return err("Use at least 6 characters for the new password.")
        salt = secrets.token_hex(16)
        q("UPDATE users SET salt=%s, password_hash=%s WHERE email=%s", (salt, pw_hash(new, salt), e))
        q("DELETE FROM sessions WHERE email=%s AND token<>%s", (e, tok))  # log out other devices
        return 200, {}
    if key == "DELETE /api/account":  # DELETE account (sessions + history removed by ON DELETE CASCADE)
        if not pw_ok(str(b.get("password") or ""), me): return err("Your password is incorrect.")
        q("DELETE FROM users WHERE email=%s", (e,)); return 200, {}
    m = re.fullmatch(r"/api/history/(\d+)", path)
    if m and method == "PUT":         # UPDATE one history result
        result = str(b.get("result") or "")
        if result not in ("Resolved", "Not Resolved"): return err("Result must be Resolved or Not Resolved.")
        n = q("UPDATE history SET result=%s WHERE id=%s AND email=%s", (result, int(m[1]), e))[1]
        return (200, {}) if n else err("Entry not found.", 404)
    if m and method == "DELETE":      # DELETE one history entry
        n = q("DELETE FROM history WHERE id=%s AND email=%s", (int(m[1]), e))[1]
        return (200, {}) if n else err("Entry not found.", 404)
    return err("Not found", 404)

# ---------- Web server ----------
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8", ".png": "image/png"}

class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def handle_any(self, method):
        path = self.path.split("?")[0]
        if not path.startswith("/api/"):
            if method != "GET": return self.send(405, b"Method not allowed", "text/plain")
            name = os.path.basename(unquote(path)) or "login.html"
            f, ext = os.path.join(ROOT, name), os.path.splitext(name)[1]
            if ext not in TYPES or not os.path.isfile(f): return self.send(404, b"Not found", "text/plain")
            with open(f, "rb") as fh: return self.send(200, fh.read(), TYPES[ext])
        try:
            size = int(self.headers.get("Content-Length") or 0)
            try: b = json.loads(self.rfile.read(size) or b"{}")
            except ValueError: b = {}
            if not isinstance(b, dict): b = {}
            tok = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            code, obj = api(method, path, b, tok)
        except mysql.connector.Error as ex:
            print("MySQL error:", ex); code, obj = 500, {"error": "Database error. Is MySQL running in XAMPP?"}
        except Exception as ex:
            print("Error:", ex); code, obj = 500, {"error": "Server error."}
        self.send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")
    def do_PUT(self): self.handle_any("PUT")
    def do_DELETE(self): self.handle_any("DELETE")
    def log_message(self, *a): pass

if __name__ == "__main__":
    try:
        setup()
    except mysql.connector.Error as ex:
        print("Could not connect to MySQL:", ex)
        print("-> Open the XAMPP Control Panel and click Start next to MySQL, then run this again.")
        sys.exit(1)
    print(f"BCTS running at http://localhost:{PORT}  (MySQL database: {DB_NAME})")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()
