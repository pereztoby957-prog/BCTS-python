BCTS - Basic Computer Troubleshooting System (Python + MySQL)

One-time setup
  1. Install Python 3.10 or newer from https://python.org (tick "Add Python to PATH").
  2. In a terminal, inside this folder, run:   pip install -r requirements.txt

Every time you run it
  1. Open the XAMPP Control Panel and click Start next to MySQL.
  2. Run:   python server.py      (or double-click start.bat on Windows)
  3. Open http://localhost:3000

The database "bcts" is created automatically in MySQL. View it at
http://localhost/phpmyadmin (start Apache in XAMPP too). Tables: users, sessions, history.
If your MySQL root user has a password, set DB_PASSWORD (see the top of server.py).
If a bcts.db file from the older version is in this folder, its accounts and history
are imported into MySQL the first time the server starts.

CRUD features
  Create  - register an account; record a troubleshooting result
  Read    - view guides, your history, your profile
  Update  - edit your name, change your password, change a history result
  Delete  - delete one history entry, clear all history, delete your account
