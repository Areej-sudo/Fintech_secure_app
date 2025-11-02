from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import sqlite3
import os
import re
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = 'securekey123'  # change for production
bcrypt = Bcrypt(app)

# Encryption key (Fernet)
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Database file
DB_FILE = 'database.db'

# Create DB + users table if not exists
if not os.path.exists(DB_FILE):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until INTEGER DEFAULT 0
            )
        ''')
        conn.commit()


# ---------- Helpers ----------
def sanitize_input(value: str) -> str:
    if not value:
        return ""
    # remove script-angle brackets to reduce XSS vectors, then strip
    value = re.sub(r"[<>]", "", value)
    return value.strip()


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))


def validate_password(password: str) -> bool:
    # at least 8 chars, upper, lower, number, special
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$', password))


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            flash("Unauthorized access — please log in.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for('register'))

        if not validate_email(email):
            flash("Invalid email format.", "error")
            return redirect(url_for('register'))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))

        if not validate_password(password):
            flash("Weak password. Use 8+ chars with upper, lower, number and symbol.", "error")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_pw)
                )
                conn.commit()
            flash("Registration successful. You may now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        with sqlite3.connect(DB_FILE) as conn:
            user_row = conn.execute("SELECT id, username, email, password, failed_attempts, locked_until FROM users WHERE username=?",
                                    (username,)).fetchone()

            if not user_row:
                flash("User not found.", "error")
                return redirect(url_for('login'))

            uid, u, e, pw_hash, fails, locked_until = user_row

            # locked_until stored as epoch seconds; check lock
            now_ts = int(time.time())
            if locked_until and locked_until > now_ts:
                flash("Account temporarily locked due to repeated failed attempts. Try later.", "error")
                return redirect(url_for('login'))

            if bcrypt.check_password_hash(pw_hash, password):
                # successful login: reset counters
                conn.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?", (username,))
                conn.commit()
                session.permanent = True
                session['user'] = username
                session['last_active'] = int(time.time())
                flash(f"Welcome back, {username}!", "success")
                return redirect(url_for('dashboard'))
            else:
                # increment failures and possibly lock account
                fails = (fails or 0) + 1
                if fails >= 5:
                    lock_until = int(time.time()) + 60  # lock 60 seconds (adjust as needed)
                    conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?", (fails, lock_until, username))
                else:
                    conn.execute("UPDATE users SET failed_attempts=? WHERE username=?", (fails, username))
                conn.commit()
                flash("Invalid credentials.", "error")
                return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # session timeout check (optional): expire if idle > 5 minutes
    last = session.get('last_active', int(time.time()))
    now_ts = int(time.time())
    if now_ts - last > 300:
        session.pop('user', None)
        flash("Session expired due to inactivity. Please log in again.", "error")
        return redirect(url_for('login'))
    session['last_active'] = now_ts

    sample_data = [
        {"date": "2025-10-30", "desc": "Deposit", "amount": "+ $500"},
        {"date": "2025-10-28", "desc": "Withdrawal", "amount": "- $200"},
        {"date": "2025-10-25", "desc": "Deposit", "amount": "+ $800"},
    ]
    return render_template('dashboard.html', user=session.get('user'), data=sample_data)


@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt_data():
    text = sanitize_input(request.form.get('text', ''))
    if not text:
        flash("Please enter text to encrypt.", "error")
        return redirect(url_for('dashboard'))

    encrypted = fernet.encrypt(text.encode()).decode()
    # show encrypted on dashboard (include sample data so table renders)
    sample_data = [
        {"date": "2025-10-30", "desc": "Deposit", "amount": "+ $500"},
        {"date": "2025-10-28", "desc": "Withdrawal", "amount": "- $200"},
        {"date": "2025-10-25", "desc": "Deposit", "amount": "+ $800"},
    ]
    return render_template('dashboard.html', user=session.get('user'), data=sample_data, encrypted=encrypted)


@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt_data():
    text = sanitize_input(request.form.get('text', ''))
    if not text:
        flash("Please enter encrypted text to decrypt.", "error")
        return redirect(url_for('dashboard'))

    try:
        decrypted = fernet.decrypt(text.encode()).decode()
    except Exception:
        flash("Invalid encrypted text or tampered data.", "error")
        return redirect(url_for('dashboard'))

    sample_data = [
        {"date": "2025-10-30", "desc": "Deposit", "amount": "+ $500"},
        {"date": "2025-10-28", "desc": "Withdrawal", "amount": "- $200"},
        {"date": "2025-10-25", "desc": "Deposit", "amount": "+ $800"},
    ]
    return render_template('dashboard.html', user=session.get('user'), data=sample_data, decrypted=decrypted)


@app.route('/logout')
@login_required
def logout():
    session.pop('user', None)
    session.pop('last_active', None)
    flash("You have logged out successfully.", "success")
    return redirect(url_for('login'))


# ---------- Error handlers ----------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', message="An unexpected error occurred"), 500


# ---------- Run ----------
if __name__ == '__main__':
    app.run(debug=True)
