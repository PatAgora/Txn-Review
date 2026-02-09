import os, sqlite3, csv, io, json
import stat
from datetime import datetime, date, timedelta
from collections import defaultdict
from datetime import date, timedelta
import ast
import math
import json
import re
import smtplib
import secrets
import hashlib
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import qrcode
from io import BytesIO

from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, flash, abort, session, Response

from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

DB_PATH = os.getenv("TX_DB") or os.path.abspath(os.path.join(os.path.dirname(__file__), "tx.db"))
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# ---------- Database Security Hardening ----------
# Encryption key derived from environment or generated
DB_ENCRYPTION_KEY = os.getenv("DB_ENCRYPTION_KEY", "")
ENCRYPT_SENSITIVE_FIELDS = True  # Enable field-level encryption for sensitive data


def _get_encryption_key() -> bytes:
    """Derive a Fernet encryption key from the configured secret."""
    key_source = DB_ENCRYPTION_KEY or app.secret_key
    if isinstance(key_source, str):
        key_source = key_source.encode()
    
    # Use PBKDF2 to derive a proper Fernet key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'tx_review_tool_salt_v1',  # Static salt - key_source provides entropy
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key_source))
    return key


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string value for storage."""
    if not plaintext or not ENCRYPT_SENSITIVE_FIELDS:
        return plaintext
    try:
        f = Fernet(_get_encryption_key())
        return "ENC:" + f.encrypt(plaintext.encode()).decode()
    except Exception:
        return plaintext


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a stored encrypted value."""
    if not ciphertext or not ciphertext.startswith("ENC:"):
        return ciphertext
    try:
        f = Fernet(_get_encryption_key())
        return f.decrypt(ciphertext[4:].encode()).decode()
    except Exception:
        return ciphertext  # Return as-is if decryption fails


def secure_database_file(db_path: str):
    """
    Apply security hardening to the database file:
    - Set restrictive file permissions (owner read/write only)
    - Verify file is not in web-accessible directory
    """
    if not os.path.exists(db_path):
        return
    
    try:
        # Set file permissions to 600 (owner read/write only)
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
        
        # Also secure the WAL and SHM files if they exist (SQLite journal files)
        for ext in ['-wal', '-shm', '-journal']:
            journal_path = db_path + ext
            if os.path.exists(journal_path):
                os.chmod(journal_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        print(f"Warning: Could not set database file permissions: {e}")


def verify_db_path_security(db_path: str) -> list:
    """
    Security checks for database path.
    Returns list of warnings (empty if all checks pass).
    """
    warnings = []
    
    # Check 1: Database should not be in static/templates directories
    dangerous_dirs = ['static', 'templates', 'public', 'www', 'html']
    db_dir = os.path.dirname(os.path.abspath(db_path)).lower()
    for danger in dangerous_dirs:
        if danger in db_dir:
            warnings.append(f"Database is in potentially web-accessible directory containing '{danger}'")
    
    # Check 2: Database file should not be world-readable
    if os.path.exists(db_path):
        mode = os.stat(db_path).st_mode
        if mode & stat.S_IROTH:  # World readable
            warnings.append("Database file is world-readable")
        if mode & stat.S_IWOTH:  # World writable
            warnings.append("Database file is world-writable")
    
    # Check 3: Parent directory should not be world-writable
    parent_dir = os.path.dirname(os.path.abspath(db_path))
    if os.path.exists(parent_dir):
        parent_mode = os.stat(parent_dir).st_mode
        if parent_mode & stat.S_IWOTH:
            warnings.append("Database parent directory is world-writable")
    
    return warnings

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))


# ---------- WSGI Middleware: Strip Server Header ----------
class StripServerHeader:
    """WSGI middleware that overrides the Server header on every response,
    including static files, at the WSGI layer before the reverse proxy."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            # Remove any existing Server header and replace with ours
            headers = [(k, v) for k, v in headers if k.lower() != 'server']
            headers.append(('Server', 'Scrutinise'))
            return start_response(status, headers, exc_info)
        return self.app(environ, custom_start_response)

app.wsgi_app = StripServerHeader(app.wsgi_app)

# ---------- CREST Security Configuration ----------
# Session configuration
app.config['SESSION_COOKIE_SECURE'] = not os.getenv('FLASK_DEBUG')  # HTTPS only (disable only for local debug)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# Security constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
PASSWORD_MIN_LENGTH = 10
COMMON_PASSWORDS = {'password', 'password123', 'admin123', '123456789', 'qwerty123', 'letmein123'}


# ---------- CSRF Protection ----------
def generate_csrf_token():
    """Generate or return existing CSRF token for the current session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.before_request
def csrf_protect():
    """Validate CSRF token on all POST requests."""
    if request.method == "POST":
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            abort(403)


# ---------- Robots.txt (ensures our security headers apply) ----------
@app.route('/robots.txt')
def robots_txt():
    resp = Response("User-agent: *\nDisallow: /\n", mimetype='text/plain')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

# ---------- Error handlers (ensure headers on 404/500 too) ----------
@app.errorhandler(404)
def not_found(e):
    return Response("Not Found", status=404, mimetype='text/plain')

@app.errorhandler(500)
def server_error(e):
    return Response("Internal Server Error", status=500, mimetype='text/plain')

# ---------- Security Headers (ZAP Remediation) ----------
@app.after_request
def set_security_headers(response):
    """Set security headers on every response to address ZAP findings."""
    # Content Security Policy — all resources self-hosted, no external domains needed
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )

    # Anti-clickjacking (legacy browser support alongside CSP frame-ancestors)
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # HSTS — enforce HTTPS for 1 year with subdomains
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Hide server version information
    response.headers['Server'] = 'Scrutinise'

    # Referrer policy — limit referrer info sent cross-origin
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions policy — disable unused browser features
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

    # Cross-Origin headers (AGRA-001-1-7 pen test remediation)
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['X-XSS-Protection'] = '0'

    # Cache control — prevent caching of all dynamic pages
    # Static assets (CSS/JS/fonts) are excluded so browsers can cache them
    if not request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response


# ---------- Password Policy (CREST Compliant) ----------
def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password against CREST standards:
    - Minimum 10 characters
    - At least one uppercase letter
    - At least one lowercase letter  
    - At least one number
    - At least one special character
    - Not a common password
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)."
    
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password is too common. Please choose a stronger password."
    
    return True, "Password meets requirements."


# ---------- Two-Factor Authentication (2FA) ----------
def generate_totp_secret():
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def generate_backup_codes(count=8):
    """Generate backup codes for 2FA recovery."""
    codes = [secrets.token_hex(4).upper() for _ in range(count)]
    return codes


def get_totp_qr_code(username: str, secret: str) -> str:
    """Generate QR code for TOTP setup as base64 data URI."""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="Scrutinise TXN"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    # Return as base64 data URI
    import base64
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code."""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    # Allow 1 window tolerance (30 seconds before/after)
    return totp.verify(code, valid_window=1)


def verify_backup_code(user_id: int, code: str) -> bool:
    """Verify and consume a backup code."""
    db = get_db()
    user = db.execute("SELECT backup_codes FROM users WHERE id=?", (user_id,)).fetchone()
    if not user or not user['backup_codes']:
        return False
    
    try:
        codes = json.loads(user['backup_codes'])
    except:
        return False
    
    code_upper = code.upper().replace('-', '').replace(' ', '')
    if code_upper in codes:
        # Remove used code
        codes.remove(code_upper)
        db.execute("UPDATE users SET backup_codes=? WHERE id=?", 
                   (json.dumps(codes), user_id))
        db.commit()
        return True
    return False


def is_2fa_required() -> bool:
    """Check if 2FA is enforced globally."""
    return cfg_get('cfg_enforce_2fa', False, bool)


def user_has_2fa(user_id: int) -> bool:
    """Check if user has 2FA enabled and verified."""
    db = get_db()
    user = db.execute("SELECT totp_enabled, totp_verified FROM users WHERE id=?", (user_id,)).fetchone()
    return user and user['totp_enabled'] == 1 and user['totp_verified'] == 1


# ---------- Email Service ----------
def get_smtp_config():
    """Get SMTP configuration from database (with decryption for sensitive fields)."""
    try:
        db = get_db()
        return {
            'host': cfg_get('cfg_smtp_host', '', str),
            'port': cfg_get('cfg_smtp_port', 587, int),
            'username': cfg_get('cfg_smtp_username', '', str),
            'password': decrypt_value(cfg_get('cfg_smtp_password', '', str)),  # Decrypt password
            'from_email': cfg_get('cfg_smtp_from_email', '', str),
            'from_name': cfg_get('cfg_smtp_from_name', 'Transaction Review Tool', str),
            'use_tls': cfg_get('cfg_smtp_use_tls', True, bool),
        }
    except:
        return None


def set_smtp_password(password: str):
    """Store SMTP password with encryption."""
    encrypted = encrypt_value(password) if password else ''
    cfg_set('cfg_smtp_password', encrypted)


def send_email(to_email: str, subject: str, html_body: str, text_body: str = None) -> tuple[bool, str]:
    """Send email using configured SMTP settings."""
    config = get_smtp_config()
    
    if not config or not config['host']:
        return False, "SMTP not configured. Please configure email settings in Admin panel."
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{config['from_name']} <{config['from_email']}>"
        msg['To'] = to_email
        
        if text_body:
            msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        if config['use_tls']:
            server = smtplib.SMTP(config['host'], config['port'])
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(config['host'], config['port'])
        
        if config['username'] and config['password']:
            server.login(config['username'], config['password'])
        
        server.sendmail(config['from_email'], to_email, msg.as_string())
        server.quit()
        
        return True, "Email sent successfully."
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"


def send_welcome_email(username: str, email: str, temp_password: str) -> tuple[bool, str]:
    """Send welcome email to new user with temporary password."""
    subject = "Your Transaction Review Tool Account"
    
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #212529;">Welcome to Transaction Review Tool</h2>
            <p>Hello <strong>{username}</strong>,</p>
            <p>Your account has been created. Here are your login credentials:</p>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p style="margin: 5px 0;"><strong>Username:</strong> {username}</p>
                <p style="margin: 5px 0;"><strong>Temporary Password:</strong> <code style="background: #e9ecef; padding: 2px 6px; border-radius: 3px;">{temp_password}</code></p>
            </div>
            <p style="color: #dc3545;"><strong>Important:</strong> You must change your password upon first login.</p>
            <p>Password requirements:</p>
            <ul>
                <li>Minimum 10 characters</li>
                <li>At least one uppercase letter</li>
                <li>At least one lowercase letter</li>
                <li>At least one number</li>
                <li>At least one special character (!@#$%^&* etc.)</li>
            </ul>
            <p>If you did not expect this email, please contact your administrator immediately.</p>
            <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
            <p style="font-size: 12px; color: #6c757d;">This is an automated message from Transaction Review Tool.</p>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Welcome to Transaction Review Tool
    
    Hello {username},
    
    Your account has been created. Here are your login credentials:
    
    Username: {username}
    Temporary Password: {temp_password}
    
    IMPORTANT: You must change your password upon first login.
    
    Password requirements:
    - Minimum 10 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character (!@#$%^&* etc.)
    
    If you did not expect this email, please contact your administrator immediately.
    """
    
    return send_email(email, subject, html_body, text_body)

# ---------- Embedded schema (fallback if schema.sql not found) ----------
SCHEMA_SQL = r"""
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS config_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ref_country_risk(
  iso2 TEXT PRIMARY KEY,
  risk_level TEXT CHECK(risk_level IN ('LOW','MEDIUM','HIGH','HIGH_3RD','PROHIBITED')),
  score INTEGER NOT NULL,
  prohibited INTEGER DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ref_sort_codes(
  sort_code TEXT PRIMARY KEY,
  bank_name TEXT,
  branch TEXT,
  schemes TEXT,
  valid_from DATE,
  valid_to DATE
);

CREATE TABLE IF NOT EXISTS kyc_profile(
  customer_id TEXT PRIMARY KEY,
  expected_monthly_in REAL,
  expected_monthly_out REAL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customer_cash_limits(
  customer_id TEXT PRIMARY KEY,
  daily_limit REAL,
  weekly_limit REAL,
  monthly_limit REAL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions(
  id TEXT PRIMARY KEY,
  txn_date DATE NOT NULL,
  customer_id TEXT NOT NULL,
  direction TEXT CHECK(direction IN ('in','out')) NOT NULL,
  amount REAL NOT NULL,
  currency TEXT DEFAULT 'GBP',
  base_amount REAL NOT NULL,
  country_iso2 TEXT,
  payer_sort_code TEXT,
  payee_sort_code TEXT,
  channel TEXT,
  narrative TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tx_customer_date ON transactions(customer_id, txn_date);
CREATE INDEX IF NOT EXISTS idx_tx_country ON transactions(country_iso2);
CREATE INDEX IF NOT EXISTS idx_tx_direction ON transactions(direction);

CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  txn_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  score INTEGER NOT NULL,
  severity TEXT CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')) NOT NULL,
  reasons TEXT NOT NULL,
  rule_tags TEXT NOT NULL,
  config_version INTEGER REFERENCES config_versions(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_customer ON alerts(customer_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, created_at);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT CHECK(role IN ('admin','reviewer')) NOT NULL DEFAULT 'reviewer',
  must_change_password INTEGER DEFAULT 0,
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until TIMESTAMP,
  last_login TIMESTAMP,
  last_password_change TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  user_id INTEGER,
  username TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at);

CREATE TABLE IF NOT EXISTS customers(
  customer_id TEXT PRIMARY KEY,
  customer_name TEXT,
  business_type TEXT,
  onboarded_date DATE,
  status TEXT DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS statements(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id TEXT NOT NULL,
  filename TEXT,
  uploaded_by INTEGER,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  record_count INTEGER,
  date_from DATE,
  date_to DATE,
  FOREIGN KEY(customer_id) REFERENCES customers(customer_id),
  FOREIGN KEY(uploaded_by) REFERENCES users(id)
);
"""

# ---------- DB helpers ----------
def get_db():
    if "db" not in g:
        # Apply file security on first access
        secure_database_file(DB_PATH)
        
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        
        # SQLite security pragmas
        g.db.execute("PRAGMA secure_delete = ON")  # Overwrite deleted data
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def exec_script(path):
    db = get_db()
    try:
        with open(path, "r") as f:
            db.executescript(f.read())
    except FileNotFoundError:
        # Fallback to embedded schema
        db.executescript(SCHEMA_SQL)
    db.commit()

def ensure_config_kv_table():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS config_kv(
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()

# ---------- Audit Logging (CREST Compliance) ----------
def log_audit_event(event_type: str, user_id: int = None, username: str = None, details: str = None):
    """Log security-relevant events for audit trail."""
    try:
        db = get_db()
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent', '')[:500] if request else None
        
        db.execute("""
            INSERT INTO audit_log(event_type, user_id, username, ip_address, user_agent, details)
            VALUES(?, ?, ?, ?, ?, ?)
        """, (event_type, user_id, username, ip_address, user_agent, details))
        db.commit()
    except Exception as e:
        # Don't fail the main operation if audit logging fails
        print(f"Audit log error: {e}")


def ensure_audit_log_table():
    """Create audit log table if not exists."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL,
          user_id INTEGER,
          username TEXT,
          ip_address TEXT,
          user_agent TEXT,
          details TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event_type, created_at);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at);")
    db.commit()


# ---------- Account Lockout (CREST Compliance) ----------
def check_account_locked(username: str) -> tuple[bool, str]:
    """Check if account is locked due to failed login attempts."""
    db = get_db()
    user = db.execute("SELECT locked_until FROM users WHERE username=?", (username,)).fetchone()
    
    if user and user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.now() < locked_until:
            remaining = int((locked_until - datetime.now()).total_seconds() / 60) + 1
            return True, f"Account is locked. Try again in {remaining} minute(s)."
        else:
            # Lockout expired, reset
            db.execute("UPDATE users SET locked_until=NULL, failed_login_attempts=0 WHERE username=?", (username,))
            db.commit()
    
    return False, ""


def record_failed_login(username: str):
    """Record a failed login attempt and lock account if threshold exceeded."""
    db = get_db()
    user = db.execute("SELECT id, failed_login_attempts FROM users WHERE username=?", (username,)).fetchone()
    
    if user:
        attempts = (user["failed_login_attempts"] or 0) + 1
        
        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            db.execute(
                "UPDATE users SET failed_login_attempts=?, locked_until=? WHERE username=?",
                (attempts, locked_until.isoformat(), username)
            )
            log_audit_event("ACCOUNT_LOCKED", user["id"], username, 
                          f"Account locked after {attempts} failed attempts")
        else:
            db.execute("UPDATE users SET failed_login_attempts=? WHERE username=?", (attempts, username))
        
        db.commit()
    
    log_audit_event("LOGIN_FAILED", None, username, "Invalid credentials")


def reset_failed_login(username: str):
    """Reset failed login counter on successful login."""
    db = get_db()
    db.execute("UPDATE users SET failed_login_attempts=0, locked_until=NULL, last_login=? WHERE username=?",
               (datetime.now().isoformat(), username))
    db.commit()


# ---------- Authentication helpers ----------
def ensure_users_table():
    """Create users table and seed default admin if needed."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT,
          password_hash TEXT NOT NULL,
          role TEXT CHECK(role IN ('admin','reviewer')) NOT NULL DEFAULT 'reviewer',
          must_change_password INTEGER DEFAULT 0,
          failed_login_attempts INTEGER DEFAULT 0,
          locked_until TIMESTAMP,
          last_login TIMESTAMP,
          last_password_change TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()
    
    # Add new columns to existing table if they don't exist
    cols = {r[1] for r in db.execute("PRAGMA table_info(users);")}
    if "email" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT;")
    if "must_change_password" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0;")
    if "failed_login_attempts" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;")
    if "locked_until" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP;")
    if "last_login" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP;")
    if "last_password_change" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN last_password_change TIMESTAMP;")
    # 2FA columns
    if "totp_secret" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT;")
    if "totp_enabled" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;")
    if "backup_codes" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN backup_codes TEXT;")
    if "totp_verified" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_verified INTEGER DEFAULT 0;")
    db.commit()
    
    # Seed default admin if no users exist (with must_change_password flag)
    if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        db.execute(
            "INSERT INTO users(username, password_hash, role, must_change_password) VALUES(?, ?, ?, ?)",
            ("admin", generate_password_hash("Admin@12345"), "admin", 1)
        )
        db.commit()

def ensure_customers_table():
    """Create customers table."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS customers(
          customer_id TEXT PRIMARY KEY,
          customer_name TEXT,
          business_type TEXT,
          onboarded_date DATE,
          status TEXT DEFAULT 'active',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()

def ensure_statements_table():
    """Create statements table and add statement_id to transactions if needed."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS statements(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          customer_id TEXT NOT NULL,
          filename TEXT,
          uploaded_by INTEGER,
          uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          record_count INTEGER,
          date_from DATE,
          date_to DATE
        );
    """)
    db.commit()
    # Add statement_id to transactions if not exists
    cols = {r[1] for r in db.execute("PRAGMA table_info(transactions);")}
    if "statement_id" not in cols:
        db.execute("ALTER TABLE transactions ADD COLUMN statement_id INTEGER;")
        db.commit()

def get_current_user():
    """Return current user dict or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None

def login_required(f):
    """Decorator: require logged-in user and enforce 2FA if enabled globally."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.")
            return redirect(url_for("login", next=request.url))
        
        # Check if 2FA is enforced globally and user hasn't set it up
        if cfg_get('cfg_enforce_2fa', False, bool):
            # Skip check for 2FA setup pages to avoid redirect loop
            if request.endpoint not in ('setup_2fa', 'manage_2fa', 'logout', 'static'):
                db = get_db()
                user = db.execute("SELECT totp_enabled, totp_verified FROM users WHERE id=?", 
                                  (session["user_id"],)).fetchone()
                if user:
                    totp_enabled = False
                    try:
                        totp_enabled = user["totp_enabled"] and user["totp_verified"]
                    except (KeyError, TypeError):
                        pass
                    
                    if not totp_enabled:
                        flash("Two-factor authentication is required. Please set up 2FA to continue.")
                        return redirect(url_for("setup_2fa"))
        
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please log in to continue.")
            return redirect(url_for("login", next=request.url))
        if user["role"] != "admin":
            flash("Admin access required.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_user():
    """Make current_user available in all templates."""
    return {"current_user": get_current_user()}

# --- AI Rationale storage ----------------------------------------------------
def ensure_ai_rationale_table():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS ai_rationales (
          id INTEGER PRIMARY KEY,
          customer_id TEXT NOT NULL,
          period_from TEXT,
          period_to TEXT,
          nature_of_business TEXT,
          est_income REAL,
          est_expenditure REAL,
          rationale_text TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(customer_id, period_from, period_to)
        );
    """)
    db.commit()

def _load_rationale_row(customer_id: str, p_from: Optional[str], p_to: Optional[str]):
    db = get_db()
    return db.execute(
        "SELECT * FROM ai_rationales WHERE customer_id=? AND IFNULL(period_from,'')=IFNULL(?, '') AND IFNULL(period_to,'')=IFNULL(?, '')",
        (customer_id, p_from, p_to)
    ).fetchone()

def _ensure_ai_rationale_columns():
    db = get_db()
    cols = {r[1] for r in db.execute("PRAGMA table_info(ai_rationales);")}
    if "rationale_text" not in cols:
        db.execute("ALTER TABLE ai_rationales ADD COLUMN rationale_text TEXT;")
        db.commit()

def _upsert_rationale_row(customer_id: str, p_from: Optional[str], p_to: Optional[str],
                          nature_of_business: Optional[str], est_income: Optional[float],
                          est_expenditure: Optional[float], rationale_text: str):
    """
    Insert or update a rationale row. Uses DELETE + INSERT pattern to handle NULL values
    correctly (SQLite's ON CONFLICT doesn't work properly with NULLs in unique constraints).
    """
    db = get_db()
    
    # Delete any existing row with same customer_id and period bounds
    # Use IFNULL to handle NULL comparisons properly
    db.execute("""
        DELETE FROM ai_rationales 
        WHERE customer_id = ? 
          AND IFNULL(period_from, '') = IFNULL(?, '')
          AND IFNULL(period_to, '') = IFNULL(?, '')
    """, (customer_id, p_from, p_to))
    
    # Insert the new row
    db.execute("""
        INSERT INTO ai_rationales(customer_id, period_from, period_to, nature_of_business,
                                  est_income, est_expenditure, rationale_text, updated_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (customer_id, p_from, p_to, nature_of_business, est_income, est_expenditure, rationale_text))
    db.commit()

def _format_date_pretty(date_str: str) -> str:
    """YYYY-MM-DD -> '18th July 2025'."""
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    d = dt.day
    suffix = "th" if 11 <= d <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(d % 10, "th")
    return f"{d}{suffix} {dt.strftime('%B %Y')}"

def _latest_case_customer_id() -> Optional[str]:
    row = get_db().execute(
        "SELECT customer_id FROM ai_cases ORDER BY updated_at DESC, id DESC LIMIT 1"
    ).fetchone()
    return row["customer_id"] if row else None

def _build_customer_friendly_sentence(country_name: str, items: list) -> str:
    """
    items: [{'date':'YYYY-MM-DD','direction':'IN'|'OUT','amount':float}]
    -> Our records show X received from <country> ... and Y sent to <country> ...
    """
    incoming = [i for i in items if i["direction"] == "IN"]
    outgoing = [i for i in items if i["direction"] == "OUT"]

    def describe(trans, verb_singular, verb_plural, preposition):
        parts = [f"£{t['amount']:,.2f} on {_format_date_pretty(t['date'])}" for t in trans]
        n = len(trans)
        verb = verb_singular if n == 1 else verb_plural
        return f"{n} transaction{'s' if n != 1 else ''} {verb} {preposition} {country_name} valued at " + ", ".join(parts)

    segments = []
    if incoming:
        segments.append(describe(incoming, "was received", "were received", "from"))
    if outgoing:
        segments.append(describe(outgoing, "was sent", "were sent", "to"))

    if not segments:
        return ""

    # Use singular/plural for closing question
    total_txns = len(incoming) + len(outgoing)
    closing = "Please confirm the reason for this transaction?" if total_txns == 1 else "Please confirm the reasons for these transactions?"
    return "Our records show " + " and ".join(segments) + ". " + closing

def upsert_cash_limits(customer_id: str, daily: float, weekly: float, monthly: float):
    db = get_db()
    db.execute(
        """INSERT INTO customer_cash_limits(customer_id, daily_limit, weekly_limit, monthly_limit)
           VALUES(?,?,?,?)
           ON CONFLICT(customer_id) DO UPDATE SET
             daily_limit=excluded.daily_limit,
             weekly_limit=excluded.weekly_limit,
             monthly_limit=excluded.monthly_limit,
             updated_at=CURRENT_TIMESTAMP
        """,
        (customer_id, daily, weekly, monthly)
    )
    db.commit()

def cfg_get(key, default=None, cast=str):
    """Get a config value, cast if possible; store default if missing."""
    ensure_config_kv_table()
    row = get_db().execute("SELECT value FROM config_kv WHERE key=?", (key,)).fetchone()
    if not row or row["value"] is None:
        cfg_set(key, default)
        return default
    raw = row["value"]
    try:
        if cast is float: return float(raw)
        if cast is int:   return int(float(raw))
        if cast is bool:  return raw in ("1", "true", "True", "yes", "on")
        if cast is list:  return json.loads(raw) if raw else []
        return raw
    except Exception:
        return default

# --- Country name utility (fallback map; uses ISO2 -> full name) ---
_COUNTRY_NAME_FALLBACK = {
    "GB":"United Kingdom","AE":"United Arab Emirates","TR":"Türkiye","RU":"Russia",
    "US":"United States","DE":"Germany","FR":"France","ES":"Spain","IT":"Italy",
    "NL":"Netherlands","CN":"China","HK":"Hong Kong","SG":"Singapore","IE":"Ireland"
}
def country_full_name(iso2: str) -> str:
    if not iso2:
        return ""
    iso2 = str(iso2).upper().strip()
    return _COUNTRY_NAME_FALLBACK.get(iso2, iso2)

def human_join(items):
    # Oxford-comma joining of short phrases
    items = [str(x) for x in items if str(x)]
    if not items: return ""
    if len(items) == 1: return items[0]
    if len(items) == 2: return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"

def make_narrative_from_txns(txns):
    """
    txns: list of {txn_id, txn_date, base_amount, country_iso2, direction}
    Returns concise sentence like:
      'two transactions to Russia valued at £1,234.00 on 2025-08-29 and £577.89 on 2025-09-11'
    Groups by country + direction; limits to 3 dates per group; rolls-up counts.
    """
    if not txns:
        return ""
    from collections import defaultdict
    buckets = defaultdict(list)  # (preposition, country) -> [text parts]
    # Normalize and sort by date
    norm = []
    for t in txns:
        norm.append({
            "date": str(t.get("txn_date","")),
            "amt": float(t.get("base_amount") or 0.0),
            "country": country_full_name(t.get("country_iso2")),
            "dir": (t.get("direction") or "").lower(),
        })
    norm.sort(key=lambda x: x["date"])

    for t in norm:
        prep = "to" if t["dir"] == "out" else "from"
        buckets[(prep, t["country"])].append(f"£{t['amt']:,.2f} on {t['date']}")

    parts = []
    for (prep, country), vals in buckets.items():
        n = len(vals)
        listed = human_join(vals[:3])
        extra = "" if n <= 3 else f" (and {n-3} more)"
        plural = "transaction" if n == 1 else "transactions"
        parts.append(f"{n} {plural} {prep} {country} valued at {listed}{extra}")
    return human_join(parts)

def cfg_set(key, value):
    """Upsert config value; lists -> JSON."""
    ensure_config_kv_table()
    if isinstance(value, list):
        val = json.dumps(value)
    elif isinstance(value, bool):
        val = "1" if value else "0"
    else:
        val = "" if value is None else str(value)
    db = get_db()
    db.execute("""
        INSERT INTO config_kv(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP
    """, (key, val))
    db.commit()

def format_date_pretty(date_str):
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    day = dt.day
    suffix = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    # Portable day formatting
    return f"{day}{suffix} {dt.strftime('%B %Y')}"

def build_customer_friendly_question(transactions, country_name):
    incoming = [t for t in transactions if t["direction"] == "IN"]
    outgoing = [t for t in transactions if t["direction"] == "OUT"]

    parts = []
    if incoming:
        inc_desc = ", ".join(
            f"£{t['amount']:.2f} on {format_date_pretty(t['date'])}"
            for t in incoming
        )
        verb = "was received" if len(incoming) == 1 else "were received"
        parts.append(f"{len(incoming)} transaction{'s' if len(incoming)>1 else ''} {verb} from {country_name} valued at {inc_desc}")
    if outgoing:
        out_desc = ", ".join(
            f"£{t['amount']:.2f} on {format_date_pretty(t['date'])}"
            for t in outgoing
        )
        verb = "was sent" if len(outgoing) == 1 else "were sent"
        parts.append(f"{len(outgoing)} transaction{'s' if len(outgoing)>1 else ''} {verb} to {country_name} valued at {out_desc}")

    sentence = " and ".join(parts)
    total_txns = len(incoming) + len(outgoing)
    closing = "Please confirm the reason for this transaction?" if total_txns == 1 else "Please confirm the reasons for these transactions?"
    return f"Our records show {sentence}. {closing}"

def ai_normalise_questions_llm(customer_id, fired_tags, source_alerts, base_questions, model=None, max_count=6):
    """
    Ask the LLM to merge/rephrase questions; preserve best-fit tag; attach sources.
    Falls back to base_questions on any error.
    """
    if not llm_enabled():
        return base_questions

    # build per-tag → txn_ids map from source_alerts
    per_tag_src = {}
    for r in source_alerts:
        per_tag_src.setdefault(r["tag"], [])
        if r["txn_id"] not in per_tag_src[r["tag"]]:
            per_tag_src[r["tag"]].append(r["txn_id"])

    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        model = model or str(cfg_get("cfg_ai_model", "gpt-4o-mini"))

        lines = [
            f"Customer: {customer_id}",
            f"Alert tags observed: {', '.join(sorted(set(fired_tags or [])))}",
            "Example alerts (tag / sev / score / date / txn_id):"
        ]
        for r in source_alerts[:15]:
            lines.append(f"- {r['tag']} / {r['severity']} / {r['score']} / {r['txn_date']} / {r['txn_id']}")
        lines.append("\nExisting questions (pre-normalisation):")
        for q in base_questions:
            lines.append(f"- [{q['tag']}] {q['question']}")

        prompt = "\n".join(lines) + f"""
Please consolidate these into at most {max_count} clear, non-leading outreach questions for the customer.
Group overlaps; keep terminology neutral and regulator-friendly.
Return STRICT JSON array, each item exactly:
{{"tag":"<tag from observed set>","question":"<clean customer-facing question>","sources":["<txn_id>", "..."]}}
If you cannot determine per-question sources from context, use an empty array [].
"""

        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a financial-crime analyst. Be concise, neutral, and non-leading."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        raw = (resp.choices[0].message.content or "").strip()
        data = json.loads(raw)

        out, seen = [], set()
        for item in data:
            tag = (item.get("tag") or "").strip() or (fired_tags[0] if fired_tags else "NLP_RISK")
            q   = (item.get("question") or "").strip()
            src = item.get("sources") or []
            if not q:
                continue
            if not src and tag in per_tag_src:
                src = per_tag_src[tag][:5]
            key = (tag, q.lower())
            if key in seen: 
                continue
            seen.add(key)
            out.append({"tag": tag, "question": q, "sources": src})
        return out or base_questions

    except Exception:
        # fallback: dedupe base set; keep per-tag sources we already computed
        out, seen = [], set()
        for q in base_questions:
            key = (q["tag"], q["question"].lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"tag": q["tag"], "question": q["question"], "sources": q.get("sources", [])})
        return out

def enrich_txn_details(txn_ids):
    """Return dict {txn_id: {txn_id, txn_date, base_amount, country_iso2, direction}}."""
    if not txn_ids:
        return {}
    db = get_db()
    qmarks = ",".join("?" for _ in txn_ids)
    rows = db.execute(f"""
        SELECT id AS txn_id, txn_date, base_amount, country_iso2, direction
        FROM transactions
        WHERE id IN ({qmarks})
    """, list(map(str, txn_ids))).fetchall()
    return {r["txn_id"]: dict(r) for r in rows}

def init_db():
    if not os.path.exists(DB_PATH):
        open(DB_PATH, "a").close()
    # Will use schema.sql if present; otherwise uses embedded SCHEMA_SQL
    exec_script(os.path.join(os.path.dirname(__file__), "schema.sql"))
    db = get_db()
    cur = db.execute("SELECT COUNT(*) c FROM config_versions")
    if cur.fetchone()["c"] == 0:
        db.execute("INSERT INTO config_versions(name) VALUES (?)", ("init",))
        db.commit()

ALLOWED_AST_NODES = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
    ast.Load, ast.Name, ast.Constant, ast.Call,
    ast.And, ast.Or, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod
}

import re

def _get_patterns(key: str, defaults: list) -> list:
     items = cfg_get(key, None, list)
     if items is None:
         # seed once
         seeded = [{"term": p, "enabled": True} for p in defaults]
         cfg_set(key, seeded)
         items = seeded
     return [i["term"] for i in items if isinstance(i, dict) and i.get("enabled")]

def _mitigant_patterns():
     defaults = [
         r"\binvoice\b", r"\bcontract\b", r"\bpurchase\s*order\b|\bPO\b",
         r"\bid\s*verified\b|\bKYC\b|\bscreened\b",
         r"\bshipping\b|\bbill of lading\b|\bBOL\b|\btracking\b",
         r"\bevidence\b|\bdocument(s)?\b|\bproof\b",
         r"\bbank transfer\b|\bwire\b|\bSWIFT\b|\bIBAN\b|\baudit trail\b",
     ]
     return _get_patterns("cfg_mitigant_patterns", defaults)

def _aggravant_patterns():
     defaults = [
         r"\bcash\b", r"\bcrypto\b|\busdt\b", r"\bgift\b", r"\bfamily\b|\bfriend\b",
         r"\bno doc(s)?\b|\bcannot provide\b|\bunknown\b|\bunaware\b",
         r"\bshell\b|\boffshore\b"
     ]
     return _get_patterns("cfg_aggravant_patterns", defaults)

def analyse_answer(text: str):
    """Return {'class': 'mitigating'|'aggravating'|'neutral'|'blank', 'hits': [...]}."""
    if not text or not text.strip():
        return {"class": "blank", "hits": []}
    t = text.lower()
    m_hits = [p for p in _mitigant_patterns() if re.search(p, t)]
    a_hits = [p for p in _aggravant_patterns() if re.search(p, t)]
    if a_hits and not m_hits:
        return {"class": "aggravating", "hits": a_hits}
    if m_hits and not a_hits:
        return {"class": "mitigating", "hits": m_hits}
    if m_hits and a_hits:
        # mixed; treat as neutral but note both
        return {"class": "neutral", "hits": m_hits + a_hits}
    return {"class": "neutral", "hits": []}

def cfg_get_bool(key, default=True):
    v = cfg_get(key, None)
    if v is None:
        cfg_set(key, default)
        return default
    return str(v).lower() in ("1","true","yes","on")

def llm_enabled():
    # Toggle + API key present
    return bool(os.getenv("OPENAI_API_KEY")) and bool(cfg_get("cfg_ai_use_llm", False))

def ai_suggest_questions_llm(customer_id, fired_tags, sample_alerts, base_questions, model=None):
    """Return up to a few extra questions from ChatGPT. Fails closed (returns [])."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        model = model or str(cfg_get("cfg_ai_model", "gpt-4o-mini"))

        # Compact context
        lines = [f"Customer: {customer_id}", "Alert tags (severity/score/date):"]
        for r in (sample_alerts or [])[:10]:
            lines.append(f"- {r['tag']} / {r['severity']} / {r['score']} / {r['txn_date']}")
        lines.append("Base questions we already plan to ask:")
        for q in base_questions:
            lines.append(f"- [{q['tag']}] {q['question']}")
        prompt = "\n".join(lines) + """
Please propose up to 3 additional concise, non-leading, regulator-friendly questions that clarify risk.
Return pure JSON array with objects of form: {"tag":"<best-fit tag>","question":"..."}.
"""

        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a compliance analyst following AML/FCA best practice. Be concise and non-leading."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        import json
        txt = (resp.choices[0].message.content or "").strip()
        extras = json.loads(txt)
        out = []
        for e in extras:
            tag = (e.get("tag") or "").strip() or (fired_tags[0] if fired_tags else "NLP_RISK")
            q = (e.get("question") or "").strip()
            if q:
                out.append({"tag": tag, "question": q})
        return out
    except Exception:
        return []

def ai_question_bank():
    # One or more questions per tag; keep simple, non-leading, regulator-friendly phrasing.
    return {
        "PROHIBITED_COUNTRY": [
            "Please explain the purpose for sending funds to this location.",
            "Please can you provide details of the party you made the payment to, and confirm the nature of your relationship with them?"
        ],
        "HIGH_RISK_COUNTRY": [
            "What goods or services does this payment relate to?",
            "Can you confirm the nature of your relationship with this party?"
        ],
        "CASH_DAILY_BREACH": [
            "Why was cash used instead of electronic means for this amount?",
        ],
        "HISTORICAL_DEVIATION": [
            "This amount is higher than your usual activity. What is the reason for the increased activity?",
            "Is this a one-off or should we expect similar sized payments going forward?"
        ],
        "NLP_RISK": [
            "Please clarify the transaction narrative and provide supporting documentation (e.g., invoice/contract)."
        ],
        "EXPECTED_BREACH_OUT": [
            "Your monthly account outgoings exceed your declared expectations. What is the reason for the increase?",
            "Do we need to update your expected monthly outgoings moving forwards?"
        ],
        "EXPECTED_BREACH_IN": [
            "Your monthly account incomings exceed your declared expectations. What is the reason for the increase?",
            "Do we need to update your expected monthly incomings moving forwards?"
        ],
    }

def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get((sev or "").upper(), 0)

def build_ai_questions(customer_id, dfrom=None, dto=None, max_per_tag=5):
    """
    Returns:
      base_questions: [{"tag","question","sources":[txn_ids...]}]  (ONE per tag)
      fired_tags: list[str] in importance order
      preview_alerts: compact list of exemplar alerts for prompt
    """
    tagged = fetch_customer_alerts_with_tags(customer_id, dfrom, dto)
    if not tagged:
        return [], [], []

    from collections import defaultdict
    per_tag = defaultdict(list)
    for r in tagged:
        per_tag[r["tag"]].append(r)

    # order tags by worst severity → highest score → recency
    sev_rank = {"CRITICAL":1,"HIGH":2,"MEDIUM":3,"LOW":4,"INFO":5}
    fired = sorted(
        per_tag.keys(),
        key=lambda tg: (
            min(sev_rank.get(x["severity"], 5) for x in per_tag[tg]),
            -max(x["score"] or 0 for x in per_tag[tg]),
            max(x["txn_date"] for x in per_tag[tg]),
        )
    )

    # per-tag sources (txn_ids)
    per_tag_txn_ids = {tg: [x["txn_id"] for x in per_tag[tg][:max_per_tag]] for tg in per_tag}

    qbank = ai_question_bank()
    base = []

    # --- keep only ONE question per tag (the first template in qbank) ---
    for tg in fired:
        qs = qbank.get(tg, [])
        if not qs:
            continue
        q_text = qs[0].strip()  # choose the primary template for that tag
        base.append({
            "tag": tg,
            "question": q_text,
            "sources": per_tag_txn_ids.get(tg, [])
        })

    # compact exemplar alerts for prompt context
    preview = []
    for tg in fired:
        for r in per_tag[tg][:max_per_tag]:
            preview.append({
                "tag": tg, "severity": r["severity"], "score": r["score"],
                "txn_date": r["txn_date"], "txn_id": r["txn_id"]
            })
    return base, fired, preview

def ai_assess_responses(answer_rows, fired_tags):
    """
    Uses the *actual questions + answers* to build an explainable summary.
    Scoring:
      - Start from tag risk (same weights as before)
      - Per-answer: mitigating -6, aggravating +6, blank +2 (mild penalty)
    """
    # 1) Base from tags
    base = 0
    for t in set(fired_tags or []):
        if t == "PROHIBITED_COUNTRY": base += 70
        elif t == "HIGH_RISK_COUNTRY": base += 30
        elif t == "CASH_DAILY_BREACH": base += 15
        elif t == "HISTORICAL_DEVIATION": base += 20
        elif t == "NLP_RISK": base += 10
        elif t == "EXPECTED_BREACH_OUT": base += 15
        elif t == "EXPECTED_BREACH_IN": base += 10

    # 2) Question-by-question analysis
    bullets = []
    mitig_n = aggr_n = blank_n = 0
    for row in (answer_rows or []):
        q = (row.get("question") or "").strip()
        a = (row.get("answer") or "").strip()
        tag = row.get("tag") or "—"
        res = analyse_answer(a)

        # Adjust score
        if res["class"] == "mitigating":
            base -= 6; mitig_n += 1
            verdict = "Mitigating evidence noted"
        elif res["class"] == "aggravating":
            base += 6; aggr_n += 1
            verdict = "Aggravating indicator present"
        elif res["class"] == "blank":
            base += 2; blank_n += 1
            verdict = "No answer provided"
        else:
            verdict = "Neutral / requires review"

        bullets.append(f"- [{tag}] Q: {q} — {verdict}{'' if not a else f'; Answer: {a}'}")

    # 3) Clamp & map to band (re-using your severity thresholds)
    score = max(0, min(100, base))
    sev_crit = cfg_get("cfg_sev_critical", 90, int)
    sev_high = cfg_get("cfg_sev_high", 70, int)
    sev_med  = cfg_get("cfg_sev_medium", 50, int)
    sev_low  = cfg_get("cfg_sev_low", 30, int)

    if score >= sev_crit: band = "CRITICAL"
    elif score >= sev_high: band = "HIGH"
    elif score >= sev_med: band = "MEDIUM"
    elif score >= sev_low: band = "LOW"
    else: band = "INFO"

    # 4) Build a clean narrative summary that quotes the questions asked
    lines = []
    if fired_tags:
        lines.append(f"Triggered tags: {', '.join(sorted(set(fired_tags)))}.")
    if bullets:
        lines.append("Question & answer review:")
        lines.extend(bullets)
    # quick tallies
    if mitig_n or aggr_n or blank_n:
        tallies = []
        if mitig_n: tallies.append(f"{mitig_n} mitigating")
        if aggr_n: tallies.append(f"{aggr_n} aggravating")
        if blank_n: tallies.append(f"{blank_n} unanswered")
        lines.append(f"Answer quality: {', '.join(tallies)}.")
    lines.append(f"Calculated residual risk: {band} (score {score}).")

    return score, band, "\n".join(lines)

def _safe_eval(expr: str, names: dict) -> bool:
    """
    Very small, whitelisted expression evaluator for rule trigger conditions.
    Supports: and/or/not, comparisons, + - * / %, numeric/string constants,
    names from 'names', and calls to whitelisted helper functions below.
    """
    if not expr or not expr.strip():
        return False

    # Parse
    node = ast.parse(expr, mode="eval")

    # Validate node types
    for n in ast.walk(node):
        if type(n) not in ALLOWED_AST_NODES:
            raise ValueError(f"Disallowed expression element: {type(n).__name__}")
        if isinstance(n, ast.Call):
            if not isinstance(n.func, ast.Name):
                raise ValueError("Only simple function calls allowed")
            if n.func.id not in names:
                raise ValueError(f"Function '{n.func.id}' not allowed")

    # Evaluate
    code = compile(node, "<rule>", "eval")
    return bool(eval(code, {"__builtins__": {}}, names))

def load_rules_from_db():
    """Return list of dict rules from SQLite 'rules' table (if present)."""
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, category, rule, trigger_condition, score_impact, tags, outcome, description "
            "FROM rules ORDER BY category, rule"
        ).fetchall()
    except sqlite3.OperationalError:
        # 'rules' table not present yet
        return []

    out = []
    for r in rows:
        out.append({k: r[k] for k in r.keys()})
    return out

# Helper functions exposed to rule expressions -------------------------------

def in_high_risk(country_iso2: str) -> bool:
    cmap = get_country_map()
    c = cmap.get((country_iso2 or "").upper())
    return bool(c and (c["risk_level"] in ("HIGH", "HIGH_3RD") or int(c["prohibited"]) == 1))

def is_prohibited(country_iso2: str) -> bool:
    cmap = get_country_map()
    c = cmap.get((country_iso2 or "").upper())
    return bool(c and int(c["prohibited"]) == 1)

def contains(text: str, needle: str) -> bool:
    return (text or "").lower().find((needle or "").lower()) >= 0

def pct_over(actual: float, expected: float, factor: float = 1.0) -> bool:
    """Return True if actual > expected * factor."""
    try:
        return float(actual) > float(expected) * float(factor)
    except Exception:
        return False

def gt(x, y):  # handy for expressions
    try:
        return float(x) > float(y)
    except Exception:
        return False

def get_builtin_rules():
    """Return the hard-coded rules that are active in score_new_transactions(), as read-only metadata."""
    return [
        {
            "category": "Jurisdiction Risk",
            "rule": "Prohibited Country",
            "trigger_condition": "is_prohibited(txn.country_iso2)",
            "score_impact": "100",
            "tags": "PROHIBITED_COUNTRY",
            "outcome": "Critical",
            "description": "Flag any payment where the destination is on the prohibited list.",
        },
        {
            "category": "Jurisdiction Risk",
            "rule": "High-Risk Corridor",
            "trigger_condition": "in_high_risk(txn.country_iso2)",
            "score_impact": "Risk table score",
            "tags": "HIGH_RISK_COUNTRY",
            "outcome": "Escalate",
            "description": "Increase score for payments routed via high-risk or high-risk third countries.",
        },
        {
            "category": "Cash Activity",
            "rule": "Cash Daily Limit Breach",
            "trigger_condition": "txn.channel == 'cash' AND day_cash_total > configured daily_limit",
            "score_impact": "20",
            "tags": "CASH_DAILY_BREACH",
            "outcome": "Escalate",
            "description": "Alert when daily cash deposits/withdrawals exceed the set customer limit.",
        },
        {
            "category": "Behavioural Deviation",
            "rule": "Outlier vs Median",
            "trigger_condition": "txn.base_amount > 3 × median_amount (per customer + direction)",
            "score_impact": "25",
            "tags": "HISTORICAL_DEVIATION",
            "outcome": "Escalate",
            "description": "Flag unusually large transactions compared to customer’s typical behaviour.",
        },
        {
            "category": "Narrative Risk",
            "rule": "Risky Terms",
            "trigger_condition": "narrative contains any of: consultancy, gift, usdt, otc, crypto, cash, shell, hawala",
            "score_impact": "10",
            "tags": "NLP_RISK",
            "outcome": "Review",
            "description": "Flag transactions with sensitive wording in the narrative.",
        },
        {
            "category": "KYC Profile Breach",
            "rule": "Outflows > Expected",
            "trigger_condition": "month_out_total > expected_monthly_out × 1.2",
            "score_impact": "20",
            "tags": "EXPECTED_BREACH_OUT",
            "outcome": "Escalate",
            "description": "Monthly outflows exceed declared KYC expectations.",
        },
        {
            "category": "KYC Profile Breach",
            "rule": "Inflows > Expected",
            "trigger_condition": "month_in_total > expected_monthly_in × 1.2",
            "score_impact": "15",
            "tags": "EXPECTED_BREACH_IN",
            "outcome": "Review",
            "description": "Monthly inflows exceed declared KYC expectations.",
        },
        {
            "category": "Severity Mapping",
            "rule": "Score → Severity",
            "trigger_condition": "prohibited OR score≥90→Critical; 70–89→High; 50–69→Medium; 30–49→Low; else Info",
            "score_impact": "—",
            "tags": "—",
            "outcome": "Severity assignment",
            "description": "Maps composite score to severity band for alerting.",
        },
    ]

from datetime import date, timedelta

def _period_bounds(period: str):
    """
    Returns (start_date_str, end_date_str) or (None, None) for 'all'.
    Supported:
      all | 3m | 6m | 12m | ytd | month:YYYY-MM
    """
    today = date.today()
    if not period or period == "all":
        return None, None
    if period in {"3m","6m","12m"}:
        months = int(period[:-1])
        y = today.year
        m = today.month - months + 1
        while m <= 0:
            m += 12; y -= 1
        start = date(y, m, 1)
        end = today
        return start.isoformat(), end.isoformat()
    if period == "ytd":
        start = date(today.year, 1, 1)
        return start.isoformat(), today.isoformat()
    if period.startswith("month:"):
        ym = period.split(":",1)[1]
        y, m = map(int, ym.split("-"))
        start = date(y, m, 1)
        if m == 12:
            end = date(y+1, 1, 1) - timedelta(days=1)
        else:
            end = date(y, m+1, 1) - timedelta(days=1)
        return start.isoformat(), end.isoformat()
    return None, None

# ---------- Simple scoring / rules ----------
def get_country_map():
    db = get_db()
    rows = db.execute("SELECT iso2, risk_level, score, prohibited FROM ref_country_risk").fetchall()
    return {r["iso2"]: dict(r) for r in rows}

def get_expected_map():
    db = get_db()
    rows = db.execute("SELECT * FROM kyc_profile").fetchall()
    return {r["customer_id"]: dict(r) for r in rows}

def upsert_country(iso2, level, score, prohibited):
    db = get_db()
    db.execute(
        """INSERT INTO ref_country_risk(iso2, risk_level, score, prohibited)
           VALUES(?,?,?,?)
           ON CONFLICT(iso2) DO UPDATE SET risk_level=excluded.risk_level,
                                          score=excluded.score,
                                          prohibited=excluded.prohibited,
                                          updated_at=CURRENT_TIMESTAMP
        """,
        (iso2, level, score, prohibited)
    )
    db.commit()

def upsert_sort_codes(rows):
    db = get_db()
    for r in rows:
        db.execute(
            """INSERT INTO ref_sort_codes(sort_code, bank_name, branch, schemes, valid_from, valid_to)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(sort_code) DO UPDATE SET bank_name=excluded.bank_name,
                                                   branch=excluded.branch,
                                                   schemes=excluded.schemes,
                                                   valid_from=excluded.valid_from,
                                                   valid_to=excluded.valid_to
            """,
            (r.get("sort_code"), r.get("bank_name"), r.get("branch"),
             r.get("schemes"), r.get("valid_from"), r.get("valid_to"))
        )
    db.commit()

def load_csv_to_table(path, table):
    import pandas as pd
    df = pd.read_csv(path)
    db = get_db()
    if table == "ref_country_risk":
        for _,r in df.iterrows():
            upsert_country(str(r["iso2"]).strip(), str(r["risk_level"]).strip(),
                           int(r["score"]), int(r.get("prohibited",0)))
    elif table == "ref_sort_codes":
        recs = df.to_dict(orient="records")
        upsert_sort_codes(recs)
    elif table == "kyc_profile":
        for _,r in df.iterrows():
            db.execute(
                """INSERT INTO kyc_profile(customer_id, expected_monthly_in, expected_monthly_out)
                   VALUES(?,?,?)
                   ON CONFLICT(customer_id) DO UPDATE SET expected_monthly_in=excluded.expected_monthly_in,
                                                         expected_monthly_out=excluded.expected_monthly_out,
                                                         updated_at=CURRENT_TIMESTAMP
                """,
                (str(r["customer_id"]), float(r["expected_monthly_in"]), float(r["expected_monthly_out"]))
            )
        db.commit()
    elif table == "customer_cash_limits":
        for _,r in df.iterrows():
            upsert_cash_limits(str(r["customer_id"]), float(r["daily_limit"]),
                               float(r["weekly_limit"]), float(r["monthly_limit"]))
    else:
        raise ValueError("Unsupported table for CSV load")

def ingest_transactions_csv(fobj):
    import pandas as pd
    from datetime import datetime, timedelta, date

    # --- helpers -------------------------------------------------------------
    def _excel_serial_to_date(n):
        # Excel's day 1 = 1899-12-31; but with the 1900-leap bug, pandas/Excel often use 1899-12-30
        # We’ll use 1899-12-30 which matches most CSV exports.
        origin = date(1899, 12, 30)
        try:
            n = int(float(n))
            if n <= 0:
                return None
            return origin + timedelta(days=n)
        except Exception:
            return None

    COMMON_FORMATS = [
        "%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y",
        "%d-%m-%Y", "%Y/%m/%d",
    ]

    def _coerce_date(val):
        if val is None:
            return None
        s = str(val).strip()
        if s == "" or s.lower() in ("nan", "none", "null"):
            return None

        # 1) numeric → Excel serial
        try:
            # accept integers/floats or numeric-looking strings
            if isinstance(val, (int, float)) or s.replace(".", "", 1).isdigit():
                d = _excel_serial_to_date(val)
                if d:
                    return d
        except Exception:
            pass

        # 2) try explicit formats
        for fmt in COMMON_FORMATS:
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass

        # 3) last resort: pandas to_datetime with dayfirst True then False
        try:
            d = pd.to_datetime(s, dayfirst=True, errors="coerce")
            if pd.notna(d):
                return d.date()
        except Exception:
            pass
        try:
            d = pd.to_datetime(s, dayfirst=False, errors="coerce")
            if pd.notna(d):
                return d.date()
        except Exception:
            pass

        return None

    # --- load & validate columns --------------------------------------------
    df = pd.read_csv(fobj)

    needed = {
        "id","txn_date","customer_id","direction","amount","currency","base_amount",
        "country_iso2","payer_sort_code","payee_sort_code","channel","narrative"
    }
    missing = needed - set(map(str, df.columns))
    if missing:
        raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")

    # --- txn_date robust parsing (no warnings, no mass failure) -------------
    df["txn_date"] = df["txn_date"].apply(_coerce_date)
    bad_dates = df["txn_date"].isna().sum()
    if bad_dates:
        # Drop rows with unparseable txn_date; we’ll report how many were skipped
        df = df[df["txn_date"].notna()]

    # --- normalize text-ish fields ------------------------------------------
    df["direction"] = df["direction"].astype(str).str.lower().str.strip()
    df["currency"]  = df.get("currency", "GBP").fillna("GBP").astype(str).str.strip()

    # Normalize optional text fields (empty → None)
    for col in ["country_iso2","payer_sort_code","payee_sort_code","channel","narrative"]:
        if col in df.columns:
            df[col] = df[col].astype(str)
            df[col] = df[col].str.strip()
            df[col] = df[col].replace({"": None, "nan": None, "None": None, "NULL": None})
        else:
            df[col] = None

    # ISO2 upper-case
    df["country_iso2"] = df["country_iso2"].apply(lambda x: (x or "").upper() or None)

    # channel lower-case
    df["channel"] = df["channel"].apply(lambda x: (x or "").lower() or None)

    # --- amounts: coerce, backfill, then fill (0.0) to satisfy NOT NULL -----
    df["amount"]      = pd.to_numeric(df["amount"], errors="coerce")
    df["base_amount"] = pd.to_numeric(df["base_amount"], errors="coerce")

    mask_amt_na  = df["amount"].isna() & df["base_amount"].notna()
    mask_base_na = df["base_amount"].isna() & df["amount"].notna()
    df.loc[mask_amt_na,  "amount"]      = df.loc[mask_amt_na,  "base_amount"]
    df.loc[mask_base_na, "base_amount"] = df.loc[mask_base_na, "amount"]

    df["amount"]      = df["amount"].fillna(0.0)
    df["base_amount"] = df["base_amount"].fillna(0.0)

    # --- insert --------------------------------------------------------------
    recs = df.to_dict(orient="records")
    db = get_db()
    n_inserted = 0
    for r in recs:
        db.execute(
            """INSERT OR REPLACE INTO transactions
               (id, txn_date, customer_id, direction, amount, currency, base_amount, country_iso2,
                payer_sort_code, payee_sort_code, channel, narrative)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(r["id"]),
                str(r["txn_date"]),                 # now a real date
                str(r["customer_id"]),
                str(r["direction"]),
                float(r["amount"]),                 # not null
                str(r.get("currency","GBP")),
                float(r["base_amount"]),            # not null
                (str(r["country_iso2"]) if r.get("country_iso2") else None),
                (str(r["payer_sort_code"]) if r.get("payer_sort_code") else None),
                (str(r["payee_sort_code"]) if r.get("payee_sort_code") else None),
                (str(r["channel"]) if r.get("channel") else None),
                (str(r["narrative"]) if r.get("narrative") else None),
            )
        )
        n_inserted += 1

    db.commit()
    score_new_transactions()

    # Return count; the UI already flashes “Loaded N transactions”
    # If you want to surface skipped rows, you can also flash here, but
    # we’ll just print to console to avoid changing routes:
    if bad_dates:
        print(f"[ingest_transactions_csv] Skipped {bad_dates} row(s) with invalid txn_date.")

    return n_inserted

def ingest_transactions_csv_for_customer(fobj, expected_customer_id, statement_id=None):
    """
    Ingest transactions for a specific customer only.
    Validates that all rows belong to the expected customer.
    Returns (n_inserted, date_from, date_to).
    """
    import pandas as pd
    from datetime import datetime, timedelta, date as date_type

    # --- helpers -------------------------------------------------------------
    def _excel_serial_to_date(n):
        origin = date_type(1899, 12, 30)
        try:
            n = int(float(n))
            if n <= 0:
                return None
            return origin + timedelta(days=n)
        except Exception:
            return None

    COMMON_FORMATS = [
        "%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y",
        "%d-%m-%Y", "%Y/%m/%d",
    ]

    def _coerce_date(val):
        if val is None:
            return None
        s = str(val).strip()
        if s == "" or s.lower() in ("nan", "none", "null"):
            return None
        try:
            if isinstance(val, (int, float)) or s.replace(".", "", 1).isdigit():
                d = _excel_serial_to_date(val)
                if d:
                    return d
        except Exception:
            pass
        for fmt in COMMON_FORMATS:
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
        try:
            d = pd.to_datetime(s, dayfirst=True, errors="coerce")
            if pd.notna(d):
                return d.date()
        except Exception:
            pass
        return None

    # --- load & validate columns --------------------------------------------
    df = pd.read_csv(fobj)

    needed = {
        "id","txn_date","customer_id","direction","amount","currency","base_amount",
        "country_iso2","payer_sort_code","payee_sort_code","channel","narrative"
    }
    missing = needed - set(map(str, df.columns))
    if missing:
        raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")

    # Validate customer_id matches expected
    df["customer_id"] = df["customer_id"].astype(str).str.strip()
    unique_customers = df["customer_id"].unique()
    invalid_customers = [c for c in unique_customers if c != expected_customer_id]
    if invalid_customers:
        raise ValueError(f"CSV contains customer_id(s) {invalid_customers} but expected {expected_customer_id}")

    # --- txn_date robust parsing -------------
    df["txn_date"] = df["txn_date"].apply(_coerce_date)
    bad_dates = df["txn_date"].isna().sum()
    if bad_dates:
        df = df[df["txn_date"].notna()]

    if len(df) == 0:
        raise ValueError("No valid transactions found in the file.")

    # --- normalize text-ish fields ------------------------------------------
    df["direction"] = df["direction"].astype(str).str.lower().str.strip()
    df["currency"]  = df.get("currency", "GBP").fillna("GBP").astype(str).str.strip()

    for col in ["country_iso2","payer_sort_code","payee_sort_code","channel","narrative"]:
        if col in df.columns:
            df[col] = df[col].astype(str)
            df[col] = df[col].str.strip()
            df[col] = df[col].replace({"": None, "nan": None, "None": None, "NULL": None})
        else:
            df[col] = None

    df["country_iso2"] = df["country_iso2"].apply(lambda x: (x or "").upper() or None)
    df["channel"] = df["channel"].apply(lambda x: (x or "").lower() or None)

    df["amount"]      = pd.to_numeric(df["amount"], errors="coerce")
    df["base_amount"] = pd.to_numeric(df["base_amount"], errors="coerce")

    mask_amt_na  = df["amount"].isna() & df["base_amount"].notna()
    mask_base_na = df["base_amount"].isna() & df["amount"].notna()
    df.loc[mask_amt_na,  "amount"]      = df.loc[mask_amt_na,  "base_amount"]
    df.loc[mask_base_na, "base_amount"] = df.loc[mask_base_na, "amount"]

    df["amount"]      = df["amount"].fillna(0.0)
    df["base_amount"] = df["base_amount"].fillna(0.0)

    # Get date range
    date_from = str(df["txn_date"].min())
    date_to = str(df["txn_date"].max())

    # --- insert (bulk for performance) -----------------------------------------
    recs = df.to_dict(orient="records")
    db = get_db()
    
    # Prepare batch data for executemany (much faster for large volumes)
    batch_data = [
        (
            str(r["id"]),
            str(r["txn_date"]),
            str(r["customer_id"]),
            str(r["direction"]),
            float(r["amount"]),
            str(r.get("currency", "GBP")),
            float(r["base_amount"]),
            (str(r["country_iso2"]) if r.get("country_iso2") else None),
            (str(r["payer_sort_code"]) if r.get("payer_sort_code") else None),
            (str(r["payee_sort_code"]) if r.get("payee_sort_code") else None),
            (str(r["channel"]) if r.get("channel") else None),
            (str(r["narrative"]) if r.get("narrative") else None),
            statement_id,
        )
        for r in recs
    ]
    
    db.executemany(
        """INSERT OR REPLACE INTO transactions
           (id, txn_date, customer_id, direction, amount, currency, base_amount, country_iso2,
            payer_sort_code, payee_sort_code, channel, narrative, statement_id)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        batch_data
    )
    n_inserted = len(batch_data)

    db.commit()
    score_new_transactions()

    return n_inserted, date_from, date_to

# ---------- Built-in rules (hard-coded) with configurable parameters ----------
def builtin_rules_catalog():
    return [
        {
            "key": "cash_daily_breach",
            "category": "Cash Activity",
            "rule": "Cash Daily Limit Breach",
            "trigger": "day_cash_total > cfg_cash_daily_limit (global)",
            "impact": "+20",
            "tags": "CASH_DAILY_BREACH",
            "outcome": "Escalate",
            "description": "Alert when daily cash deposits/withdrawals exceed the global cash limit.",
            "params": [ {"key":"cfg_cash_daily_limit","label":"Global cash daily limit","prefix":"£"} ],
        },
        {
            "key": "high_risk_corridor",
            "category": "Jurisdiction Risk",
            "rule": "High-Risk Corridor",
            "trigger": "in_high_risk(txn.country_iso2) AND txn.base_amount ≥ cfg_high_risk_min_amount",
            "impact": "risk table score",
            "tags": "HIGH_RISK_COUNTRY",
            "outcome": "Escalate",
            "description": "Increase score for transactions to high-risk or high-risk third countries if above the minimum amount.",
            "params": [ {"key":"cfg_high_risk_min_amount","label":"Min amount","prefix":"£"} ],
        },
        {
            "key": "median_outlier",
            "category": "Behavioural Deviation",
            "rule": "Outlier vs Median",
            "trigger": "txn.base_amount > (cfg_median_multiplier × median_amount)",
            "impact": "+25",
            "tags": "HISTORICAL_DEVIATION",
            "outcome": "Escalate",
            "description": "Flag unusually large transactions compared to customer’s typical behaviour.",
            "params": [ {"key":"cfg_median_multiplier","label":"Multiplier","suffix":"×"} ],
            "requires": "Historical median available",
        },
        {
            "key": "nlp_risky_terms",
            "category": "Narrative Risk",
            "rule": "Risky Terms",
            "trigger": "narrative contains any enabled keyword",
            "impact": "+10",
            "tags": "NLP_RISK",
            "outcome": "Review",
            "description": "Flag transactions with sensitive wording in the narrative.",
            "params": [ {"key":"cfg_risky_terms2","label":"Keywords","kind":"list"} ],
        },
        {
            "key": "expected_out",
            "category": "KYC Profile Breach",
            "rule": "Outflows > Expected",
            "trigger": "month_out_total > (cfg_expected_out_factor × expected_monthly_out)",
            "impact": "+20",
            "tags": "EXPECTED_BREACH_OUT",
            "outcome": "Escalate",
            "description": "Monthly outflows exceed declared KYC expectations.",
            "params": [ {"key":"cfg_expected_out_factor","label":"Multiplier","suffix":"×"} ],
            "requires": "KYC expected_monthly_out set",
        },
        {
            "key": "expected_in",
            "category": "KYC Profile Breach",
            "rule": "Inflows > Expected",
            "trigger": "month_in_total > (cfg_expected_in_factor × expected_monthly_in)",
            "impact": "+15",
            "tags": "EXPECTED_BREACH_IN",
            "outcome": "Review",
            "description": "Monthly inflows exceed declared KYC expectations.",
            "params": [ {"key":"cfg_expected_in_factor","label":"Multiplier","suffix":"×"} ],
            "requires": "KYC expected_monthly_in set",
        },
        {
            "key": "cash_daily_breach",
            "category": "Cash Activity",
            "rule": "Cash Daily Limit Breach",
            "trigger": "day_cash_total > per-customer daily_limit",
            "impact": "+20",
            "tags": "CASH_DAILY_BREACH",
            "outcome": "Escalate",
            "description": "Alert when daily cash deposits/withdrawals exceed the set customer limit.",
            "params": [],
            "requires": "Customer cash daily_limit set (optional)",
        },
        {
            "key": "severity_mapping",
            "category": "Severity Mapping",
            "rule": "Score → Severity",
            "trigger": "≥ cfg_sev_critical → Critical; ≥ cfg_sev_high → High; ≥ cfg_sev_medium → Medium; ≥ cfg_sev_low → Low; else Info",
            "impact": "—",
            "tags": "—",
            "outcome": "Severity assignment",
            "description": "Maps composite score to severity band for alerting.",
            "params": [
                {"key":"cfg_sev_critical","label":"Critical ≥"},
                {"key":"cfg_sev_high","label":"High ≥"},
                {"key":"cfg_sev_medium","label":"Medium ≥"},
                {"key":"cfg_sev_low","label":"Low ≥"},
            ],
        },
        {
            "key": "structuring",
            "category": "Wolfsberg - Structuring",
            "rule": "Structuring Detection",
            "trigger": "Multiple transactions just below reporting threshold within 7-day window",
            "impact": "+30",
            "tags": "STRUCTURING",
            "outcome": "Escalate",
            "description": "Detects potential smurfing/structuring where transactions are deliberately kept below reporting thresholds.",
            "params": [
                {"key":"cfg_structuring_threshold","label":"Reporting threshold","prefix":"£"},
                {"key":"cfg_structuring_margin_pct","label":"Margin below threshold","suffix":"%"},
                {"key":"cfg_structuring_min_count","label":"Min transactions to trigger"},
            ],
        },
        {
            "key": "flowthrough",
            "category": "Wolfsberg - Flow Patterns",
            "rule": "Flow-Through Detection",
            "trigger": "Matching inflow and outflow within configurable window",
            "impact": "+25",
            "tags": "FLOW_THROUGH",
            "outcome": "Escalate",
            "description": "Detects pass-through or layering patterns where funds flow in and out in similar amounts within a short period.",
            "params": [
                {"key":"cfg_flowthrough_window_days","label":"Window (days)"},
                {"key":"cfg_flowthrough_match_pct","label":"Amount match tolerance","suffix":"%"},
            ],
        },
        {
            "key": "dormancy",
            "category": "Wolfsberg - Behavioural",
            "rule": "Dormancy Reactivation",
            "trigger": "Significant transaction after extended period of inactivity",
            "impact": "+20",
            "tags": "DORMANCY_REACTIVATION",
            "outcome": "Review",
            "description": "Flags accounts that suddenly become active after a dormant period, a common money laundering indicator.",
            "params": [
                {"key":"cfg_dormancy_inactive_days","label":"Dormancy period (days)"},
                {"key":"cfg_dormancy_reactivation_amount","label":"Min reactivation amount","prefix":"£"},
            ],
        },
        {
            "key": "velocity",
            "category": "Wolfsberg - Behavioural",
            "rule": "High Velocity",
            "trigger": "High frequency of transactions within short time window",
            "impact": "+15",
            "tags": "HIGH_VELOCITY",
            "outcome": "Review",
            "description": "Detects rapid movement of funds through an account, indicative of layering or pass-through activity.",
            "params": [
                {"key":"cfg_velocity_window_hours","label":"Window (hours)"},
                {"key":"cfg_velocity_min_count","label":"Min transaction count"},
            ],
        },
    ]

def ensure_ai_tables():
    """Create/patch AI tables (adds 'sources' column to ai_answers; rationale columns to ai_cases)."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS ai_cases (
          id INTEGER PRIMARY KEY,
          customer_id TEXT NOT NULL,
          period_from TEXT,
          period_to TEXT,
          assessment_risk TEXT,
          assessment_score INTEGER,
          assessment_summary TEXT,
          rationale_text TEXT,                -- NEW: persisted rationale
          rationale_generated_at TEXT,        -- NEW: when rationale was generated
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS ai_answers (
          id INTEGER PRIMARY KEY,
          case_id INTEGER NOT NULL,
          tag TEXT,
          question TEXT NOT NULL,
          answer TEXT,
          sources TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(case_id) REFERENCES ai_cases(id) ON DELETE CASCADE
        );
    """)
    # Add columns idempotently
    try:
        db.execute("ALTER TABLE ai_answers ADD COLUMN sources TEXT;")
    except sqlite3.OperationalError:
        pass
    try:
        db.execute("ALTER TABLE ai_cases ADD COLUMN rationale_text TEXT;")
    except sqlite3.OperationalError:
        pass
    try:
        db.execute("ALTER TABLE ai_cases ADD COLUMN rationale_generated_at TEXT;")
    except sqlite3.OperationalError:
        pass
    db.commit()

def fetch_customer_alerts_with_tags(customer_id, dfrom=None, dto=None):
    """
    Rows shaped for AI: one row per (alert, tag).
    {alert_id, txn_id, txn_date, severity, score, tag}
    """
    db = get_db()
    wh, params = ["a.customer_id = ?"], [customer_id]
    if dfrom: wh.append("t.txn_date >= ?"); params.append(dfrom)
    if dto:   wh.append("t.txn_date <= ?"); params.append(dto)

    rows = db.execute(f"""
        SELECT a.id AS alert_id, a.txn_id, t.txn_date, a.severity, a.score, a.rule_tags
        FROM alerts a
        JOIN transactions t ON t.id = a.txn_id
        WHERE {" AND ".join(wh)}
        ORDER BY CASE a.severity
                   WHEN 'CRITICAL' THEN 1
                   WHEN 'HIGH' THEN 2
                   WHEN 'MEDIUM' THEN 3
                   WHEN 'LOW' THEN 4
                   ELSE 5
                 END, a.score DESC, t.txn_date DESC
    """, params).fetchall()

    out = []
    for r in rows:
        try:
            tags = json.loads(r["rule_tags"] or "[]")
        except Exception:
            tags = []
        for tag in tags:
            out.append({
                "alert_id": r["alert_id"],
                "txn_id": r["txn_id"],
                "txn_date": r["txn_date"],
                "severity": r["severity"],
                "score": r["score"],
                "tag": tag
            })
    return out

def ensure_default_parameters():
    """
    Seed all configurable parameters with sensible defaults (idempotent).
    Also migrates old cfg_risky_terms -> cfg_risky_terms2 (objects with enabled flag).
    """
    # Core thresholds / factors
    defaults = {
        "cfg_high_risk_min_amount": 0.0,     # £ threshold for high-risk corridor rule
        "cfg_median_multiplier": 3.0,        # × median for outlier rule
        "cfg_expected_out_factor": 1.2,      # × expected monthly outflows
        "cfg_expected_in_factor": 1.2,       # × expected monthly inflows
        "cfg_cash_daily_limit": 0.0,

        # Structuring detection parameters
        "cfg_structuring_threshold": 10000.0,  # £ reporting threshold to detect structuring below
        "cfg_structuring_margin_pct": 15.0,    # % below threshold to flag (e.g., 15% = £8,500-£9,999)
        "cfg_structuring_min_count": 2,        # min transactions in window to trigger

        # Flow-through detection parameters
        "cfg_flowthrough_window_days": 3,      # days window for in-then-out detection
        "cfg_flowthrough_match_pct": 80.0,     # % match tolerance for amounts (80% = within 20%)

        # Dormancy detection parameters
        "cfg_dormancy_inactive_days": 90,      # days of inactivity to consider dormant
        "cfg_dormancy_reactivation_amount": 5000.0,  # £ minimum to trigger after dormancy

        # Velocity detection parameters
        "cfg_velocity_window_hours": 24,       # hours window for velocity check
        "cfg_velocity_min_count": 5,           # min transactions in window to trigger

        # Severity mapping thresholds
        "cfg_sev_critical": 90,
        "cfg_sev_high": 70,
        "cfg_sev_medium": 50,
        "cfg_sev_low": 30,

        # AI (LLM) integration toggles
        "cfg_ai_use_llm": False,             # off by default (local/heuristic only)
        "cfg_ai_model": "gpt-4o-mini",

        # Rule enable/disable toggles (all on by default)
        "cfg_rule_enabled_prohibited_country": True,
        "cfg_rule_enabled_high_risk_corridor": True,
        "cfg_rule_enabled_median_outlier": True,
        "cfg_rule_enabled_nlp_risky_terms": True,
        "cfg_rule_enabled_expected_out": True,
        "cfg_rule_enabled_expected_in": True,
        "cfg_rule_enabled_cash_daily_breach": True,
        "cfg_rule_enabled_severity_mapping": True,
        "cfg_rule_enabled_structuring": True,
        "cfg_rule_enabled_flowthrough": True,
        "cfg_rule_enabled_dormancy": True,
        "cfg_rule_enabled_velocity": True,
    }

    # Write any missing defaults
    for k, v in defaults.items():
        if cfg_get(k, None) is None:
            cfg_set(k, v)

    # Legacy keyword list -> migrate to object list with enabled flags
    if cfg_get("cfg_risky_terms2", None) is None:
        base = cfg_get("cfg_risky_terms", None, list)
        if not base:
            base = ["consultancy", "gift", "usdt", "otc", "crypto", "cash", "shell", "hawala"]
            cfg_set("cfg_risky_terms", base)
        terms = [{"term": t, "enabled": True} for t in base]
        cfg_set("cfg_risky_terms2", terms)

def risky_terms_enabled():
    items = cfg_get("cfg_risky_terms2", [], list)
    return [i["term"] for i in items if isinstance(i, dict) and i.get("enabled")]

def score_new_transactions():
    import statistics
    db = get_db()
    country_map = get_country_map()
    expected_map = get_expected_map()

    # Params
    high_risk_min_amount = cfg_get("cfg_high_risk_min_amount", 0.0, float)
    median_mult = cfg_get("cfg_median_multiplier", 3.0, float)
    exp_out_factor = cfg_get("cfg_expected_out_factor", 1.2, float)
    exp_in_factor  = cfg_get("cfg_expected_in_factor", 1.2, float)
    enabled_terms  = risky_terms_enabled()  # NEW: only enabled
    sev_crit = cfg_get("cfg_sev_critical", 90, int)
    sev_high = cfg_get("cfg_sev_high", 70, int)
    sev_med  = cfg_get("cfg_sev_medium", 50, int)
    sev_low  = cfg_get("cfg_sev_low", 30, int)

    # Toggles
    on = {
        "prohibited_country": cfg_get_bool("cfg_rule_enabled_prohibited_country", True),
        "high_risk_corridor": cfg_get_bool("cfg_rule_enabled_high_risk_corridor", True),
        "median_outlier": cfg_get_bool("cfg_rule_enabled_median_outlier", True),
        "nlp_risky_terms": cfg_get_bool("cfg_rule_enabled_nlp_risky_terms", True),
        "expected_out": cfg_get_bool("cfg_rule_enabled_expected_out", True),
        "expected_in": cfg_get_bool("cfg_rule_enabled_expected_in", True),
        "cash_daily_breach": cfg_get_bool("cfg_rule_enabled_cash_daily_breach", True),
        "severity_mapping": cfg_get_bool("cfg_rule_enabled_severity_mapping", True),
        "structuring": cfg_get_bool("cfg_rule_enabled_structuring", True),
        "flowthrough": cfg_get_bool("cfg_rule_enabled_flowthrough", True),
        "dormancy": cfg_get_bool("cfg_rule_enabled_dormancy", True),
        "velocity": cfg_get_bool("cfg_rule_enabled_velocity", True),
    }

    # New rule parameters
    structuring_threshold = cfg_get("cfg_structuring_threshold", 10000.0, float)
    structuring_margin_pct = cfg_get("cfg_structuring_margin_pct", 15.0, float)
    structuring_min_count = cfg_get("cfg_structuring_min_count", 2, int)
    flowthrough_window_days = cfg_get("cfg_flowthrough_window_days", 3, int)
    flowthrough_match_pct = cfg_get("cfg_flowthrough_match_pct", 80.0, float)
    dormancy_inactive_days = cfg_get("cfg_dormancy_inactive_days", 90, int)
    dormancy_reactivation_amount = cfg_get("cfg_dormancy_reactivation_amount", 5000.0, float)
    velocity_window_hours = cfg_get("cfg_velocity_window_hours", 24, int)
    velocity_min_count = cfg_get("cfg_velocity_min_count", 5, int)

    # Medians
    cur = db.execute("SELECT customer_id, direction, base_amount FROM transactions")
    per_key = defaultdict(list)
    for r in cur.fetchall():
        per_key[(r["customer_id"], r["direction"])].append(r["base_amount"])
    cust_medians = {k: statistics.median(v) for k,v in per_key.items() if v}

    # Worklist
    txns = db.execute("""
        SELECT t.* FROM transactions t
        LEFT JOIN alerts a ON a.txn_id = t.id
        WHERE a.id IS NULL
        ORDER BY t.txn_date ASC
    """).fetchall()

    for t in txns:
        reasons, tags, score = [], [], 0
        severity = "LOW"
        chan = (t["channel"] or "").lower()
        narrative = (t["narrative"] or "")

        d = date.fromisoformat(t["txn_date"])
        month_start = d.replace(day=1).isoformat()
        month_end = ((d.replace(day=28)+timedelta(days=4)).replace(day=1) - timedelta(days=1)).isoformat()

        month_in_total = float(db.execute(
            "SELECT SUM(base_amount) s FROM transactions WHERE customer_id=? AND direction='in' AND txn_date BETWEEN ? AND ?",
            (t["customer_id"], month_start, month_end)
        ).fetchone()["s"] or 0)

        month_out_total = float(db.execute(
            "SELECT SUM(base_amount) s FROM transactions WHERE customer_id=? AND direction='out' AND txn_date BETWEEN ? AND ?",
            (t["customer_id"], month_start, month_end)
        ).fetchone()["s"] or 0)

        exp = expected_map.get(t["customer_id"], {"expected_monthly_in":0, "expected_monthly_out":0})
        expected_monthly_in  = float(exp.get("expected_monthly_in") or 0)
        expected_monthly_out = float(exp.get("expected_monthly_out") or 0)
        med = float(cust_medians.get((t["customer_id"], t["direction"]), 0.0))

        # Prohibited
        c = country_map.get(t["country_iso2"] or "")
        if on["prohibited_country"] and c and c["prohibited"]:
            reasons.append(f"Prohibited country {t['country_iso2']}")
            tags.append("PROHIBITED_COUNTRY")
            score += 100

        # High-risk
        elif on["high_risk_corridor"] and c and (c["risk_level"] in ("HIGH_3RD","HIGH")) and float(t["base_amount"]) >= high_risk_min_amount:
            reasons.append(f"High-risk corridor {t['country_iso2']} ({c['risk_level']})")
            tags.append("HIGH_RISK_COUNTRY")
            score += int(c["score"])

        # Cash daily breach (GLOBAL)
        cash_daily_limit = float(cfg_get("cfg_cash_daily_limit", 0.0, float))
        if on["cash_daily_breach"] and cash_daily_limit > 0 and (chan == "cash" or "cash" in narrative.lower()):
            d_total = float(db.execute(
                 "SELECT SUM(base_amount) AS s FROM transactions "
                 "WHERE customer_id=? AND txn_date=? "
                 "AND (lower(IFNULL(channel,''))='cash' OR instr(lower(IFNULL(narrative,'')),'cash')>0)",
                 (t["customer_id"], t["txn_date"])
            ).fetchone()["s"] or 0)
            if d_total > cash_daily_limit:
                reasons.append(f"Cash daily limit breached (global £{cash_daily_limit:,.2f}; activity £{d_total:,.2f})")
                tags.append("CASH_DAILY_BREACH")
                score += 20        

        # Median outlier
        if on["median_outlier"] and med > 0 and float(t["base_amount"]) > med * float(median_mult):
            reasons.append(f"Significant deviation (×{t['base_amount']/med:.1f})")
            tags.append("HISTORICAL_DEVIATION")
            score += 25

        # NLP risky terms (only enabled terms)
        if on["nlp_risky_terms"] and enabled_terms:
            low = narrative.lower()
            if any(term.lower() in low for term in enabled_terms):
                reasons.append("Narrative contains risky term(s)")
                tags.append("NLP_RISK")
                score += 10

        # Expected breaches
        if on["expected_out"] and t["direction"]=="out" and expected_monthly_out>0:
            if month_out_total > expected_monthly_out * float(exp_out_factor):
                reasons.append(f"Outflows exceed expected (actual £{month_out_total:.2f})")
                tags.append("EXPECTED_BREACH_OUT")
                score += 20

        if on["expected_in"] and t["direction"]=="in" and expected_monthly_in>0:
            if month_in_total > expected_monthly_in * float(exp_in_factor):
                reasons.append(f"Inflows exceed expected (actual £{month_in_total:.2f})")
                tags.append("EXPECTED_BREACH_IN")
                score += 15

        # Structuring detection - transactions just below reporting threshold
        if on["structuring"] and structuring_threshold > 0:
            lower_bound = structuring_threshold * (1 - structuring_margin_pct / 100)
            amt = float(t["base_amount"])
            if lower_bound <= amt < structuring_threshold:
                # Count similar transactions in rolling 7-day window
                window_start = (d - timedelta(days=7)).isoformat()
                window_end = d.isoformat()
                similar_count = db.execute(
                    """SELECT COUNT(*) as cnt FROM transactions
                       WHERE customer_id=? AND txn_date BETWEEN ? AND ?
                       AND base_amount >= ? AND base_amount < ?""",
                    (t["customer_id"], window_start, window_end, lower_bound, structuring_threshold)
                ).fetchone()["cnt"]
                if similar_count >= structuring_min_count:
                    reasons.append(f"Potential structuring: {similar_count} transactions just below £{structuring_threshold:,.0f} threshold")
                    tags.append("STRUCTURING")
                    score += 30

        # Flow-through detection - funds in then out within short window
        if on["flowthrough"]:
            amt = float(t["base_amount"])
            window_start = (d - timedelta(days=flowthrough_window_days)).isoformat()
            window_end = (d + timedelta(days=flowthrough_window_days)).isoformat()
            match_lower = amt * (flowthrough_match_pct / 100)
            match_upper = amt * (2 - flowthrough_match_pct / 100)
            opposite_dir = "out" if t["direction"] == "in" else "in"

            matching_txn = db.execute(
                """SELECT id, base_amount, txn_date FROM transactions
                   WHERE customer_id=? AND direction=?
                   AND txn_date BETWEEN ? AND ?
                   AND base_amount BETWEEN ? AND ?
                   AND id != ?
                   LIMIT 1""",
                (t["customer_id"], opposite_dir, window_start, window_end, match_lower, match_upper, t["id"])
            ).fetchone()
            if matching_txn:
                reasons.append(f"Flow-through pattern: £{amt:,.2f} {t['direction']} matched by £{matching_txn['base_amount']:,.2f} {opposite_dir} within {flowthrough_window_days} days")
                tags.append("FLOW_THROUGH")
                score += 25

        # Dormancy detection - sudden activity after period of inactivity
        if on["dormancy"] and float(t["base_amount"]) >= dormancy_reactivation_amount:
            dormancy_start = (d - timedelta(days=dormancy_inactive_days)).isoformat()
            dormancy_end = (d - timedelta(days=1)).isoformat()
            recent_activity = db.execute(
                """SELECT COUNT(*) as cnt FROM transactions
                   WHERE customer_id=? AND txn_date BETWEEN ? AND ?""",
                (t["customer_id"], dormancy_start, dormancy_end)
            ).fetchone()["cnt"]
            if recent_activity == 0:
                # Check there was activity before the dormancy period
                prior_activity = db.execute(
                    """SELECT COUNT(*) as cnt FROM transactions
                       WHERE customer_id=? AND txn_date < ?""",
                    (t["customer_id"], dormancy_start)
                ).fetchone()["cnt"]
                if prior_activity > 0:
                    reasons.append(f"Dormancy reactivation: £{t['base_amount']:,.2f} after {dormancy_inactive_days}+ days of inactivity")
                    tags.append("DORMANCY_REACTIVATION")
                    score += 20

        # Velocity detection - high frequency of transactions in short window
        if on["velocity"]:
            # Convert hours to a date range (approximate using days for SQLite date functions)
            velocity_days = max(1, velocity_window_hours // 24) if velocity_window_hours >= 24 else 1
            velocity_start = (d - timedelta(days=velocity_days)).isoformat()
            velocity_end = d.isoformat()
            txn_count = db.execute(
                """SELECT COUNT(*) as cnt FROM transactions
                   WHERE customer_id=? AND txn_date BETWEEN ? AND ?""",
                (t["customer_id"], velocity_start, velocity_end)
            ).fetchone()["cnt"]
            if txn_count >= velocity_min_count:
                reasons.append(f"High velocity: {txn_count} transactions within {velocity_window_hours} hours")
                tags.append("HIGH_VELOCITY")
                score += 15

        # Severity mapping (kept even if toggle is off; but we respect it for transparency)
        if on["severity_mapping"]:
            if "PROHIBITED_COUNTRY" in tags or score >= sev_crit:
                severity = "CRITICAL"
            elif score >= sev_high:
                severity = "HIGH"
            elif score >= sev_med:
                severity = "MEDIUM"
            elif score >= sev_low:
                severity = "LOW"

        if reasons:
            db.execute(
                """INSERT INTO alerts(txn_id, customer_id, score, severity, reasons, rule_tags, config_version)
                   VALUES(?,?,?,?,?,?, (SELECT MAX(id) FROM config_versions))""",
                (t["id"], t["customer_id"], int(min(score,100)), severity,
                 json.dumps(reasons), json.dumps(list(dict.fromkeys(tags))))
            )
    db.commit()

# ---------- Routes ----------

# --- Authentication routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") and not session.get("awaiting_2fa"):
        # Check if user must change password
        if session.get("must_change_password"):
            return redirect(url_for("change_password"))
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Check account lockout
        is_locked, lock_msg = check_account_locked(username)
        if is_locked:
            flash(lock_msg)
            log_audit_event("LOGIN_BLOCKED", None, username, "Account locked")
            return render_template("login.html")
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        
        if user and check_password_hash(user["password_hash"], password):
            # Reset failed attempts on successful login
            reset_failed_login(username)
            
            # Check if 2FA is enabled for this user
            totp_enabled = False
            try:
                totp_enabled = user["totp_enabled"] and user["totp_verified"]
            except (KeyError, TypeError):
                pass
            
            if totp_enabled:
                # Store pending login in session and redirect to 2FA verification
                session["pending_user_id"] = user["id"]
                session["pending_username"] = user["username"]
                session["awaiting_2fa"] = True
                log_audit_event("LOGIN_2FA_PENDING", user["id"], username, "Awaiting 2FA verification")
                return redirect(url_for("verify_2fa"))
            
            # No 2FA - complete login
            complete_login(user)
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        else:
            # Record failed attempt
            record_failed_login(username)
            flash("Invalid username or password.")
    
    return render_template("login.html")


def complete_login(user):
    """Complete the login process after password (and optionally 2FA) verification."""
    # Clear any pending 2FA state
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("awaiting_2fa", None)
    
    # Set session
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["last_activity"] = datetime.now().isoformat()
    
    # Update last login timestamp
    db = get_db()
    db.execute("UPDATE users SET last_login=? WHERE id=?", 
               (datetime.now().isoformat(), user["id"]))
    db.commit()
    
    # Check if password change required
    if user["must_change_password"]:
        session["must_change_password"] = True
        log_audit_event("LOGIN_SUCCESS", user["id"], user["username"], "Password change required")
        flash("Welcome! You must change your password before continuing.")
        return redirect(url_for("change_password"))
    
    log_audit_event("LOGIN_SUCCESS", user["id"], user["username"])
    flash(f"Welcome, {user['username']}!")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Verify 2FA code after password authentication."""
    if not session.get("awaiting_2fa") or not session.get("pending_user_id"):
        return redirect(url_for("login"))
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["pending_user_id"],)).fetchone()
    
    if not user:
        session.clear()
        return redirect(url_for("login"))
    
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "").replace("-", "")
        use_backup = request.form.get("use_backup") == "1"
        
        verified = False
        if use_backup:
            # Try backup code
            verified = verify_backup_code(user["id"], code)
            if verified:
                log_audit_event("LOGIN_2FA_BACKUP", user["id"], user["username"], "Used backup code")
        else:
            # Try TOTP code
            verified = verify_totp(user["totp_secret"], code)
        
        if verified:
            complete_login(user)
            next_url = request.args.get("next") or url_for("dashboard")
            
            # Check if we need to redirect to password change
            if session.get("must_change_password"):
                return redirect(url_for("change_password"))
            
            return redirect(next_url)
        else:
            # Record failed 2FA attempt
            record_failed_login(user["username"])
            log_audit_event("LOGIN_2FA_FAILED", user["id"], user["username"], "Invalid 2FA code")
            flash("Invalid verification code. Please try again.")
    
    return render_template("verify_2fa.html", username=user["username"])


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Force password change for users with must_change_password flag."""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        
        # Verify current password
        if not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.")
            return render_template("change_password.html")
        
        # Check new passwords match
        if new_password != confirm_password:
            flash("New passwords do not match.")
            return render_template("change_password.html")
        
        # Validate new password against policy
        is_valid, msg = validate_password(new_password)
        if not is_valid:
            flash(msg)
            return render_template("change_password.html")
        
        # Ensure new password is different from current
        if check_password_hash(user["password_hash"], new_password):
            flash("New password must be different from current password.")
            return render_template("change_password.html")
        
        # Update password
        db.execute("""
            UPDATE users SET 
                password_hash=?, 
                must_change_password=0, 
                last_password_change=?
            WHERE id=?
        """, (generate_password_hash(new_password), datetime.now().isoformat(), session["user_id"]))
        db.commit()
        
        # Clear the flag from session
        session.pop("must_change_password", None)
        
        log_audit_event("PASSWORD_CHANGED", session["user_id"], session["username"])
        flash("Password changed successfully!")
        return redirect(url_for("dashboard"))
    
    return render_template("change_password.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    """Setup 2FA for the current user."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    
    # Check if already enabled
    try:
        if user["totp_enabled"] and user["totp_verified"]:
            flash("Two-factor authentication is already enabled.")
            return redirect(url_for("manage_2fa"))
    except (KeyError, TypeError):
        pass
    
    # Generate or retrieve secret
    try:
        secret = user["totp_secret"]
    except (KeyError, TypeError):
        secret = None
    
    if not secret:
        secret = generate_totp_secret()
        db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, session["user_id"]))
        db.commit()
    
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        
        if verify_totp(secret, code):
            # Generate backup codes
            backup_codes = generate_backup_codes()
            
            # Enable 2FA
            db.execute("""
                UPDATE users SET 
                    totp_enabled=1, 
                    totp_verified=1, 
                    backup_codes=?
                WHERE id=?
            """, (json.dumps(backup_codes), session["user_id"]))
            db.commit()
            
            log_audit_event("2FA_ENABLED", session["user_id"], session["username"], "2FA setup completed")
            
            # Show backup codes
            return render_template("2fa_backup_codes.html", 
                                   backup_codes=backup_codes, 
                                   show_success=True)
        else:
            flash("Invalid verification code. Please try again.")
    
    # Generate QR code
    qr_code = get_totp_qr_code(user["username"], secret)
    
    return render_template("setup_2fa.html", 
                           qr_code=qr_code, 
                           secret=secret,
                           username=user["username"])


@app.route("/manage-2fa", methods=["GET", "POST"])
@login_required
def manage_2fa():
    """Manage 2FA settings for the current user."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    
    if request.method == "POST":
        action = request.form.get("action", "")
        
        if action == "disable":
            # Verify password before disabling
            password = request.form.get("password", "")
            if check_password_hash(user["password_hash"], password):
                db.execute("""
                    UPDATE users SET 
                        totp_enabled=0, 
                        totp_verified=0, 
                        totp_secret=NULL, 
                        backup_codes=NULL
                    WHERE id=?
                """, (session["user_id"],))
                db.commit()
                log_audit_event("2FA_DISABLED", session["user_id"], session["username"])
                flash("Two-factor authentication has been disabled.")
                return redirect(url_for("manage_2fa"))
            else:
                flash("Incorrect password. Please try again.")
        
        elif action == "regenerate_backup":
            # Verify password before regenerating
            password = request.form.get("password", "")
            if check_password_hash(user["password_hash"], password):
                backup_codes = generate_backup_codes()
                db.execute("UPDATE users SET backup_codes=? WHERE id=?", 
                           (json.dumps(backup_codes), session["user_id"]))
                db.commit()
                log_audit_event("2FA_BACKUP_REGENERATED", session["user_id"], session["username"])
                return render_template("2fa_backup_codes.html", 
                                       backup_codes=backup_codes,
                                       show_success=False,
                                       regenerated=True)
            else:
                flash("Incorrect password. Please try again.")
    
    # Get remaining backup codes count
    backup_count = 0
    try:
        if user["backup_codes"]:
            backup_count = len(json.loads(user["backup_codes"]))
    except (KeyError, TypeError, json.JSONDecodeError):
        pass
    
    # Check if 2FA is enabled
    totp_enabled = False
    try:
        totp_enabled = user["totp_enabled"] and user["totp_verified"]
    except (KeyError, TypeError):
        pass
    
    return render_template("manage_2fa.html",
                           totp_enabled=totp_enabled,
                           backup_codes_remaining=backup_count)


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    username = session.get("username")
    session.clear()
    if user_id:
        log_audit_event("LOGOUT", user_id, username)
    flash("You have been logged out.")
    return redirect(url_for("login"))


# --- Session timeout check ---
@app.before_request
def check_session_timeout():
    """Check for session timeout on each request."""
    if session.get("user_id"):
        last_activity = session.get("last_activity")
        if last_activity:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.now() - last_time > timedelta(minutes=30):
                user_id = session.get("user_id")
                username = session.get("username")
                session.clear()
                log_audit_event("SESSION_TIMEOUT", user_id, username)
                flash("Your session has expired. Please log in again.")
                return redirect(url_for("login"))
        
        # Update last activity time
        session["last_activity"] = datetime.now().isoformat()
        
        # Force password change redirect
        if session.get("must_change_password") and request.endpoint not in ('change_password', 'logout', 'static'):
            return redirect(url_for("change_password"))

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    customer_id = request.args.get("customer_id", "").strip()
    period = request.args.get("period", "all")
    start, end = _period_bounds(period)

    # Build months list for period selector
    months = []
    cur = date.today().replace(day=1)
    for _ in range(18):
        months.append(cur.strftime("%Y-%m"))
        if cur.month == 1:
            cur = cur.replace(year=cur.year-1, month=12)
        else:
            cur = cur.replace(month=cur.month-1)

    # If no customer selected, show AGGREGATE overview across all customers
    if not customer_id:
        # Build date predicates for aggregate view
        tx_where, tx_params = [], []
        a_where, a_params = [], []
        
        if start and end:
            tx_where.append("t.txn_date BETWEEN ? AND ?")
            tx_params = [start, end]
            a_where.append("a.created_at BETWEEN ? AND ?")
            a_params = [start + " 00:00:00", end + " 23:59:59"]
        
        tx_pred = ("WHERE " + " AND ".join(tx_where)) if tx_where else ""
        a_pred = ("WHERE " + " AND ".join(a_where)) if a_where else ""
        
        # Aggregate KPIs
        total_tx = db.execute(f"SELECT COUNT(*) c FROM transactions t {tx_pred}", tx_params).fetchone()["c"]
        total_alerts = db.execute(f"SELECT COUNT(*) c FROM alerts a {a_pred}", a_params).fetchone()["c"]
        critical = db.execute(f"SELECT COUNT(*) c FROM alerts a {a_pred} {'AND' if a_pred else 'WHERE'} a.severity='CRITICAL'", a_params).fetchone()["c"]
        total_customers = db.execute("SELECT COUNT(*) c FROM customers").fetchone()["c"]
        
        kpis = {
            "total_tx": total_tx,
            "total_alerts": total_alerts,
            "alert_rate": (total_alerts / total_tx) if total_tx else 0,
            "critical": critical,
            "total_customers": total_customers,
        }
        
        # Aggregate volume tiles
        sums = db.execute(f"""
            SELECT
                SUM(CASE WHEN t.direction='in'  THEN t.base_amount ELSE 0 END) AS total_in,
                SUM(CASE WHEN t.direction='out' THEN t.base_amount ELSE 0 END) AS total_out,
                SUM(CASE WHEN t.direction='in'  AND LOWER(t.channel)='cash' THEN t.base_amount ELSE 0 END) AS cash_in,
                SUM(CASE WHEN t.direction='out' AND LOWER(t.channel)='cash' THEN t.base_amount ELSE 0 END) AS cash_out
            FROM transactions t {tx_pred}
        """, tx_params).fetchone()
        
        tiles = {
            "total_in": float(sums["total_in"] or 0),
            "total_out": float(sums["total_out"] or 0),
            "cash_in": float(sums["cash_in"] or 0),
            "cash_out": float(sums["cash_out"] or 0),
            "high_risk_volume": 0,
            "high_risk_total": 0.0,
        }
        
        # High-risk country volume
        high_risk_rows = db.execute(f"""
            SELECT COUNT(*) cnt, SUM(t.base_amount) tot
            FROM transactions t
            JOIN ref_country_risk r ON r.iso2 = t.country_iso2
            {tx_pred} {'AND' if tx_pred else 'WHERE'} r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
        """, tx_params).fetchone()
        tiles["high_risk_volume"] = int(high_risk_rows["cnt"] or 0)
        tiles["high_risk_total"] = float(high_risk_rows["tot"] or 0)
        
        # Top countries
        top_countries = db.execute(f"""
            SELECT t.country_iso2 AS iso2, COUNT(*) AS cnt, SUM(t.base_amount) AS total
            FROM transactions t
            {tx_pred} {'AND' if tx_pred else 'WHERE'} t.country_iso2 IS NOT NULL AND t.country_iso2 != ''
            GROUP BY t.country_iso2
            ORDER BY total DESC
            LIMIT 10
        """, tx_params).fetchall()
        
        # Severity breakdown for chart
        sev_rows = db.execute(f"""
            SELECT a.severity, COUNT(*) cnt FROM alerts a {a_pred} GROUP BY a.severity
        """, a_params).fetchall()
        sev_map = {r["severity"]: r["cnt"] for r in sev_rows}
        labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        values = [sev_map.get(s, 0) for s in labels]
        
        # Monthly trend
        trend_rows = db.execute(f"""
            SELECT strftime('%Y-%m', t.txn_date) AS ym,
                   SUM(CASE WHEN t.direction='in' THEN t.base_amount ELSE 0 END) AS inflow,
                   SUM(CASE WHEN t.direction='out' THEN t.base_amount ELSE 0 END) AS outflow
            FROM transactions t {tx_pred}
            GROUP BY ym ORDER BY ym
        """, tx_params).fetchall()
        trend_labels = [r["ym"] for r in trend_rows]
        trend_in = [float(r["inflow"] or 0) for r in trend_rows]
        trend_out = [float(r["outflow"] or 0) for r in trend_rows]
        
        # Customers with most alerts
        top_alert_customers = db.execute(f"""
            SELECT a.customer_id, COUNT(*) as alert_count,
                   SUM(CASE WHEN a.severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count
            FROM alerts a {a_pred}
            GROUP BY a.customer_id
            ORDER BY alert_count DESC
            LIMIT 10
        """, a_params).fetchall()

        return render_template(
            "dashboard.html",
            kpis=kpis,
            tiles=tiles,
            labels=labels, values=values,
            top_countries=top_countries,
            trend_labels=trend_labels, trend_in=trend_in, trend_out=trend_out,
            months=months,
            selected_period=period,
            filter_meta={"start": start, "end": end} if start else None,
            overview_mode=True,  # Flag for template to show aggregate view
            top_alert_customers=top_alert_customers,
            metrics={
                "avg_cash_deposits": 0.0,
                "avg_cash_withdrawals": 0.0,
                "avg_in": 0.0,
                "avg_out": 0.0,
                "max_in": 0.0,
                "max_out": 0.0,
                "overseas_value": 0.0,
                "overseas_pct": 0.0,
                "highrisk_value": 0.0,
                "highrisk_pct": 0.0,
            }
        )

    # --- Normal (filtered) dashboard below ---
    period = request.args.get("period", "all")
    start, end = _period_bounds(period)

    # Predicates for transactions and alerts
    tx_where, tx_params = ["t.customer_id = ?"], [customer_id]
    a_where, a_params = ["a.customer_id = ?"], [customer_id]

    if start and end:
        tx_where.append("t.txn_date BETWEEN ? AND ?"); tx_params += [start, end]
        a_where.append("a.created_at BETWEEN ? AND ?"); a_params += [start + " 00:00:00", end + " 23:59:59"]

    tx_pred = "WHERE " + " AND ".join(tx_where)
    a_pred  = "WHERE " + " AND ".join(a_where)

    # KPIs
    total_tx = db.execute(f"SELECT COUNT(*) c FROM transactions t {tx_pred}", tx_params).fetchone()["c"]
    total_alerts = db.execute(f"SELECT COUNT(*) c FROM alerts a {a_pred}", a_params).fetchone()["c"]
    critical = db.execute(f"SELECT COUNT(*) c FROM alerts a {a_pred} AND a.severity='CRITICAL'", a_params).fetchone()["c"]

    kpis = {
        "total_tx": total_tx,
        "total_alerts": total_alerts,
        "alert_rate": (total_alerts / total_tx) if total_tx else 0,
        "critical": critical,
    }

    # Tiles: totals, cash in/out
    sums = db.execute(f"""
      SELECT
        SUM(CASE WHEN t.direction='in'  THEN t.base_amount ELSE 0 END)  AS total_in,
        SUM(CASE WHEN t.direction='out' THEN t.base_amount ELSE 0 END)  AS total_out
      FROM transactions t {tx_pred}
    """, tx_params).fetchone()
    total_in  = float(sums["total_in"]  or 0)
    total_out = float(sums["total_out"] or 0)
    total_value = total_in + total_out

    cash = db.execute(f"""
      SELECT
        SUM(CASE WHEN t.direction='in'
                   AND lower(IFNULL(t.channel,''))='cash'
                 THEN t.base_amount ELSE 0 END) AS cash_in,
        SUM(CASE WHEN t.direction='out'
                   AND lower(IFNULL(t.channel,''))='cash'
                 THEN t.base_amount ELSE 0 END) AS cash_out
      FROM transactions t {tx_pred}
    """, tx_params).fetchone()
    cash_in  = float(cash["cash_in"]  or 0)
    cash_out = float(cash["cash_out"] or 0)

    # High/High-3rd/Prohibited corridors — count AND total £
    hr = db.execute(f"""
      SELECT COUNT(*) AS cnt, SUM(t.base_amount) AS total
      FROM transactions t
      JOIN ref_country_risk r ON r.iso2 = IFNULL(t.country_iso2, '')
      {tx_pred + (' AND ' if tx_pred else 'WHERE ')} r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
    """, tx_params).fetchone()
    high_risk_volume = int(hr["cnt"] or 0)
    high_risk_total  = float(hr["total"] or 0)

    tiles = {
        "total_in": total_in,
        "total_out": total_out,
        "cash_in": cash_in,
        "cash_out": cash_out,
        "high_risk_volume": high_risk_volume,  # (you can ignore in template if you don't want to show the count)
        "high_risk_total": high_risk_total,
    }

    # Alerts over time — group by TRANSACTION DATE (t.txn_date)
    if start and end:
        aot_sql = """
          SELECT strftime('%Y-%m-%d', t.txn_date) d, COUNT(*) c
          FROM alerts a
          JOIN transactions t ON t.id = a.txn_id
          WHERE t.customer_id = ? AND t.txn_date BETWEEN ? AND ?
          GROUP BY d ORDER BY d
        """
        aot_params = [customer_id, start, end]
    else:
        aot_sql = """
          SELECT strftime('%Y-%m-%d', t.txn_date) d, COUNT(*) c
          FROM alerts a
          JOIN transactions t ON t.id = a.txn_id
          WHERE t.customer_id = ?
          GROUP BY d ORDER BY d
        """
        aot_params = [customer_id]
    rows = db.execute(aot_sql, aot_params).fetchall()
    labels = [r["d"] for r in rows]
    values = [int(r["c"]) for r in rows]

    # Top countries (alerts) — show full country names
    tc_rows = db.execute(f"""
      SELECT t.country_iso2, COUNT(*) cnt
      FROM alerts a
      JOIN transactions t ON t.id = a.txn_id
      {a_pred}
      GROUP BY t.country_iso2
      ORDER BY cnt DESC
      LIMIT 10
    """, a_params).fetchall()
    top_countries = [
        {"name": country_full_name(r["country_iso2"]), "cnt": int(r["cnt"] or 0)}
        for r in tc_rows
    ]

    # Monthly trend of money in/out with cash breakdown (ALL TIME for this customer)
    trend_rows = db.execute("""
      SELECT strftime('%Y-%m', t.txn_date) ym,
             SUM(CASE WHEN t.direction='in'  THEN t.base_amount ELSE 0 END) AS in_sum,
             SUM(CASE WHEN t.direction='out' THEN t.base_amount ELSE 0 END) AS out_sum,
             SUM(CASE WHEN t.direction='in'  AND LOWER(IFNULL(t.channel,''))='cash' THEN t.base_amount ELSE 0 END) AS cash_in_sum,
             SUM(CASE WHEN t.direction='out' AND LOWER(IFNULL(t.channel,''))='cash' THEN t.base_amount ELSE 0 END) AS cash_out_sum
      FROM transactions t
      WHERE t.customer_id = ?
      GROUP BY ym
      ORDER BY ym
    """, [customer_id]).fetchall()
    trend_labels = [r["ym"] for r in trend_rows]
    trend_in  = [float(r["in_sum"]  or 0) for r in trend_rows]
    trend_out = [float(r["out_sum"] or 0) for r in trend_rows]
    trend_cash_in = [float(r["cash_in_sum"] or 0) for r in trend_rows]
    trend_cash_out = [float(r["cash_out_sum"] or 0) for r in trend_rows]

    # Reviewer metrics (averages, highs, overseas, high-risk % etc.)
    m = db.execute(f"""
      SELECT
        AVG(CASE WHEN t.direction='in'  AND lower(IFNULL(t.channel,''))='cash' THEN t.base_amount END) AS avg_cash_in,
        AVG(CASE WHEN t.direction='out' AND lower(IFNULL(t.channel,''))='cash' THEN t.base_amount END) AS avg_cash_out,
        AVG(CASE WHEN t.direction='in'  THEN t.base_amount END) AS avg_in,
        AVG(CASE WHEN t.direction='out' THEN t.base_amount END) AS avg_out,
        MAX(CASE WHEN t.direction='in'  THEN t.base_amount END) AS max_in,
        MAX(CASE WHEN t.direction='out' THEN t.base_amount END) AS max_out,
        SUM(CASE WHEN IFNULL(t.country_iso2,'')<>'' AND UPPER(t.country_iso2)<>'GB' AND t.direction='in' THEN t.base_amount ELSE 0 END) AS overseas_in,
        SUM(CASE WHEN IFNULL(t.country_iso2,'')<>'' AND UPPER(t.country_iso2)<>'GB' AND t.direction='out' THEN t.base_amount ELSE 0 END) AS overseas_out,
        SUM(t.base_amount) AS total_value
      FROM transactions t {tx_pred}
    """, tx_params).fetchone()

    avg_cash_deposits     = float(m["avg_cash_in"]  or 0.0)
    avg_cash_withdrawals  = float(m["avg_cash_out"] or 0.0)
    avg_in                = float(m["avg_in"]       or 0.0)
    avg_out               = float(m["avg_out"]      or 0.0)
    max_in                = float(m["max_in"]       or 0.0)
    max_out               = float(m["max_out"]      or 0.0)
    overseas_in           = float(m["overseas_in"] or 0.0)
    overseas_out          = float(m["overseas_out"] or 0.0)
    total_val_from_query  = float(m["total_value"]  or 0.0)
    # Use the earlier computed total_value if present; else fall back
    denom_total = total_value if total_value > 0 else total_val_from_query

    hr_val_row = db.execute(f"""
      SELECT SUM(t.base_amount) AS v
      FROM transactions t
      JOIN ref_country_risk r ON r.iso2 = IFNULL(t.country_iso2, '')
      {tx_pred + (' AND ' if tx_pred else 'WHERE ')} r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
    """, tx_params).fetchone()
    highrisk_value = float(hr_val_row["v"] or 0.0)
    highrisk_pct   = (highrisk_value / denom_total * 100.0) if denom_total > 0 else 0.0

    metrics = {
        "avg_cash_deposits": avg_cash_deposits,
        "avg_cash_withdrawals": avg_cash_withdrawals,
        "avg_in": avg_in,
        "avg_out": avg_out,
        "max_in": max_in,
        "max_out": max_out,
        "overseas_in": overseas_in,
        "overseas_out": overseas_out,
        "highrisk_value": highrisk_value,
        "highrisk_pct": highrisk_pct,
    }

    # Month options (last 18 months)
    months = []
    cur = date.today().replace(day=1)
    for _ in range(18):
        months.append(cur.strftime("%Y-%m"))
        if cur.month == 1:
            cur = cur.replace(year=cur.year-1, month=12)
        else:
            cur = cur.replace(month=cur.month-1)

    return render_template(
        "dashboard.html",
        kpis=kpis,
        labels=labels, values=values,
        top_countries=top_countries,
        tiles=tiles,
        trend_labels=trend_labels, 
        trend_in=trend_in, 
        trend_out=trend_out,
        trend_cash_in=trend_cash_in,
        trend_cash_out=trend_cash_out,
        months=months,
        selected_period=period,
        filter_meta={"customer_id": customer_id},
        metrics=metrics,
    )

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    """Statement upload page - reviewers can upload transaction CSVs for specific customers."""
    init_db()
    ensure_customers_table()
    ensure_statements_table()
    
    db = get_db()
    
    # Get list of customers for dropdown
    customers = db.execute("SELECT customer_id, customer_name FROM customers WHERE status='active' ORDER BY customer_id").fetchall()
    
    # Get selected customer's statement history
    selected_customer = request.args.get("customer_id", "").strip()
    statements = []
    if selected_customer:
        statements = db.execute("""
            SELECT s.*, u.username as uploaded_by_name
            FROM statements s
            LEFT JOIN users u ON u.id = s.uploaded_by
            WHERE s.customer_id = ?
            ORDER BY s.uploaded_at DESC
        """, (selected_customer,)).fetchall()
    
    if request.method == "POST":
        customer_id = request.form.get("customer_id", "").strip()
        tx_file = request.files.get("tx_file")
        
        if not customer_id:
            flash("Please select a customer.")
            return redirect(url_for("upload"))
        
        # Verify customer exists
        cust = db.execute("SELECT * FROM customers WHERE customer_id=?", (customer_id,)).fetchone()
        if not cust:
            flash(f"Customer {customer_id} not found in the system.")
            return redirect(url_for("upload"))
        
        if not tx_file or not tx_file.filename:
            flash("Please select a transaction file to upload.")
            return redirect(url_for("upload", customer_id=customer_id))
        
        try:
            n, date_from, date_to = ingest_transactions_csv_for_customer(tx_file, customer_id)
            
            # Create statement record
            user_id = session.get("user_id")
            db.execute("""
                INSERT INTO statements(customer_id, filename, uploaded_by, record_count, date_from, date_to)
                VALUES(?, ?, ?, ?, ?, ?)
            """, (customer_id, tx_file.filename, user_id, n, date_from, date_to))
            db.commit()
            
            flash(f"Loaded {n} transactions for customer {customer_id} ({tx_file.filename})")
        except ValueError as e:
            flash(f"Error: {e}")
        
        return redirect(url_for("upload", customer_id=customer_id))
    
    return render_template("upload.html", customers=customers, selected_customer=selected_customer, statements=statements)

@app.route("/alerts")
@login_required
def alerts():
    db = get_db()

    # Read filters
    sev  = (request.args.get("severity") or "").strip().upper()
    cust = (request.args.get("customer_id") or "").strip()
    tag  = (request.args.get("tag") or "").strip()  # NEW

    # Base query (severity / customer handled in SQL)
    where, params = [], []
    if sev:
        where.append("a.severity = ?"); params.append(sev)
    if cust:
        where.append("a.customer_id = ?"); params.append(cust)

    sql = f"""
      SELECT a.*, t.country_iso2, t.txn_date
        FROM alerts a
        LEFT JOIN transactions t ON t.id = a.txn_id
       {('WHERE ' + ' AND '.join(where)) if where else ''}
       ORDER BY 
         CASE a.severity 
           WHEN 'CRITICAL' THEN 1 
           WHEN 'HIGH' THEN 2 
           WHEN 'MEDIUM' THEN 3 
           WHEN 'LOW' THEN 4 
           ELSE 5 
         END,
         t.txn_date DESC, 
         a.created_at DESC
       LIMIT 5000
    """
    rows = db.execute(sql, params).fetchall()

    # Build tag list (from the SQL-filtered set before applying 'tag')
    tag_set = set()
    for r in rows:
        try:
            for tg in json.loads(r["rule_tags"] or "[]"):
                if tg:
                    tag_set.add(str(tg))
        except Exception:
            pass
    available_tags = sorted(tag_set)

    # Apply tag filter in Python (robust even without SQLite JSON1)
    out = []
    for r in rows:
        d = dict(r)
        try:
            reasons_list = json.loads(d.get("reasons") or "[]")
        except Exception:
            reasons_list = [d.get("reasons")] if d.get("reasons") else []

        try:
            tags_list = json.loads(d.get("rule_tags") or "[]")
        except Exception:
            tags_list = []

        # If a tag is selected, keep only rows that include it
        if tag and tag not in tags_list:
            continue

        # Flatten for table display
        d["reasons"]   = ", ".join(x for x in reasons_list if x)
        d["rule_tags"] = ", ".join(tags_list)
        
        # Format dates in UK format (DD/MM/YYYY)
        if d.get("txn_date"):
            try:
                from datetime import datetime
                dt = datetime.strptime(d["txn_date"], "%Y-%m-%d")
                d["txn_date_uk"] = dt.strftime("%d/%m/%Y")
            except:
                d["txn_date_uk"] = d["txn_date"]
        
        if d.get("created_at"):
            try:
                from datetime import datetime
                # Handle both datetime formats
                ca = d["created_at"][:19] if len(d["created_at"]) > 19 else d["created_at"]
                dt = datetime.strptime(ca, "%Y-%m-%d %H:%M:%S")
                d["created_at_uk"] = dt.strftime("%d/%m/%Y %H:%M")
            except:
                d["created_at_uk"] = d["created_at"][:16] if d["created_at"] else "—"
        
        out.append(d)

    return render_template(
        "alerts.html",
        alerts=out,
        available_tags=available_tags,  # for the dropdown
    )

# ---------- Admin: Customer Management ----------
@app.route("/admin/customers", methods=["GET", "POST"])
@admin_required
def admin_customers():
    """Admin page for managing customer population."""
    ensure_customers_table()
    db = get_db()
    
    if request.method == "POST":
        action = request.form.get("action", "")
        
        if action == "upload":
            # Upload customer population CSV
            cust_file = request.files.get("customer_file")
            if cust_file and cust_file.filename:
                try:
                    import pandas as pd
                    df = pd.read_csv(cust_file)
                    
                    # Normalize column names
                    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
                    
                    if "customer_id" not in df.columns:
                        flash("CSV must have a 'customer_id' column.")
                        return redirect(url_for("admin_customers"))
                    
                    n_added = 0
                    for _, r in df.iterrows():
                        cust_id = str(r.get("customer_id", "")).strip()
                        if not cust_id:
                            continue
                        db.execute("""
                            INSERT INTO customers(customer_id, customer_name, business_type, onboarded_date, status)
                            VALUES(?, ?, ?, ?, ?)
                            ON CONFLICT(customer_id) DO UPDATE SET
                                customer_name=excluded.customer_name,
                                business_type=excluded.business_type,
                                onboarded_date=excluded.onboarded_date,
                                status=excluded.status,
                                updated_at=CURRENT_TIMESTAMP
                        """, (
                            cust_id,
                            str(r.get("customer_name", "")).strip() or None,
                            str(r.get("business_type", "")).strip() or None,
                            str(r.get("onboarded_date", "")).strip() or None,
                            str(r.get("status", "active")).strip() or "active",
                        ))
                        n_added += 1
                    db.commit()
                    flash(f"Uploaded {n_added} customer(s).")
                except Exception as e:
                    flash(f"Error uploading customers: {e}")
            else:
                flash("Please select a CSV file.")
        
        elif action == "add":
            # Add single customer
            cust_id = request.form.get("customer_id", "").strip()
            if cust_id:
                db.execute("""
                    INSERT INTO customers(customer_id, customer_name, business_type, onboarded_date, status)
                    VALUES(?, ?, ?, ?, ?)
                    ON CONFLICT(customer_id) DO UPDATE SET
                        customer_name=excluded.customer_name,
                        business_type=excluded.business_type,
                        onboarded_date=excluded.onboarded_date,
                        status=excluded.status,
                        updated_at=CURRENT_TIMESTAMP
                """, (
                    cust_id,
                    request.form.get("customer_name", "").strip() or None,
                    request.form.get("business_type", "").strip() or None,
                    request.form.get("onboarded_date", "").strip() or None,
                    request.form.get("status", "active").strip() or "active",
                ))
                db.commit()
                flash(f"Customer {cust_id} saved.")
            else:
                flash("Customer ID is required.")
        
        elif action == "delete":
            cust_id = request.form.get("customer_id", "").strip()
            if cust_id:
                db.execute("DELETE FROM customers WHERE customer_id=?", (cust_id,))
                db.commit()
                flash(f"Customer {cust_id} deleted.")
        
        return redirect(url_for("admin_customers"))
    
    # GET: list customers
    customers = db.execute("""
        SELECT c.*, 
               (SELECT COUNT(*) FROM transactions t WHERE t.customer_id = c.customer_id) as txn_count,
               (SELECT COUNT(*) FROM statements s WHERE s.customer_id = c.customer_id) as statement_count
        FROM customers c
        ORDER BY c.customer_id
    """).fetchall()
    
    return render_template("admin_customers.html", customers=customers)

# ---------- Admin: User Management ----------
@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    """Admin page for managing users."""
    ensure_users_table()
    ensure_audit_log_table()
    db = get_db()
    
    if request.method == "POST":
        action = request.form.get("action", "")
        
        if action == "add":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            role = request.form.get("role", "reviewer").strip()
            send_email_flag = request.form.get("send_email") == "on"
            
            if not username:
                flash("Username is required.")
            elif role not in ("admin", "reviewer"):
                flash("Invalid role.")
            else:
                existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                if existing:
                    flash(f"Username '{username}' already exists.")
                else:
                    # Generate temporary password that meets policy
                    temp_password = secrets.token_urlsafe(8) + "A1!"  # Ensures complexity
                    
                    db.execute(
                        """INSERT INTO users(username, email, password_hash, role, must_change_password) 
                           VALUES(?, ?, ?, ?, 1)""",
                        (username, email or None, generate_password_hash(temp_password), role)
                    )
                    db.commit()
                    
                    log_audit_event("USER_CREATED", session.get("user_id"), session.get("username"),
                                  f"Created user '{username}' with role '{role}'")
                    
                    # Send welcome email if configured and email provided
                    email_status = ""
                    if send_email_flag and email:
                        success, msg = send_welcome_email(username, email, temp_password)
                        if success:
                            email_status = " Welcome email sent."
                        else:
                            email_status = f" Email failed: {msg}"
                    
                    flash(f"User '{username}' created as {role}. Temporary password: {temp_password}{email_status}")
        
        elif action == "update":
            user_id = request.form.get("user_id")
            new_role = request.form.get("role", "").strip()
            new_email = request.form.get("email", "").strip()
            new_password = request.form.get("new_password", "").strip()
            force_password_change = request.form.get("force_password_change") == "on"
            
            if user_id:
                target_user = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
                updates = []
                
                if new_role in ("admin", "reviewer"):
                    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
                    updates.append(f"role={new_role}")
                
                if new_email is not None:
                    db.execute("UPDATE users SET email=? WHERE id=?", (new_email or None, user_id))
                
                if new_password:
                    # Validate password policy
                    is_valid, msg = validate_password(new_password)
                    if not is_valid:
                        flash(f"Password policy error: {msg}")
                        return redirect(url_for("admin_users"))
                    
                    db.execute("UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?", 
                              (generate_password_hash(new_password), user_id))
                    updates.append("password reset")
                
                if force_password_change:
                    db.execute("UPDATE users SET must_change_password=1 WHERE id=?", (user_id,))
                    updates.append("must change password")
                
                # Handle 2FA reset
                reset_2fa = request.form.get("reset_2fa") == "on"
                if reset_2fa:
                    db.execute("""
                        UPDATE users SET 
                            totp_enabled=0, 
                            totp_verified=0, 
                            totp_secret=NULL, 
                            backup_codes=NULL 
                        WHERE id=?
                    """, (user_id,))
                    updates.append("2FA reset")
                
                db.commit()
                
                if updates and target_user:
                    log_audit_event("USER_UPDATED", session.get("user_id"), session.get("username"),
                                  f"Updated user '{target_user['username']}': {', '.join(updates)}")
                
                flash("User updated.")
        
        elif action == "delete":
            user_id = request.form.get("user_id")
            current_user_id = session.get("user_id")
            if user_id and int(user_id) != current_user_id:
                target_user = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
                db.execute("DELETE FROM users WHERE id=?", (user_id,))
                db.commit()
                
                if target_user:
                    log_audit_event("USER_DELETED", session.get("user_id"), session.get("username"),
                                  f"Deleted user '{target_user['username']}'")
                
                flash("User deleted.")
            else:
                flash("Cannot delete yourself.")
        
        elif action == "unlock":
            user_id = request.form.get("user_id")
            if user_id:
                target_user = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
                db.execute("UPDATE users SET locked_until=NULL, failed_login_attempts=0 WHERE id=?", (user_id,))
                db.commit()
                
                if target_user:
                    log_audit_event("USER_UNLOCKED", session.get("user_id"), session.get("username"),
                                  f"Unlocked user '{target_user['username']}'")
                
                flash("User account unlocked.")
        
        elif action == "toggle_2fa_enforcement":
            current = cfg_get('cfg_enforce_2fa', False, bool)
            cfg_set('cfg_enforce_2fa', not current)
            status = "enabled" if not current else "disabled"
            log_audit_event("2FA_ENFORCEMENT_CHANGED", session.get("user_id"), session.get("username"),
                          f"2FA enforcement {status}")
            flash(f"Two-factor authentication enforcement has been {status}.")
        
        return redirect(url_for("admin_users"))
    
    # GET: list users with extended info
    users = db.execute("""
        SELECT id, username, email, role, must_change_password, 
               failed_login_attempts, locked_until, last_login, created_at,
               totp_enabled, totp_verified
        FROM users ORDER BY username
    """).fetchall()
    
    # Get SMTP configuration status
    smtp_configured = bool(cfg_get('cfg_smtp_host', '', str))
    
    # Get 2FA enforcement status
    enforce_2fa = cfg_get('cfg_enforce_2fa', False, bool)
    
    return render_template("admin_users.html", users=users, smtp_configured=smtp_configured, enforce_2fa=enforce_2fa)


# ---------- Admin: SMTP Email Settings ----------
@app.route("/admin/smtp", methods=["GET", "POST"])
@admin_required
def admin_smtp():
    """Admin page for configuring SMTP email settings."""
    if request.method == "POST":
        action = request.form.get("action", "")
        
        if action == "save":
            cfg_set("cfg_smtp_host", request.form.get("smtp_host", "").strip())
            cfg_set("cfg_smtp_port", int(request.form.get("smtp_port") or 587))
            cfg_set("cfg_smtp_username", request.form.get("smtp_username", "").strip())
            # Use encrypted storage for password
            smtp_password = request.form.get("smtp_password", "").strip()
            if smtp_password:  # Only update if a new password is provided
                set_smtp_password(smtp_password)
            cfg_set("cfg_smtp_from_email", request.form.get("smtp_from_email", "").strip())
            cfg_set("cfg_smtp_from_name", request.form.get("smtp_from_name", "").strip() or "Transaction Review Tool")
            cfg_set("cfg_smtp_use_tls", request.form.get("smtp_use_tls") == "on")
            
            log_audit_event("SMTP_CONFIG_UPDATED", session.get("user_id"), session.get("username"))
            flash("SMTP settings saved. Password is encrypted at rest.")
        
        elif action == "test":
            test_email = request.form.get("test_email", "").strip()
            if test_email:
                success, msg = send_email(
                    test_email,
                    "Transaction Review Tool - Test Email",
                    "<h2>Test Email</h2><p>This is a test email from Transaction Review Tool.</p><p>If you received this, your SMTP configuration is working correctly!</p>",
                    "Test Email\n\nThis is a test email from Transaction Review Tool.\n\nIf you received this, your SMTP configuration is working correctly!"
                )
                if success:
                    flash(f"Test email sent successfully to {test_email}!")
                else:
                    flash(f"Test email failed: {msg}")
            else:
                flash("Please enter a test email address.")
        
        return redirect(url_for("admin_smtp"))
    
    # GET: show current settings (mask password for display)
    raw_password = cfg_get("cfg_smtp_password", "", str)
    has_password = bool(raw_password)
    
    smtp_config = {
        "host": cfg_get("cfg_smtp_host", "", str),
        "port": cfg_get("cfg_smtp_port", 587, int),
        "username": cfg_get("cfg_smtp_username", "", str),
        "password_set": has_password,  # Don't expose actual password
        "from_email": cfg_get("cfg_smtp_from_email", "", str),
        "from_name": cfg_get("cfg_smtp_from_name", "Transaction Review Tool", str),
        "use_tls": cfg_get("cfg_smtp_use_tls", True, bool),
    }
    
    return render_template("admin_smtp.html", smtp=smtp_config)


# ---------- Admin: Audit Log ----------
@app.route("/admin/audit-log")
@admin_required
def admin_audit_log():
    """View security audit log."""
    ensure_audit_log_table()
    db = get_db()
    
    # Filter parameters
    event_type = request.args.get("event_type", "").strip()
    username = request.args.get("username", "").strip()
    days = int(request.args.get("days") or 7)
    
    where = ["created_at >= datetime('now', ?)"]
    params = [f"-{days} days"]
    
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    if username:
        where.append("username LIKE ?")
        params.append(f"%{username}%")
    
    logs = db.execute(f"""
        SELECT * FROM audit_log
        WHERE {' AND '.join(where)}
        ORDER BY created_at DESC
        LIMIT 1000
    """, params).fetchall()
    
    # Get distinct event types for filter dropdown
    event_types = db.execute("SELECT DISTINCT event_type FROM audit_log ORDER BY event_type").fetchall()
    
    return render_template("admin_audit_log.html", logs=logs, event_types=event_types,
                          filter_event_type=event_type, filter_username=username, filter_days=days)


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    countries = db.execute("SELECT * FROM ref_country_risk ORDER BY iso2").fetchall()

    # Parameters shown/edited in the UI
    params = {
        "cfg_high_risk_min_amount": float(cfg_get("cfg_high_risk_min_amount", 0.0)),
        "cfg_median_multiplier":    float(cfg_get("cfg_median_multiplier", 3.0)),
        "cfg_expected_out_factor":  float(cfg_get("cfg_expected_out_factor", 1.2)),
        "cfg_expected_in_factor":   float(cfg_get("cfg_expected_in_factor", 1.2)),
        "cfg_sev_critical":         int(cfg_get("cfg_sev_critical", 90)),
        "cfg_sev_high":             int(cfg_get("cfg_sev_high", 70)),
        "cfg_sev_medium":           int(cfg_get("cfg_sev_medium", 50)),
        "cfg_sev_low":              int(cfg_get("cfg_sev_low", 30)),
        "cfg_ai_use_llm":           bool(cfg_get("cfg_ai_use_llm", False)),
        "cfg_ai_model":             str(cfg_get("cfg_ai_model", "gpt-4o-mini")),
        "cfg_risky_terms2":         cfg_get("cfg_risky_terms2", [], list),
        "cfg_cash_daily_limit":     float(cfg_get("cfg_cash_daily_limit", 0.0)),
        # Wolfsberg rule parameters
        "cfg_structuring_threshold":       float(cfg_get("cfg_structuring_threshold", 10000.0)),
        "cfg_structuring_margin_pct":      float(cfg_get("cfg_structuring_margin_pct", 15.0)),
        "cfg_structuring_min_count":       int(cfg_get("cfg_structuring_min_count", 2)),
        "cfg_flowthrough_window_days":     int(cfg_get("cfg_flowthrough_window_days", 3)),
        "cfg_flowthrough_match_pct":       float(cfg_get("cfg_flowthrough_match_pct", 80.0)),
        "cfg_dormancy_inactive_days":      int(cfg_get("cfg_dormancy_inactive_days", 90)),
        "cfg_dormancy_reactivation_amount": float(cfg_get("cfg_dormancy_reactivation_amount", 5000.0)),
        "cfg_velocity_window_hours":       int(cfg_get("cfg_velocity_window_hours", 24)),
        "cfg_velocity_min_count":          int(cfg_get("cfg_velocity_min_count", 5)),
    }

    # Rule toggles
    toggles = {
        "prohibited_country": bool(cfg_get("cfg_rule_enabled_prohibited_country", True)),
        "high_risk_corridor": bool(cfg_get("cfg_rule_enabled_high_risk_corridor", True)),
        "median_outlier":     bool(cfg_get("cfg_rule_enabled_median_outlier", True)),
        "nlp_risky_terms":    bool(cfg_get("cfg_rule_enabled_nlp_risky_terms", True)),
        "expected_out":       bool(cfg_get("cfg_rule_enabled_expected_out", True)),
        "expected_in":        bool(cfg_get("cfg_rule_enabled_expected_in", True)),
        "cash_daily_breach":  bool(cfg_get("cfg_rule_enabled_cash_daily_breach", True)),
        "severity_mapping":   bool(cfg_get("cfg_rule_enabled_severity_mapping", True)),
        "structuring":        bool(cfg_get("cfg_rule_enabled_structuring", True)),
        "flowthrough":        bool(cfg_get("cfg_rule_enabled_flowthrough", True)),
        "dormancy":           bool(cfg_get("cfg_rule_enabled_dormancy", True)),
        "velocity":           bool(cfg_get("cfg_rule_enabled_velocity", True)),
    }

    return render_template(
        "admin.html",
        countries=countries,
        params=params,
        toggles=toggles,
        builtin_rules=builtin_rules_catalog(),  # uses your catalog helper
    )

@app.post("/admin/country")
@admin_required
def admin_country():
    iso2 = request.form.get("iso2","").upper().strip()
    level = request.form.get("risk_level","MEDIUM").strip()
    score = int(request.form.get("score","0"))
    prohibited = 1 if request.form.get("prohibited") else 0
    if not iso2: abort(400)
    upsert_country(iso2, level, score, prohibited)
    flash(f"Country {iso2} saved.")
    return redirect(url_for("admin"))

@app.post("/admin/rule-params")
@admin_required
def admin_rule_params():
    """Persist numeric parameters, severity thresholds, and AI toggles."""
    # Numbers / floats
    cfg_set("cfg_high_risk_min_amount", float(request.form.get("cfg_high_risk_min_amount") or 0))
    cfg_set("cfg_median_multiplier",    float(request.form.get("cfg_median_multiplier") or 3.0))
    cfg_set("cfg_expected_out_factor",  float(request.form.get("cfg_expected_out_factor") or 1.2))
    cfg_set("cfg_expected_in_factor",   float(request.form.get("cfg_expected_in_factor") or 1.2))
    cfg_set("cfg_cash_daily_limit",     float(request.form.get("cfg_cash_daily_limit") or 0))

    # Wolfsberg rule parameters
    cfg_set("cfg_structuring_threshold",       float(request.form.get("cfg_structuring_threshold") or 10000.0))
    cfg_set("cfg_structuring_margin_pct",      float(request.form.get("cfg_structuring_margin_pct") or 15.0))
    cfg_set("cfg_structuring_min_count",       int(request.form.get("cfg_structuring_min_count") or 2))
    cfg_set("cfg_flowthrough_window_days",     int(request.form.get("cfg_flowthrough_window_days") or 3))
    cfg_set("cfg_flowthrough_match_pct",       float(request.form.get("cfg_flowthrough_match_pct") or 80.0))
    cfg_set("cfg_dormancy_inactive_days",      int(request.form.get("cfg_dormancy_inactive_days") or 90))
    cfg_set("cfg_dormancy_reactivation_amount", float(request.form.get("cfg_dormancy_reactivation_amount") or 5000.0))
    cfg_set("cfg_velocity_window_hours",       int(request.form.get("cfg_velocity_window_hours") or 24))
    cfg_set("cfg_velocity_min_count",          int(request.form.get("cfg_velocity_min_count") or 5))

    # Severities
    cfg_set("cfg_sev_critical", int(request.form.get("cfg_sev_critical") or 90))
    cfg_set("cfg_sev_high",     int(request.form.get("cfg_sev_high") or 70))
    cfg_set("cfg_sev_medium",   int(request.form.get("cfg_sev_medium") or 50))
    cfg_set("cfg_sev_low",      int(request.form.get("cfg_sev_low") or 30))

    # AI
    cfg_set("cfg_ai_use_llm", bool(request.form.get("cfg_ai_use_llm")))
    cfg_set("cfg_ai_model", (request.form.get("cfg_ai_model") or "gpt-4o-mini").strip())

    flash("Rule parameters saved.")
    return redirect(url_for("admin") + "#rule-params")

# --- helper to rewrite questions into natural sentences ---
def _enrich_questions_with_sentences(questions):
    """Take the structured question rows and rewrite into natural language sentences with country names, dates, amounts."""
    enriched = []
    for q in questions:
        if not q.get("sources"):
            enriched.append(q)
            continue

        # Example: "2025-09-11 OUT £577.89 (RU)"
        refs = []
        for s in q["sources"]:
            parts = []
            if s.get("date"): parts.append(s["date"])
            if s.get("direction"): parts.append(s["direction"])
            if s.get("amount"): parts.append(f"£{s['amount']}")
            if s.get("country"): parts.append(s["country_full"])  # assume you already map iso2->full
            if s.get("txn_id"): parts.append(f"Txn {s['txn_id']}")
            refs.append(" ".join(parts))

        # Collapse into a friendly sentence
        joined = "; ".join(refs)
        q["question"] = f"{q['question']} For reference: {joined}"
        enriched.append(q)

    return enriched


def _month_bounds_for(date_str: str):
    d = date.fromisoformat(date_str)
    start = d.replace(day=1)
    # end of month
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
    return start.isoformat(), end.isoformat()

def _expected_vs_actual_month(customer_id: str, direction: str, any_date: str):
    """Return (expected_x, actual_y, ym_label) for the month containing any_date."""
    db = get_db()
    start, end = _month_bounds_for(any_date)
    # Actual month sum for that direction
    y = float(db.execute(
        "SELECT SUM(base_amount) s FROM transactions "
        "WHERE customer_id=? AND direction=? AND txn_date BETWEEN ? AND ?",
        (customer_id, direction.lower(), start, end)
    ).fetchone()["s"] or 0.0)
    # Expected from KYC profile
    kyc = db.execute(
        "SELECT expected_monthly_in, expected_monthly_out FROM kyc_profile WHERE customer_id=?",
        (customer_id,)
    ).fetchone()
    exp_in  = float(kyc["expected_monthly_in"]  or 0.0) if kyc else 0.0
    exp_out = float(kyc["expected_monthly_out"] or 0.0) if kyc else 0.0
    x = exp_in if direction.lower()=="in" else exp_out
    ym = start[:7]
    return x, y, ym

def _median_for_direction(customer_id: str, direction: str):
    """Return median amount for all txns for this customer+direction (0.0 if none)."""
    import statistics
    rows = get_db().execute(
        "SELECT base_amount FROM transactions WHERE customer_id=? AND direction=?",
        (customer_id, direction.lower())
    ).fetchall()
    vals = [float(r["base_amount"] or 0.0) for r in rows if r["base_amount"] is not None]
    if not vals:
        return 0.0
    try:
        return float(statistics.median(vals))
    except statistics.StatisticsError:
        return 0.0

def _risky_terms_used(narratives: list):
    """Return sorted unique risky terms that appear in the provided narratives."""
    terms = cfg_get("cfg_risky_terms2", [], list)
    needles = [t["term"] for t in terms if isinstance(t, dict) and t.get("enabled")]
    text = " ".join(narratives).lower()
    hits = sorted({w for w in needles if w.lower() in text})
    return hits

def _closing_prompt_for_base_question(base_q: str, tag: str) -> str:
    tag = (tag or "").upper()
    q = (base_q or "").lower()

    if tag == "CASH_DAILY_BREACH":
        return "Please explain the reason for the recent level of cash activity on your account."

    if tag == "HISTORICAL_DEVIATION":
        return "We’ve seen a spike compared to your typical activity. What is the reason, and should we expect similar amounts going forward?"

    if tag == "EXPECTED_BREACH_OUT":
        return "Your outgoings are higher than you previously told us to expect. What is the reason, and should we expect this level to continue?"

    if tag == "EXPECTED_BREACH_IN":
        return "Your incomings are higher than you previously told us to expect. What is the reason, and should we expect this level to continue?"

    if tag == "NLP_RISK" or "narrative" in q or "documentation" in q:
        return "Please clarify the purpose of the payment(s) and your relationship with the payer/payee, and share any supporting documents (e.g., invoices/contracts)."

    if "relationship" in q or "party you made the payment to" in q:
        return "Please tell us who the payment(s) were to and your relationship with the recipient(s)."

    if tag in ("PROHIBITED_COUNTRY", "HIGH_RISK_COUNTRY"):
        return "Please confirm the reasons for these transactions."

    return "Please provide further details."

def _question_sentence_for_row(row: dict) -> str:
    """
    Tag-aware, data-enriched outreach sentence builder.
    """
    tag = (row.get("tag") or "").upper()
    details = row.get("source_details") or []

    # If nothing to enrich, ensure we end with a question mark.
    if not details:
        base = (row.get("question") or "").strip()
        return base if base.endswith("?") else (base + "?") if base else ""

    # Normalise details we need
    norm = []
    for s in details:
        norm.append({
            "date": s["txn_date"],
            "amount": float(s.get("base_amount") or 0.0),
            "direction": "OUT" if (s.get("direction") or "").lower() == "out" else "IN",
            "country": country_full_name(s.get("country_iso2") or ""),
            "customer_id": s.get("customer_id"),
            "channel": (s.get("channel") or "").lower(),
            "narrative": s.get("narrative") or "",
        })
    norm.sort(key=lambda x: x["date"])

    def _fmt_date(d: str) -> str:
        dt = datetime.strptime(d, "%Y-%m-%d")
        day = dt.day
        suf = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        return f"{day}{suf} {dt.strftime('%B %Y')}"

    def _list_amount_dates(items):
        return ", ".join(f"£{i['amount']:,.2f} on {_fmt_date(i['date'])}" for i in items)

    closing = _closing_prompt_for_base_question(row.get("question"), tag)

    # ---- CASH_DAILY_BREACH (ignore country; focus on cash usage) ----
    if tag == "CASH_DAILY_BREACH":
        inc_cash = [i for i in norm if i["direction"] == "IN"  and i["channel"] == "cash"]
        out_cash = [i for i in norm if i["direction"] == "OUT" and i["channel"] == "cash"]
        # Fallback: if channel not present on source txns, treat all sources as cash (conservative)
        if not inc_cash and not out_cash:
            inc_cash = [i for i in norm if i["direction"] == "IN"]
            out_cash = [i for i in norm if i["direction"] == "OUT"]
        bits = []
        if inc_cash:
            bits.append(f"{len(inc_cash)} cash deposit{'s' if len(inc_cash)!=1 else ''} valued at {_list_amount_dates(inc_cash)}")
        if out_cash:
            bits.append(f"{len(out_cash)} cash withdrawal{'s' if len(out_cash)!=1 else ''} valued at {_list_amount_dates(out_cash)}")
        front = "Our records show " + " and ".join(bits) + "."
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- HISTORICAL_DEVIATION (spike vs median) ----
    if tag == "HISTORICAL_DEVIATION":
        # Use direction of the largest txn among sources
        spike = max(norm, key=lambda x: x["amount"])
        med = _median_for_direction(spike["customer_id"], spike["direction"])
        ratio = (spike["amount"] / med) if med > 0 else None
        if ratio and ratio >= 1.2:
            ratio_int = int(ratio)
            ratio_txt = f"; this is over {ratio_int} time{'s' if ratio_int != 1 else ''} your typical amount"
        else:
            ratio_txt = ""
        front = (f"Our records show a higher-than-usual transaction of £{spike['amount']:,.2f} "
                 f"on {_fmt_date(spike['date'])}{ratio_txt}.")
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- EXPECTED_BREACH_IN / OUT (expected X vs actual Y for that month) ----
    if tag in ("EXPECTED_BREACH_IN", "EXPECTED_BREACH_OUT"):
        # Pick the most recent source txn to anchor the month
        anchor = norm[-1]
        direction = anchor["direction"].lower()  # 'in' or 'out'
        x, y, ym = _expected_vs_actual_month(anchor["customer_id"], direction, anchor["date"])
        dir_word = "incomings" if direction == "in" else "outgoings"
        # Format YYYY-MM as "Month Year" (e.g., "January 2026")
        try:
            ym_formatted = datetime.strptime(ym, "%Y-%m").strftime("%B %Y")
        except:
            ym_formatted = ym
        front = (f"Our records show your {dir_word} in {ym_formatted} totalled £{y:,.2f}, "
                 f"compared to your stated expectation of £{x:,.2f}.")
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- NLP_RISK (surface risky terms; ask for purpose + relationship) ----
    if tag == "NLP_RISK":
        hits = _risky_terms_used([i["narrative"] for i in norm if i["narrative"]])
        hit_txt = f" (keywords noted: {', '.join(hits)})" if hits else ""
        # Summarise sent/received without country to keep neutral
        inc = [i for i in norm if i["direction"] == "IN"]
        out = [i for i in norm if i["direction"] == "OUT"]
        bits = []
        if inc:
            verb = "was received" if len(inc) == 1 else "were received"
            bits.append(f"{len(inc)} transaction{'s' if len(inc)!=1 else ''} {verb} valued at {_list_amount_dates(inc)}")
        if out:
            verb = "was sent" if len(out) == 1 else "were sent"
            bits.append(f"{len(out)} transaction{'s' if len(out)!=1 else ''} {verb} valued at {_list_amount_dates(out)}")
        front = ("Our records show " + " and ".join(bits) + "." if bits else "We are reviewing recent activity.")
        total = len(inc) + len(out)
        payment_word = "this payment" if total == 1 else "these payments"
        s = f"{front} We'd like to understand {payment_word}{hit_txt}. {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- Jurisdictional (by country, sent/received) ----
    if tag in ("PROHIBITED_COUNTRY", "HIGH_RISK_COUNTRY"):
        by_country = {}
        for i in norm:
            by_country.setdefault(i["country"] or "Unknown country", []).append(i)
        parts = []
        for country, items in sorted(by_country.items(), key=lambda kv: kv[0]):
            inc = [x for x in items if x["direction"] == "IN"]
            out = [x for x in items if x["direction"] == "OUT"]
            segs = []
            if inc:
                verb = "was received" if len(inc) == 1 else "were received"
                segs.append(f"{len(inc)} transaction{'s' if len(inc)!=1 else ''} {verb} from {country} valued at {_list_amount_dates(inc)}")
            if out:
                verb = "was sent" if len(out) == 1 else "were sent"
                segs.append(f"{len(out)} transaction{'s' if len(out)!=1 else ''} {verb} to {country} valued at {_list_amount_dates(out)}")
            parts.append(" and ".join(segs))
        front = "Our records show " + " and ".join(parts) + "."
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- Neutral fallback (no country) ----
    inc = [i for i in norm if i["direction"] == "IN"]
    out = [i for i in norm if i["direction"] == "OUT"]
    bits = []
    if inc:
        verb = "was received" if len(inc) == 1 else "were received"
        bits.append(f"{len(inc)} transaction{'s' if len(inc)!=1 else ''} {verb} valued at {_list_amount_dates(inc)}")
    if out:
        verb = "was sent" if len(out) == 1 else "were sent"
        bits.append(f"{len(out)} transaction{'s' if len(out)!=1 else ''} {verb} valued at {_list_amount_dates(out)}")
    front = "Our records show " + " and ".join(bits) + "."
    s = f"{front} {closing}"
    return s if s.endswith("?") else s.rstrip('.') + "?"

# ---------- AI route (with outreach support) ----------

def _build_outreach_email(customer_id: str, rows: list) -> str:
    """
    Build a plain-text outreach email using the customer-friendly questions.
    """
    when = datetime.now().strftime("%d %B %Y")
    lines = []
    lines.append(f"Subject: Information request regarding recent account activity ({customer_id})")
    lines.append("")
    lines.append("Dear Customer,")
    lines.append("")
    lines.append(
        "We’re reviewing recent activity on your account and would be grateful if you could "
        "provide further information to help us complete our checks."
    )
    lines.append("")
    lines.append("Please respond to the questions below:")
    lines.append("")
    for i, r in enumerate(rows, start=1):
        q = (r.get("question_nice") or r.get("question") or "").strip()
        if q and not q.endswith("?"):
            q += "?"
        lines.append(f"{i}. {q}")
    lines.append("")
    lines.append("If you have any supporting documents (e.g., invoices or contracts), please include them.")
    lines.append("")
    lines.append("Kind regards,")
    lines.append("Compliance Team")
    lines.append(when)
    return "\n".join(lines)

# Remember the user's last customer in THIS browser session (not global)
def _remember_customer_for_session(customer_id: Optional[str]) -> None:
    try:
        from flask import session as _sess  # local import to avoid circulars
        if customer_id:
            _sess["last_customer_id"] = customer_id
    except Exception:
        pass


@app.route("/ai", methods=["GET", "POST"])
@login_required
def ai_analysis():
    """
    AI Analysis workflow:
      - action=build    -> collect alerts -> (optional) LLM normalise -> save questions
      - action=save     -> persist answers
      - action=outreach -> generate outreach email text (shown on page)
    Renders customer-friendly sentences (country names, natural dates, sent/received) and
    keeps intent-specific closings to avoid apparent duplicates.

    NOTE: No global fallback to "last case" — we only use the per-session last customer.
    """
    ensure_ai_tables()

    cust   = request.values.get("customer_id")
    period = request.values.get("period", "all")
    action = request.values.get("action")

    # remember the user’s current customer for this browser session
    _remember_customer_for_session(cust)

    # Resolve period bounds
    today = date.today()
    if period == "all":
        p_from, p_to = None, None
    elif period.endswith("m") and period[:-1].isdigit():
        months = int(period[:-1])
        start_month = (today.replace(day=1) - timedelta(days=months * 31)).replace(day=1)
        p_from, p_to = start_month.isoformat(), today.isoformat()
    else:
        p_from, p_to = None, None

    # If no customer provided, try session-scoped last_customer_id; else render empty state
    if not cust:
        last_cust = session.get("last_customer_id")
        if last_cust:
            return redirect(url_for("ai_analysis", customer_id=last_cust, period=period))

    db = get_db()
    params = {
        "cfg_ai_use_llm": bool(cfg_get("cfg_ai_use_llm", False)),
        "cfg_ai_model":   str(cfg_get("cfg_ai_model", "gpt-4o-mini")),
    }

    case_row = None
    answers  = []
    proposed = []
    used_llm = False
    outreach_text = None

    # -------- helpers to attach txn details + build customer-friendly text --------
    def _fetch_details_for_ids(txn_ids: list) -> dict:
        if not txn_ids:
            return {}
        qmarks = ",".join("?" * len(txn_ids))
        rows = get_db().execute(
            f"""SELECT id AS txn_id, txn_date, base_amount, country_iso2, direction,
                        customer_id, channel, narrative
                   FROM transactions
                  WHERE id IN ({qmarks})""",
            list(map(str, txn_ids)),
        ).fetchall()
        return {r["txn_id"]: dict(r) for r in rows}

    def _attach_and_enrich(rows):
        if not rows:
            return []
        # gather all ids
        all_ids = []
        for r in rows:
            src = r.get("sources")
            if isinstance(src, str) and src:
                all_ids.extend([x for x in src.split(",") if x])
            elif isinstance(src, list) and src:
                all_ids.extend(list(map(str, src)))
        details_map = _fetch_details_for_ids(list(dict.fromkeys(all_ids)))

        out = []
        for r in rows:
            if isinstance(r.get("sources"), str) and r["sources"]:
                ids = [x for x in r["sources"].split(",") if x]
            elif isinstance(r.get("sources"), list):
                ids = list(map(str, r["sources"]))
            else:
                ids = []
            r["source_details"] = [details_map[i] for i in ids if i in details_map]
            r["question_nice"] = _question_sentence_for_row(r)
            out.append(r)
        return out

    def _dedupe_by_sentence(rows):
        seen, out = set(), []
        for r in rows:
            key = (r.get("tag") or "", (r.get("question_nice") or r.get("question") or "").strip())
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    # ------------------------------ Actions ------------------------------
    if cust:
        case_row = db.execute(
            "SELECT * FROM ai_cases WHERE customer_id=? ORDER BY updated_at DESC LIMIT 1",
            (cust,),
        ).fetchone()

        # -------- Prepare Questions --------
        if action == "build":
            base_questions, fired_tags, source_alerts = build_ai_questions(cust, p_from, p_to)

            if not case_row:
                db.execute(
                    "INSERT INTO ai_cases(customer_id, period_from, period_to) VALUES(?,?,?)",
                    (cust, p_from, p_to),
                )
                db.commit()
                case_row = db.execute(
                    "SELECT * FROM ai_cases WHERE customer_id=? ORDER BY id DESC LIMIT 1",
                    (cust,),
                ).fetchone()

            final_questions = list(base_questions)
            if llm_enabled():
                final_questions = ai_normalise_questions_llm(cust, fired_tags, source_alerts, base_questions)
                used_llm = True

            # Persist (overwrite) with sources (txn_ids)
            db.execute("DELETE FROM ai_answers WHERE case_id=?", (case_row["id"],))
            for q in final_questions:
                src = q.get("sources") or []
                db.execute(
                    "INSERT INTO ai_answers(case_id, tag, question, sources) VALUES(?,?,?,?)",
                    (
                        case_row["id"],
                        q.get("tag") or "",
                        q.get("question") or "",
                        ",".join(map(str, src)) if src else None,
                    ),
                )
            db.commit()

            flash(f"Prepared {len(final_questions)} question(s) for {cust}.")
            return redirect(url_for("ai_analysis", customer_id=cust, period=period))

        # -------- Save Responses --------
        if action == "save":
            case_id = int(request.values.get("case_id"))
            for qid in request.values.getlist("qid"):
                ans = request.values.get(f"answer_{qid}", "")
                db.execute(
                    "UPDATE ai_answers SET answer=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (ans, qid),
                )
            db.execute("UPDATE ai_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (case_id,))
            db.commit()
            flash("Responses saved.")
            return redirect(url_for("ai_analysis", customer_id=cust, period=period))

        # -------- Build Outreach Pack (generate email text) --------
        if action == "outreach" and case_row:
            rows = db.execute(
                "SELECT * FROM ai_answers WHERE case_id=? ORDER BY id",
                (case_row["id"],),
            ).fetchall()
            rows = _attach_and_enrich([dict(r) for r in rows]) if rows else []
            rows = _dedupe_by_sentence(rows)
            outreach_text = _build_outreach_email(cust, rows)
            # fall through to GET rendering with outreach_text displayed

        # -------- GET view (load answers or show preview if empty) --------
        if case_row and not outreach_text:
            answers = db.execute(
                "SELECT * FROM ai_answers WHERE case_id=? ORDER BY id",
                (case_row["id"],),
            ).fetchall()
            if not answers:
                proposed, _, _ = build_ai_questions(cust, p_from, p_to)

    # Attach & enrich for display
    answers_list  = _attach_and_enrich([dict(a) for a in answers]) if answers else []
    proposed_list = _attach_and_enrich([dict(p) for p in proposed]) if proposed else []

    # Guardrail: de-duplicate identical sentences per tag
    answers_list  = _dedupe_by_sentence(answers_list)
    proposed_list = _dedupe_by_sentence(proposed_list)

    case = dict(case_row) if case_row else None

    return render_template(
        "ai.html",
        customer_id=cust,
        period=period,
        period_from=p_from,
        period_to=p_to,
        case=case,
        answers=answers_list,
        proposed_questions=proposed_list,
        params=params,
        outreach_text=outreach_text,          # displayed when present
        country_full_name=country_full_name,  # available to Jinja if needed
    )

def format_outreach_responses(answers_rows):
    """Turn outreach answers into a narrative for the rationale."""
    if not answers_rows:
        return "Outreach questions have been prepared; responses are currently awaited."

    lines = []
    for r in answers_rows:
        ans = (r.get("answer") or "").strip()
        if not ans:
            continue
        # Tag context if available
        if r.get("tag"):
            lines.append(f"Regarding {r['tag'].replace('_',' ').title()}: {ans}")
        else:
            lines.append(f"Customer stated: {ans}")

    if not lines:
        return "Outreach questions prepared; responses currently awaited."
    return " ".join(lines)

def _months_in_period(p_from: Optional[str], p_to: Optional[str]) -> float:
    """Rough month count used for avg-per-month. Falls back to 1.0 if bounds missing/invalid."""
    try:
        if not p_from or not p_to:
            return 1.0
        d1 = date.fromisoformat(p_from)
        d2 = date.fromisoformat(p_to)
        days = max(1, (d2 - d1).days + 1)
        return max(1.0, days / 30.4375)
    except Exception:
        return 1.0

def _safe_pct(numer: float, denom: float) -> float:
    try:
        return (float(numer) / float(denom)) * 100.0 if float(denom) else 0.0
    except Exception:
        return 0.0

def _format_date_uk(date_str: str) -> str:
    """Format YYYY-MM-DD as '1st January 2026' (UK style)."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        day = dt.day
        suffix = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        return f"{day}{suffix} {dt.strftime('%B %Y')}"
    except:
        return date_str

def _period_text(p_from: Optional[str] = None, p_to: Optional[str] = None) -> str:
    if not p_from and not p_to:
        return "the available period"
    if p_from and p_to:
        return f"{_format_date_uk(p_from)} to {_format_date_uk(p_to)}"
    if p_from and not p_to:
        return f"from {_format_date_uk(p_from)}"
    if p_to and not p_from:
        return f"up to {_format_date_uk(p_to)}"
    return "the selected period"

def _sector_alignment_score(nature_of_business: Optional[str], narratives: list[str]) -> tuple[float, list[str]]:
    """
    Very simple heuristic:
      - Tokenise 'nature_of_business' into keywords (>=4 chars), plus a small synonym set for common sectors.
      - Score % of narratives that contain at least one keyword.
    Returns (pct_aligned, hit_keywords_sorted)
    """
    if not nature_of_business:
        return 0.0, []
    base = nature_of_business.lower()

    # seed keywords from the nature text
    kw = {w for w in re.split(r"[^a-z0-9]+", base) if len(w) >= 4}

    # add tiny synonym hints for common sectors
    synonyms = {
        "restaurant": {"food", "catering", "kitchen", "takeaway", "diner"},
        "building": {"builder", "construction", "materials", "timber", "cement", "merchant", "trade"},
        "retail": {"shop", "store", "till", "pos", "receipt"},
        "consulting": {"consultancy", "professional", "advisory"},
        "transport": {"haulage", "logistics", "freight", "courier"},
    }
    for k, vals in synonyms.items():
        if k in base:
            kw |= vals

    kw = {k for k in kw if k}  # non-empty
    if not kw or not narratives:
        return 0.0, sorted(list(kw))

    aligned = 0
    hits = set()
    for n in narratives:
        low = (n or "").lower()
        if any(k in low for k in kw):
            aligned += 1
            # record which ones hit
            for k in kw:
                if k in low:
                    hits.add(k)

    pct = _safe_pct(aligned, len(narratives))
    return pct, sorted(list(hits))

from typing import Optional

def build_rationale_text(
    customer_id: str,
    p_from: Optional[str],
    p_to: Optional[str],
    nature_of_business: Optional[str],
    est_income: Optional[float],
    est_expenditure: Optional[float],
) -> str:
    m = _customer_metrics(customer_id, p_from, p_to)
    case, answers = _answers_summary(customer_id)

    def _period_text(pf: Optional[str], pt: Optional[str]) -> str:
        if pf and pt:
            return f"{_format_date_uk(pf)} to {_format_date_uk(pt)}"
        return "the period reviewed"

    period_txt = _period_text(p_from, p_to)

    # --- Outreach plausibility (kept but only used to shape tone if no tag-specific rewrite) ---
    n_answers = 0
    plaus_scores = []

    def _plausibility_score(ans: str, tag: str) -> int:
        if not ans:
            return 0
        a = ans.lower()
        score = 0
        # +detail
        if len(a) >= 80: score += 2
        if any(w in a for w in ["invoice", "payroll", "utilities", "supplier", "contract", "order", "shipment"]): score += 2
        if any(w in a for w in ["bank statement", "receipt", "evidence", "documentation", "proof"]): score += 2
        if any(w in a for w in ["gift", "loan", "family", "friend"]): score += 1
        if any(w in a for w in ["awaiting", "will provide", "checking", "confirming"]): score += 1
        # vagueness / hedging
        if any(w in a for w in ["don't know", "no idea", "can’t remember", "misc", "various"]): score -= 3
        if any(w in a for w in ["just because", "personal reasons"]): score -= 2
        if any(w in a for w in ["cash", "cash deposit"]) and tag.upper() != "CASH_DAILY_BREACH": score -= 1
        # light tag alignment
        t = (tag or "").upper()
        if t == "PROHIBITED_COUNTRY" and any(w in a for w in ["russia", "ru", "sanction", "export control"]):
            score += 1
        if t in ("HIGH_RISK_COUNTRY","HIGH_3RD") and any(w in a for w in ["third party", "intermediary", "agent"]):
            score += 1
        return score

    if answers:
        for r in answers:
            ans = (r.get("answer") or "").strip()
            if ans:
                n_answers += 1
                plaus_scores.append(_plausibility_score(ans, r.get("tag") or ""))

    if n_answers:
        avg_p = sum(plaus_scores) / max(1, len(plaus_scores))
        if avg_p >= 3:
            outreach_tone = "Customer explanations appear broadly plausible and evidence-led."
        elif avg_p >= 1:
            outreach_tone = "Customer explanations provide some relevant detail; further corroboration may be appropriate."
        else:
            outreach_tone = "Customer explanations lack sufficient detail and require clarification."
    else:
        outreach_tone = "Outreach questions prepared; responses currently awaited."

    # --- period months for averages (for estimate comparison) ---
    def _months_in_period() -> int:
        if m.get("period_months"):
            try:
                pm = int(m["period_months"])
                return pm if pm > 0 else 1
            except Exception:
                pass
        if p_from and p_to:
            try:
                d1 = date.fromisoformat(p_from)
                d2 = date.fromisoformat(p_to)
                days = max(1, (d2 - d1).days)
                return max(1, round(days / 30))
            except Exception:
                return 1
        return 1

    months = _months_in_period()

    def _line_for_estimate(avg_val: float, est_val: Optional[float], label: str) -> Optional[str]:
        if est_val is None or est_val <= 0:
            return None
        diff = avg_val - est_val
        pct = (diff / est_val) * 100.0
        abs_pct = abs(pct)
        if abs_pct <= 20:
            stance = "in line with"
        elif pct > 0:
            stance = "above"
        else:
            stance = "below"
        return (
            f"Average monthly {label} of £{avg_val:,.0f} is {stance} the estimate "
            f"(£{est_val:,.0f}{'' if stance=='in line with' else f', by {abs_pct:.0f}%'})."
        )

    avg_monthly_in  = (m.get("total_in") or 0.0)  / months
    avg_monthly_out = (m.get("total_out") or 0.0) / months

    income_line = _line_for_estimate(avg_monthly_in,  est_income,       "credits")
    spend_line  = _line_for_estimate(avg_monthly_out, est_expenditure,  "debits")

    # --- Friendly zero phrasing & composition helpers ---
    def _cash_phrase():
        ci, co = float(m.get("cash_in") or 0), float(m.get("cash_out") or 0)
        return "There has been no cash usage." if ci == 0 and co == 0 else \
               f"Cash activity: deposits £{ci:,.2f}, withdrawals £{co:,.2f}."

    def _overseas_phrase():
        ov = float(m.get("overseas") or 0)
        return "There have been no overseas transactions." if ov == 0 else \
               f"Overseas activity accounts for {float(m.get('overseas_pct') or 0):.1f}% of value (£{ov:,.2f})."

    def _hr_phrase():
        hr = float(m.get("hr_val") or 0)
        if hr == 0:
            return "No transactions were recorded through high-risk or prohibited corridors."
        return f"High-risk/high-risk-third/prohibited corridors account for {float(m.get('hr_pct') or 0):.1f}% of value (£{hr:,.2f})."

    cash_line = _cash_phrase()
    overseas_line = _overseas_phrase()
    hr_line = _hr_phrase()

    # --- Business alignment (keywords from nature_of_business vs narratives) ---
    def _alignment_phrase():
        nob = (nature_of_business or "").strip().lower()
        if not nob:
            return None
        stop = {"and","the","of","for","to","with","a","an","in","on","ltd","plc","inc","co"}
        kws = sorted({w.strip(",./-()") for w in nob.split() if len(w) >= 4 and w not in stop})
        if not kws:
            return None

        rows = get_db().execute(
            """
            SELECT narrative
              FROM transactions
             WHERE customer_id=? AND (? IS NULL OR txn_date>=?) AND (? IS NULL OR txn_date<=?)
             LIMIT 5000
            """,
            (customer_id, p_from, p_from, p_to, p_to)
        ).fetchall()

        total = len(rows)
        if total == 0:
            return None

        hits = 0
        for r in rows:
            text = (r["narrative"] or "").lower()
            if any(k in text for k in kws):
                hits += 1

        ratio = hits / total
        eg = ", ".join(kws[:3])
        if ratio >= 0.5:
            return f"Most transactions (≈{ratio*100:.0f}%) reference terms consistent with the declared business (e.g., {eg})."
        if ratio >= 0.2:
            return f"A minority of transactions (≈{ratio*100:.0f}%) reference business-aligned terms (e.g., {eg}); the remainder appear generic."
        return "Transaction descriptions do not strongly indicate the declared business; consider corroborating with additional evidence."

    alignment_line = _alignment_phrase()

    # --- Alerts + Outreach: collapse into single, country-explicit sentence for PROHIBITED_COUNTRY ---
    def _prohibited_country_sentence() -> Optional[str]:
        # Find distinct countries and count transactions linked to prohibited alerts in the period
        params = [customer_id]
        where = "a.customer_id=? AND json_extract(a.rule_tags, '$') IS NOT NULL AND a.rule_tags LIKE '%PROHIBITED_COUNTRY%'"
        if p_from and p_to:
            where += " AND t.txn_date BETWEEN ? AND ?"
            params += [p_from, p_to]
        
        # Get country details with transaction count
        rows = get_db().execute(
            f"""
            SELECT t.country_iso2, COUNT(DISTINCT t.id) as txn_count
              FROM alerts a
              JOIN transactions t ON t.id = a.txn_id
             WHERE {where}
             GROUP BY t.country_iso2
            """, params
        ).fetchall()
        
        # Build country string with transaction counts
        country_parts = []
        total_txn_count = 0
        for r in rows:
            if r["country_iso2"]:
                country_name = country_full_name(r["country_iso2"])
                txn_count = r["txn_count"]
                total_txn_count += txn_count
                country_parts.append((country_name, txn_count))
        
        if not country_parts:
            countries_str = "a prohibited jurisdiction"
            txn_phrase = "transactions"
        elif len(country_parts) == 1:
            country_name, txn_count = country_parts[0]
            countries_str = country_name
            txn_phrase = "1 transaction" if txn_count == 1 else f"{txn_count} transactions"
        else:
            countries_str = ", ".join(sorted(set(cp[0] for cp in country_parts)))
            txn_phrase = f"{total_txn_count} transactions"

        # Choose the most relevant/first prohibited-country answer if present
        pc_answers = [r for r in (answers or []) if (r.get("tag") or "").upper() == "PROHIBITED_COUNTRY"]
        answer_txt = (pc_answers[0].get("answer") or "").strip() if pc_answers else ""

        # Documentation heuristic - check for positive mentions of documentation
        # but exclude negations like "no invoice", "not provided", "haven't received"
        answer_lower = (answer_txt or "").lower()
        doc_keywords = ["invoice", "contract", "agreement", "evidence", "documentation", "proof", "bank statement", "receipt", "attached", "enclosed"]
        negation_patterns = ["no ", "not ", "haven't ", "hasn't ", "without ", "missing ", "awaiting ", "waiting for "]
        
        has_doc_keyword = any(w in answer_lower for w in doc_keywords)
        has_negation_before_doc = any(
            neg in answer_lower and any(w in answer_lower[answer_lower.find(neg):answer_lower.find(neg)+30] for w in doc_keywords)
            for neg in negation_patterns
        )
        mentions_docs = has_doc_keyword and not has_negation_before_doc

        if answer_txt:
            # Quote the customer's response to make it clear this is their statement, not the reviewer's
            sentence = (
                f"Alerts show {txn_phrase} to {countries_str}, which is a Prohibited Country. "
                f"The customer stated: \"{answer_txt.strip().rstrip('.')}\" "
                f"{'(supporting documentation has been provided).' if mentions_docs else '(no supporting documentation has been provided).'}"
            )
        else:
            sentence = (
                f"Alerts show {txn_phrase} to {countries_str}, which is a Prohibited Country. "
                "Customer outreach responses are awaited."
            )
        return sentence

    def _alerts_sentence() -> str:
        tags = dict(m.get("tag_counter") or {})
        if not tags:
            return "No alerts were noted in the review period."
        if "PROHIBITED_COUNTRY" in tags:
            return _prohibited_country_sentence() or "No alerts were noted in the review period."
        # fallback: name other tags cleanly
        tag_bits = [tg.replace("_", " ").title() for tg in sorted(tags.keys())]
        return "Alerts noted: " + ", ".join(tag_bits) + "."

    def _outreach_questions_and_responses_section() -> str:
        """
        Build a clear, auditable section listing ALL outreach questions and their responses.
        This ensures traceability - reviewers can see exactly what was asked and what the customer said.
        """
        if not answers:
            return ""
        
        section_lines = []
        section_lines.append("")
        section_lines.append("--- Outreach Questions & Responses ---")
        
        for idx, r in enumerate(answers, 1):
            question = (r.get("question") or "").strip()
            ans = (r.get("answer") or "").strip()
            tag = (r.get("tag") or "").upper()
            tag_nice = tag.replace("_", " ").title() if tag else "General"
            
            # Format: Q1 (Alert Type): Question text
            q_line = f"Q{idx} ({tag_nice}): {question[:200]}{'...' if len(question) > 200 else ''}"
            section_lines.append(q_line)
            
            # Format: A1: Response or [No response received]
            if ans:
                # Check if documentation was mentioned (but also check for negation)
                ans_lower = ans.lower()
                has_negation = any(neg in ans_lower for neg in [
                    "no ", "not ", "don't", "haven't", "wasn't", "didn't", "without"
                ])
                mentions_docs = any(w in ans_lower for w in [
                    "invoice", "contract", "agreement", "evidence", "documentation",
                    "proof", "bank statement", "receipt"
                ])
                
                # Only mark as "documentation referenced" if docs mentioned WITHOUT negation
                if mentions_docs and not has_negation:
                    doc_note = " [Documentation referenced]"
                elif mentions_docs and has_negation:
                    doc_note = " [No documentation provided]"
                else:
                    doc_note = ""
                
                a_line = f"A{idx}: {ans}{doc_note}"
            else:
                a_line = f"A{idx}: [No response received]"
            
            section_lines.append(a_line)
            section_lines.append("")  # Blank line between Q&A pairs
        
        return "\n".join(section_lines)

    # --- Compose final text (single cohesive section; no duplicated blocks) ---
    lines = []
    if nature_of_business:
        lines.append(f"Nature of business: {nature_of_business.strip()}.")

    lines.append(
        "Analysis of account transactions over "
        f"{period_txt}. Credits total £{(m.get('total_in') or 0):,.2f} "
        f"(avg £{(m.get('avg_in') or 0):,.2f}; largest £{(m.get('max_in') or 0):,.2f}); "
        f"debits total £{(m.get('total_out') or 0):,.2f} "
        f"(avg £{(m.get('avg_out') or 0):,.2f}; largest £{(m.get('max_out') or 0):,.2f})."
    )

    # Cash/overseas/hr (use friendly zero phrasing and avoid duplicating numbers you asked to remove earlier)
    lines.append(cash_line)
    lines.append(overseas_line)
    if float(m.get("hr_val") or 0) > 0:
        lines.append(hr_line)

    if income_line: lines.append(income_line)
    if spend_line:  lines.append(spend_line)
    if alignment_line: lines.append(alignment_line)

    # Alerts (merged prohibited-country wording if applicable)
    alerts_line = _alerts_sentence()
    lines.append(alerts_line)

    # If truly no alerts, add the "no anomalies" wrap-up
    tags = dict(m.get("tag_counter") or {})
    if not tags:
        lines.append("No material anomalies were identified in the period reviewed; activity appears consistent with the overall profile.")

    # Add outreach status summary - count answered vs outstanding questions
    if answers:
        total_questions = len(answers)
        answered_count = sum(1 for r in answers if (r.get("answer") or "").strip())
        outstanding_count = total_questions - answered_count
        
        if outstanding_count > 0 and answered_count > 0:
            lines.append(f"Outreach status: {answered_count} of {total_questions} question(s) answered; {outstanding_count} response(s) still outstanding.")
        elif outstanding_count > 0 and answered_count == 0:
            lines.append(f"Outreach status: {total_questions} question(s) sent; all responses currently outstanding.")
        elif outstanding_count == 0:
            lines.append(f"Outreach status: All {total_questions} question(s) have been answered.")
        
        # Add full Q&A section for auditability - reviewers see exactly what was asked and answered
        qa_section = _outreach_questions_and_responses_section()
        if qa_section:
            lines.append(qa_section)

    return "\n".join(lines)

from flask import session

from typing import Optional

@app.route("/ai-rationale", methods=["GET", "POST"])
@login_required
def ai_rationale():
    ensure_ai_rationale_table()  # your existing creator (with rationale_text + UNIQUE key)

    # Always read from values (works for both GET & POST)
    customer_id = (request.values.get("customer_id") or "").strip() or None
    period      = (request.values.get("period") or "all").strip()

    # Compute bounds from period (your helper)
    p_from, p_to = _period_bounds(period)

    # Defaults
    metrics = None
    answers_preview = []
    rationale_text = None
    nature_of_business = request.values.get("nature_of_business") or None
    est_income = request.values.get("est_income") or ""
    est_expenditure = request.values.get("est_expenditure") or ""
    action = (request.values.get("action") or "").strip()

    # Coerce numbers
    def _to_float_or_none(s):
        try:
            return float(str(s).replace(",", "")) if s not in (None, "", "None") else None
        except Exception:
            return None
    est_income_num = _to_float_or_none(est_income)
    est_expenditure_num = _to_float_or_none(est_expenditure)

    # POST: generate + persist, then PRG redirect to avoid resubmits
    if request.method == "POST" and action == "generate" and customer_id:
        metrics = _customer_metrics(customer_id, p_from, p_to)
        rationale_text = build_rationale_text(
            customer_id=customer_id,
            p_from=p_from,
            p_to=p_to,
            nature_of_business=nature_of_business,
            est_income=est_income_num,
            est_expenditure=est_expenditure_num,
        )
        _upsert_rationale_row(
            customer_id=customer_id,
            p_from=p_from,
            p_to=p_to,
            nature_of_business=nature_of_business,
            est_income=est_income_num,
            est_expenditure=est_expenditure_num,
            rationale_text=rationale_text,
        )
        # Redirect with both params kept
        return redirect(url_for("ai_rationale", customer_id=customer_id, period=period))

    # GET: load saved state if we have a customer
    if customer_id:
        metrics = _customer_metrics(customer_id, p_from, p_to)
        row = _load_rationale_row(customer_id, p_from, p_to)
        if row:
            rationale_text = row["rationale_text"]
            if not nature_of_business:
                nature_of_business = row["nature_of_business"]
            if est_income == "":
                est_income = "" if row["est_income"] is None else str(int(row["est_income"]))
            if est_expenditure == "":
                est_expenditure = "" if row["est_expenditure"] is None else str(int(row["est_expenditure"]))
        case, answers_preview = _answers_summary(customer_id)

    return render_template(
        "ai_rationale.html",
        customer_id=customer_id,
        period=period,
        metrics=metrics,
        nature_of_business=nature_of_business or "",
        est_income=est_income or "",
        est_expenditure=est_expenditure or "",
        rationale_text=rationale_text,
        answers_preview=answers_preview,
    )

@app.route("/explore")
@login_required
def explore():
    db = get_db()
    customer_id = request.args.get("customer_id","").strip()
    direction = request.args.get("direction","").strip()
    channel = request.args.get("channel","").strip()
    risk_param = request.args.get("risk","").strip()   # e.g. "HIGH,HIGH_3RD,PROHIBITED" or "HIGH"
    date_from = request.args.get("date_from","").strip()
    date_to = request.args.get("date_to","").strip()
    export = request.args.get("export","") == "csv"

    where, params = [], []
    join_risk = False

    if customer_id:
        where.append("t.customer_id = ?"); params.append(customer_id)
    if direction in ("in","out"):
        where.append("t.direction = ?"); params.append(direction)
    if channel:
        where.append("lower(ifnull(t.channel,'')) = ?"); params.append(channel.lower())

    # --- NEW: flexible multi-risk filter ---
    valid_risks = {"LOW","MEDIUM","HIGH","HIGH_3RD","PROHIBITED"}
    risk_list = [r.strip().upper() for r in risk_param.split(",") if r.strip()]
    risk_list = [r for r in risk_list if r in valid_risks]
    if risk_list:
        join_risk = True
        placeholders = ",".join(["?"] * len(risk_list))
        where.append(f"r.risk_level IN ({placeholders})")
        params.extend(risk_list)

    if date_from:
        where.append("t.txn_date >= ?"); params.append(date_from)
    if date_to:
        where.append("t.txn_date <= ?"); params.append(date_to)

    join_clause = "JOIN ref_country_risk r ON r.iso2 = ifnull(t.country_iso2, '')" if join_risk else ""
    where_clause = ("WHERE " + " AND ".join(where)) if where else ""

    sql = f"""
      SELECT t.id, t.txn_date, t.customer_id, t.direction, t.base_amount, t.currency,
             t.country_iso2, t.channel, t.payer_sort_code, t.payee_sort_code, t.narrative
      FROM transactions t
      {join_clause}
      {where_clause}
      ORDER BY t.txn_date DESC, t.id DESC
      LIMIT 5000
    """

    rows = db.execute(sql, params).fetchall()
    recs = [dict(r) for r in rows]

    if export:
        from flask import Response
        import csv as _csv, io

        # CSV formula injection protection (AGRA-001-1-6 pen test remediation)
        # Prefix cells starting with formula-trigger characters to prevent
        # Excel/Sheets from interpreting them as formulas.
        _CSV_FORMULA_TRIGGERS = ('=', '+', '-', '@', '\t', '\r')
        def _sanitise_csv_value(val):
            if isinstance(val, str) and val and val[0] in _CSV_FORMULA_TRIGGERS:
                return "'" + val
            return val

        si = io.StringIO()
        fieldnames = recs[0].keys() if recs else [
            "id","txn_date","customer_id","direction","base_amount","currency",
            "country_iso2","channel","payer_sort_code","payee_sort_code","narrative"
        ]
        w = _csv.DictWriter(si, fieldnames=fieldnames)
        w.writeheader()
        for r in recs:
            w.writerow({k: _sanitise_csv_value(v) for k, v in r.items()})
        return Response(
            si.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition":"attachment; filename=explore.csv"}
        )

    # distinct channels for dropdown
    ch_rows = db.execute("SELECT DISTINCT lower(ifnull(channel,'')) as ch FROM transactions ORDER BY ch").fetchall()
    channels = [r["ch"] for r in ch_rows if r["ch"]]

    return render_template("explore.html", rows=recs, channels=channels)

# ------- Rules table utilities (safe to add near other helpers) -------
def ensure_rules_table():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            rule TEXT,
            trigger_condition TEXT,
            score_impact TEXT,
            tags TEXT,
            outcome TEXT,
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_rules_category_rule ON rules(category, rule);")
    db.commit()

def _normalize_rule_columns(df):
    # Accept flexible headers from Excel
    mapping = {}
    for c in df.columns:
        k = str(c).strip().lower()
        if k == "category": mapping[c] = "category"
        elif k in ("rule", "rule name", "name"): mapping[c] = "rule"
        elif k in ("trigger condition", "trigger", "condition"): mapping[c] = "trigger_condition"
        elif k in ("score impact", "impact", "score"): mapping[c] = "score_impact"
        elif k in ("tag(s)", "tags", "rule tags"): mapping[c] = "tags"
        elif k in ("escalation outcome", "outcome", "severity outcome"): mapping[c] = "outcome"
        elif k in ("description", "plain description", "explanation"): mapping[c] = "description"
        else:
            mapping[c] = c
    df = df.rename(columns=mapping)
    # ensure optional cols exist
    for col in ["trigger_condition","score_impact","tags","outcome","description"]:
        if col not in df.columns:
            df[col] = ""
    df = df.fillna("")
    return df

# ------- Routes to edit/reload rules from Admin UI -------
@app.post("/admin/rules")
@admin_required
def admin_rules():
    """Save a single rule's editable fields (score_impact, outcome, description)."""
    ensure_rules_table()
    rid = request.form.get("save_rule")
    if not rid:
        flash("No rule id provided.")
        return redirect(url_for("admin"))

    score_impact = request.form.get(f"score_impact_{rid}", "").strip()
    outcome = request.form.get(f"outcome_{rid}", "").strip()
    description = request.form.get(f"description_{rid}", "").strip()

    db = get_db()
    db.execute("""
        UPDATE rules
           SET score_impact=?, outcome=?, description=?, updated_at=CURRENT_TIMESTAMP
         WHERE id=?
    """, (score_impact, outcome, description, rid))
    db.commit()
    flash(f"Rule {rid} saved.")
    return redirect(url_for("admin") + "#rules")

@app.post("/admin/rules-bulk")
@admin_required
def admin_rules_bulk():
    """
    Bulk actions:
      - action=reload: read uploaded .xlsx and upsert rules
      - action=wipe: delete all rules
    """
    ensure_rules_table()
    action = request.form.get("action", "").lower()
    db = get_db()

    if action == "wipe":
        db.execute("DELETE FROM rules;")
        db.commit()
        flash("All rules wiped.")
        return redirect(url_for("admin") + "#rules")

    if action == "reload":
        file = request.files.get("rules_file")
        if not file or not file.filename.lower().endswith((".xlsx", ".xls")):
            flash("Please upload an Excel file (.xlsx).")
            return redirect(url_for("admin") + "#rules")

        # Read Excel into DataFrame
        try:
            import pandas as pd
        except ImportError:
            flash("pandas is required to import Excel. Install with: pip install pandas openpyxl")
            return redirect(url_for("admin") + "#rules")

        try:
            df = pd.read_excel(file)
            df = _normalize_rule_columns(df)
        except Exception as e:
            flash(f"Failed to read Excel: {e}")
            return redirect(url_for("admin") + "#rules")

        # Upsert rows
        upsert_sql = """
            INSERT INTO rules (category, rule, trigger_condition, score_impact, tags, outcome, description, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(category, rule) DO UPDATE SET
                trigger_condition=excluded.trigger_condition,
                score_impact=excluded.score_impact,
                tags=excluded.tags,
                outcome=excluded.outcome,
                description=excluded.description,
                updated_at=CURRENT_TIMESTAMP;
        """

        recs = []
        for _, r in df.iterrows():
            category = str(r.get("category","")).strip()
            rule = str(r.get("rule","")).strip()
            if not category or not rule:
                continue
            recs.append((
                category,
                rule,
                str(r.get("trigger_condition","")).strip(),
                str(r.get("score_impact","")).strip(),
                str(r.get("tags","")).strip(),
                str(r.get("outcome","")).strip(),
                str(r.get("description","")).strip(),
            ))

        if not recs:
            flash("Excel contained no valid rule rows (need Category and Rule).")
            return redirect(url_for("admin") + "#rules")

        db.executemany(upsert_sql, recs)
        db.commit()
        flash(f"Reloaded {len(recs)} rule(s) from Excel.")
        return redirect(url_for("admin") + "#rules")

    # Unknown action
    flash("Unknown action.")
    return redirect(url_for("admin") + "#rules")

# ---------- AI Rationale storage ----------

def _period_text(p_from, p_to):
    if not p_from and not p_to:
        return "all transactions in the feed"
    return f"{p_from} to {p_to}"

def _sum_q(sql, params):
    row = get_db().execute(sql, params).fetchone()
    return float(row["s"] or 0.0)

def _count_q(sql, params):
    row = get_db().execute(sql, params).fetchone()
    return int(row["c"] or 0)

def _customer_metrics(customer_id: str, p_from: Optional[str], p_to: Optional[str]):
    """
    Returns a dict of key figures for rationale text.
    """
    db = get_db()
    wh, params = ["customer_id=?"], [customer_id]
    if p_from: wh.append("txn_date>=?"); params.append(p_from)
    if p_to:   wh.append("txn_date<=?"); params.append(p_to)
    where = "WHERE " + " AND ".join(wh)

    total_in  = _sum_q(f"SELECT SUM(base_amount) s FROM transactions {where} AND direction='in'",  params)
    total_out = _sum_q(f"SELECT SUM(base_amount) s FROM transactions {where} AND direction='out'", params)
    n_in   = _count_q(f"SELECT COUNT(*) c FROM transactions {where} AND direction='in'",  params)
    n_out  = _count_q(f"SELECT COUNT(*) c FROM transactions {where} AND direction='out'", params)
    avg_in  = (total_in / n_in) if n_in else 0.0
    avg_out = (total_out / n_out) if n_out else 0.0

    # Largest in/out
    row = db.execute(f"""
        SELECT MAX(CASE WHEN direction='in'  THEN base_amount END) AS max_in,
               MAX(CASE WHEN direction='out' THEN base_amount END) AS max_out
        FROM transactions {where}
    """, params).fetchone()
    max_in  = float(row["max_in"]  or 0.0)
    max_out = float(row["max_out"] or 0.0)

    # Cash totals
    cash_in  = _sum_q(f"SELECT SUM(base_amount) s FROM transactions {where} AND direction='in'  AND lower(IFNULL(channel,''))='cash'",  params)
    cash_out = _sum_q(f"SELECT SUM(base_amount) s FROM transactions {where} AND direction='out' AND lower(IFNULL(channel,''))='cash'", params)

    # Overseas (anything not GB and not NULL)
    overseas = _sum_q(f"""
        SELECT SUM(base_amount) s
          FROM transactions
         {where} AND IFNULL(country_iso2,'')<>'' AND UPPER(country_iso2)!='GB'
    """, params)
    total_val = total_in + total_out
    overseas_pct = (overseas / total_val * 100.0) if total_val else 0.0

    # High-risk / prohibited
    hr_val = _sum_q(f"""
        SELECT SUM(t.base_amount) s
          FROM transactions t
          JOIN ref_country_risk r ON r.iso2 = IFNULL(t.country_iso2,'')
         {where.replace('WHERE','WHERE t.')} AND r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
    """, params)
    hr_pct = (hr_val / total_val * 100.0) if total_val else 0.0

    # Alerts & tags present in period
    a_wh, a_params = ["a.customer_id=?"],[customer_id]
    if p_from and p_to:
        a_wh.append("t.txn_date BETWEEN ? AND ?"); a_params += [p_from, p_to]
    alerts = db.execute(f"""
        SELECT a.severity, a.rule_tags, t.txn_date, a.txn_id
          FROM alerts a
          JOIN transactions t ON t.id=a.txn_id
         WHERE {" AND ".join(a_wh)}
         ORDER BY t.txn_date
    """, a_params).fetchall()
    tag_counter = {}
    for r in alerts:
        tags = []
        try:
            tags = json.loads(r["rule_tags"] or "[]")
        except Exception:
            pass
        for tg in tags:
            tag_counter[tg] = tag_counter.get(tg, 0) + 1

    # KYC profile
    kyc = db.execute("SELECT expected_monthly_in, expected_monthly_out FROM kyc_profile WHERE customer_id=?", (customer_id,)).fetchone()
    exp_in  = float(kyc["expected_monthly_in"]  or 0.0) if kyc else 0.0
    exp_out = float(kyc["expected_monthly_out"] or 0.0) if kyc else 0.0

    return {
        "total_in": total_in, "total_out": total_out,
        "n_in": n_in, "n_out": n_out, "avg_in": avg_in, "avg_out": avg_out,
        "max_in": max_in, "max_out": max_out,
        "cash_in": cash_in, "cash_out": cash_out,
        "overseas": overseas, "overseas_pct": overseas_pct,
        "hr_val": hr_val, "hr_pct": hr_pct,
        "alerts": [dict(a) for a in alerts],
        "tag_counter": tag_counter,
        "expected_in": exp_in, "expected_out": exp_out,
    }


def _answers_summary(customer_id: str):
    """
    Pull latest AI case answers and summarise whether they’re answered.
    """
    db = get_db()
    case = db.execute(
        "SELECT * FROM ai_cases WHERE customer_id=? ORDER BY updated_at DESC LIMIT 1",
        (customer_id,)
    ).fetchone()
    if not case:
        return None, []

    rows = db.execute("SELECT * FROM ai_answers WHERE case_id=? ORDER BY id", (case["id"],)).fetchall()
    answered = [r for r in rows if (r["answer"] or "").strip()]
    return dict(case), [dict(r) for r in rows],

@app.post("/admin/rule-toggles")
@admin_required
def admin_rule_toggles():
    """Persist on/off switches for each built-in rule."""
    def flag(name): return bool(request.form.get(name))
    cfg_set("cfg_rule_enabled_prohibited_country", flag("enable_prohibited_country"))
    cfg_set("cfg_rule_enabled_high_risk_corridor", flag("enable_high_risk_corridor"))
    cfg_set("cfg_rule_enabled_median_outlier",     flag("enable_median_outlier"))
    cfg_set("cfg_rule_enabled_nlp_risky_terms",    flag("enable_nlp_risky_terms"))
    cfg_set("cfg_rule_enabled_expected_out",       flag("enable_expected_out"))
    cfg_set("cfg_rule_enabled_expected_in",        flag("enable_expected_in"))
    cfg_set("cfg_rule_enabled_cash_daily_breach",  flag("enable_cash_daily_breach"))
    cfg_set("cfg_rule_enabled_severity_mapping",   flag("enable_severity_mapping"))
    cfg_set("cfg_rule_enabled_structuring",        flag("enable_structuring"))
    cfg_set("cfg_rule_enabled_flowthrough",        flag("enable_flowthrough"))
    cfg_set("cfg_rule_enabled_dormancy",           flag("enable_dormancy"))
    cfg_set("cfg_rule_enabled_velocity",           flag("enable_velocity"))
    flash("Rule toggles saved.")
    return redirect(url_for("admin") + "#builtin-rules")

@app.post("/admin/keywords")
@admin_required
def admin_keywords():
    """Add / toggle / delete narrative risk keywords with enabled flags."""
    action = request.form.get("action")
    items = cfg_get("cfg_risky_terms2", [], list)

    if action == "add":
        term = (request.form.get("new_term") or "").strip()
        if term and not any(t for t in items if (t.get("term") or "").lower() == term.lower()):
            items.append({"term": term, "enabled": True})
            cfg_set("cfg_risky_terms2", items)
            flash(f"Added keyword: {term}")
    elif action == "toggle":
        term = request.form.get("term")
        for t in items:
            if t.get("term") == term:
                t["enabled"] = not bool(t.get("enabled"))
                cfg_set("cfg_risky_terms2", items)
                flash(f"Toggled keyword: {term}")
                break
    elif action == "delete":
        term = request.form.get("term")
        new_items = [t for t in items if t.get("term") != term]
        cfg_set("cfg_risky_terms2", new_items)
        flash(f"Removed keyword: {term}")
    else:
        flash("Unknown action.")

    return redirect(url_for("admin") + "#keyword-library")

@app.post("/admin/wipe")
@admin_required
def admin_wipe():
    """Danger: wipe all transactional data (transactions, alerts, optional AI tables)."""
    confirm = (request.form.get("confirm") or "").strip().upper()
    if confirm != "WIPE":
        flash("Type WIPE to confirm deletion.", "error")
        return redirect(url_for("admin") + "#danger")

    db = get_db()
    # Count before delete
    n_tx = db.execute("SELECT COUNT(*) c FROM transactions").fetchone()["c"]
    n_alerts = db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

    # Delete dependents first
    db.execute("DELETE FROM alerts;")
    db.execute("DELETE FROM transactions;")

    # Optional: clear AI working tables if you like
    try:
        db.execute("DELETE FROM ai_answers;")
        db.execute("DELETE FROM ai_cases;")
    except sqlite3.OperationalError:
        pass

    db.commit()
    try:
        db.execute("VACUUM;")
    except sqlite3.OperationalError:
        pass

    flash(f"Wiped {n_tx} transactions and {n_alerts} alerts. Any AI cases/answers were cleared.")
    return redirect(url_for("admin") + "#danger")

@app.route("/sample/<path:name>")
def download_sample(name):
    return send_from_directory(DATA_DIR, name, as_attachment=True)


# --- PDF Report Generation ---
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY


def _generate_customer_report_pdf(customer_id: str, reviewer_name: str, summary_comments: str = "") -> bytes:
    """
    Generate a comprehensive PDF report for a customer review.
    Returns the PDF as bytes.
    """
    db = get_db()
    buffer = io.BytesIO()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='ReportTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=6,
        textColor=colors.HexColor('#1a365d'),
        alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading2'],
        fontSize=12,
        spaceBefore=12,
        spaceAfter=6,
        textColor=colors.HexColor('#2d3748'),
        borderPadding=(0, 0, 3, 0),
    ))
    styles.add(ParagraphStyle(
        name='SubSection',
        parent=styles['Heading3'],
        fontSize=10,
        spaceBefore=8,
        spaceAfter=4,
        textColor=colors.HexColor('#4a5568'),
    ))
    styles.add(ParagraphStyle(
        name='BodyTextJustified',
        parent=styles['Normal'],
        fontSize=9,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name='SmallText',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#718096'),
    ))
    styles.add(ParagraphStyle(
        name='AlertHigh',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#c53030'),
    ))
    styles.add(ParagraphStyle(
        name='AlertMedium',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#dd6b20'),
    ))
    
    elements = []
    
    # --- Header ---
    elements.append(Paragraph("TRANSACTION REVIEW REPORT", styles['ReportTitle']))
    elements.append(Paragraph("Confidential - For Compliance Use Only", styles['SmallText']))
    elements.append(Spacer(1, 4*mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 1: Review Metadata ---
    elements.append(Paragraph("1. REVIEW DETAILS", styles['SectionHeader']))
    
    # Get transaction date range
    date_range = db.execute("""
        SELECT MIN(txn_date) as first_txn, MAX(txn_date) as last_txn
        FROM transactions WHERE customer_id = ?
    """, (customer_id,)).fetchone()
    
    first_txn = date_range['first_txn'] if date_range else 'N/A'
    last_txn = date_range['last_txn'] if date_range else 'N/A'
    
    # Format dates for UK display
    def format_uk_date(d):
        if not d:
            return 'N/A'
        try:
            dt = datetime.strptime(d[:10], '%Y-%m-%d')
            return dt.strftime('%d/%m/%Y')
        except:
            return d
    
    review_date = datetime.now().strftime('%d/%m/%Y %H:%M')
    
    metadata_data = [
        ['Customer ID:', customer_id, 'Review Date:', review_date],
        ['Reviewer:', reviewer_name, 'Report Generated:', datetime.now().strftime('%d/%m/%Y %H:%M')],
        ['Period Covered:', f"{format_uk_date(first_txn)} to {format_uk_date(last_txn)}", '', ''],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[80, 140, 80, 140])
    metadata_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4a5568')),
        ('TEXTCOLOR', (2, 0), (2, -1), colors.HexColor('#4a5568')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 2: Customer Profile ---
    elements.append(Paragraph("2. CUSTOMER PROFILE", styles['SectionHeader']))
    
    # Get KYC data
    kyc = db.execute("SELECT * FROM kyc_profile WHERE customer_id = ?", (customer_id,)).fetchone()
    
    # Get rationale data for nature of business and estimates
    rationale_row = db.execute("""
        SELECT nature_of_business, est_income, est_expenditure 
        FROM ai_rationales 
        WHERE customer_id = ? 
        ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    # Helper to safely get values from sqlite3.Row objects
    def safe_get(row, key, default=None):
        try:
            return row[key] if row and row[key] else default
        except (KeyError, IndexError):
            return default
    
    nature_of_business = safe_get(rationale_row, 'nature_of_business') or safe_get(kyc, 'nature_of_business', 'Not specified')
    est_income = safe_get(rationale_row, 'est_income') or safe_get(kyc, 'expected_monthly_in')
    est_expenditure = safe_get(rationale_row, 'est_expenditure') or safe_get(kyc, 'expected_monthly_out')
    
    profile_data = [
        ['Nature of Business:', nature_of_business or 'Not specified'],
        ['Expected Monthly Income:', f"£{float(est_income):,.2f}" if est_income else 'Not specified'],
        ['Expected Monthly Expenditure:', f"£{float(est_expenditure):,.2f}" if est_expenditure else 'Not specified'],
    ]
    
    if kyc:
        account_open = safe_get(kyc, 'account_open_date')
        if account_open:
            profile_data.append(['Account Open Date:', format_uk_date(account_open)])
    
    profile_table = Table(profile_data, colWidths=[140, 300])
    profile_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4a5568')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(profile_table)
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 3: Account Metrics Summary ---
    elements.append(Paragraph("3. ACCOUNT METRICS SUMMARY", styles['SectionHeader']))
    
    # Calculate metrics
    metrics = db.execute("""
        SELECT 
            COUNT(*) as total_txns,
            SUM(CASE WHEN direction='in' THEN base_amount ELSE 0 END) as total_in,
            SUM(CASE WHEN direction='out' THEN base_amount ELSE 0 END) as total_out,
            AVG(CASE WHEN direction='in' THEN base_amount END) as avg_in,
            AVG(CASE WHEN direction='out' THEN base_amount END) as avg_out,
            MAX(CASE WHEN direction='in' THEN base_amount END) as max_in,
            MAX(CASE WHEN direction='out' THEN base_amount END) as max_out,
            SUM(CASE WHEN direction='in' AND channel='cash' THEN base_amount ELSE 0 END) as cash_in,
            SUM(CASE WHEN direction='out' AND channel='cash' THEN base_amount ELSE 0 END) as cash_out,
            SUM(CASE WHEN country_iso2 IS NOT NULL AND country_iso2 != '' AND country_iso2 != 'GB' THEN base_amount ELSE 0 END) as overseas
        FROM transactions WHERE customer_id = ?
    """, (customer_id,)).fetchone()
    
    total_in = float(metrics['total_in'] or 0)
    total_out = float(metrics['total_out'] or 0)
    total_value = total_in + total_out
    overseas = float(metrics['overseas'] or 0)
    overseas_pct = (overseas / total_value * 100) if total_value > 0 else 0
    
    # High-risk value
    hr_row = db.execute("""
        SELECT COALESCE(SUM(t.base_amount), 0) as hr_val
        FROM transactions t
        JOIN ref_country_risk r ON t.country_iso2 = r.iso2
        WHERE t.customer_id = ? AND r.risk_level IN ('HIGH', 'HIGH_3RD', 'PROHIBITED')
    """, (customer_id,)).fetchone()
    hr_val = float(hr_row['hr_val'] or 0)
    hr_pct = (hr_val / total_value * 100) if total_value > 0 else 0
    
    elements.append(Paragraph("Transaction Volumes", styles['SubSection']))
    
    vol_data = [
        ['Metric', 'Credits (In)', 'Debits (Out)', 'Total'],
        ['Total Value', f"£{total_in:,.2f}", f"£{total_out:,.2f}", f"£{total_value:,.2f}"],
        ['Average Value', f"£{float(metrics['avg_in'] or 0):,.2f}", f"£{float(metrics['avg_out'] or 0):,.2f}", '-'],
        ['Largest Single', f"£{float(metrics['max_in'] or 0):,.2f}", f"£{float(metrics['max_out'] or 0):,.2f}", '-'],
        ['Transaction Count', str(db.execute("SELECT COUNT(*) FROM transactions WHERE customer_id=? AND direction='in'", (customer_id,)).fetchone()[0]),
                             str(db.execute("SELECT COUNT(*) FROM transactions WHERE customer_id=? AND direction='out'", (customer_id,)).fetchone()[0]),
                             str(metrics['total_txns'])],
    ]
    
    vol_table = Table(vol_data, colWidths=[100, 100, 100, 100])
    vol_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#edf2f7')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(vol_table)
    elements.append(Spacer(1, 3*mm))
    
    elements.append(Paragraph("Cash & International Activity", styles['SubSection']))
    
    activity_data = [
        ['Category', 'Value', '% of Total'],
        ['Cash Deposits', f"£{float(metrics['cash_in'] or 0):,.2f}", f"{(float(metrics['cash_in'] or 0)/total_value*100) if total_value > 0 else 0:.1f}%"],
        ['Cash Withdrawals', f"£{float(metrics['cash_out'] or 0):,.2f}", f"{(float(metrics['cash_out'] or 0)/total_value*100) if total_value > 0 else 0:.1f}%"],
        ['Overseas Activity', f"£{overseas:,.2f}", f"{overseas_pct:.1f}%"],
        ['High-Risk Corridors', f"£{hr_val:,.2f}", f"{hr_pct:.1f}%"],
    ]
    
    activity_table = Table(activity_data, colWidths=[140, 100, 80])
    activity_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#edf2f7')),
        ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(activity_table)
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 4: Alert Summary ---
    elements.append(Paragraph("4. ALERT SUMMARY", styles['SectionHeader']))
    
    # Get alerts by severity
    severity_counts = db.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM alerts WHERE customer_id = ?
        GROUP BY severity ORDER BY 
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
    """, (customer_id,)).fetchall()
    
    # Get alerts by type
    all_alerts = db.execute("""
        SELECT rule_tags FROM alerts WHERE customer_id = ?
    """, (customer_id,)).fetchall()
    
    tag_counts = defaultdict(int)
    for row in all_alerts:
        try:
            tags = json.loads(row['rule_tags']) if row['rule_tags'] else []
            for tag in tags:
                tag_counts[tag] += 1
        except:
            pass
    
    total_alerts = sum(r['cnt'] for r in severity_counts)
    
    elements.append(Paragraph(f"Total Alerts Generated: {total_alerts}", styles['BodyTextJustified']))
    
    if severity_counts:
        elements.append(Paragraph("Alerts by Severity", styles['SubSection']))
        sev_data = [['Severity', 'Count']]
        for row in severity_counts:
            sev_data.append([row['severity'], str(row['cnt'])])
        
        sev_table = Table(sev_data, colWidths=[100, 60])
        sev_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#edf2f7')),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 3*mm))
    
    if tag_counts:
        elements.append(Paragraph("Alerts by Type", styles['SubSection']))
        type_data = [['Alert Type', 'Count']]
        for tag, cnt in sorted(tag_counts.items(), key=lambda x: -x[1]):
            type_data.append([tag.replace('_', ' ').title(), str(cnt)])
        
        type_table = Table(type_data, colWidths=[180, 60])
        type_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#edf2f7')),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(type_table)
    
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 5: Customer Outreach ---
    elements.append(Paragraph("5. CUSTOMER OUTREACH", styles['SectionHeader']))
    
    # Get the latest case and answers
    case = db.execute("""
        SELECT * FROM ai_cases WHERE customer_id = ? ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    if case:
        answers = db.execute("""
            SELECT tag, question, answer FROM ai_answers WHERE case_id = ? ORDER BY id
        """, (case['id'],)).fetchall()
        
        if answers:
            answered = sum(1 for a in answers if (a['answer'] or '').strip())
            outstanding = len(answers) - answered
            
            elements.append(Paragraph(f"Questions Sent: {len(answers)} | Answered: {answered} | Outstanding: {outstanding}", styles['BodyTextJustified']))
            elements.append(Spacer(1, 2*mm))
            
            for idx, ans in enumerate(answers, 1):
                tag = (ans['tag'] or '').replace('_', ' ').title()
                question = ans['question'] or ''
                answer = ans['answer'] or ''
                
                elements.append(Paragraph(f"<b>Q{idx} ({tag}):</b> {question}", styles['BodyTextJustified']))
                
                if answer.strip():
                    elements.append(Paragraph(f"<b>A{idx}:</b> {answer}", styles['BodyTextJustified']))
                else:
                    elements.append(Paragraph(f"<b>A{idx}:</b> <i>[No response received]</i>", styles['SmallText']))
                
                elements.append(Spacer(1, 2*mm))
        else:
            elements.append(Paragraph("No outreach questions have been sent for this customer.", styles['BodyTextJustified']))
    else:
        elements.append(Paragraph("No outreach case exists for this customer.", styles['BodyTextJustified']))
    
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 6: Summary Comments ---
    elements.append(Paragraph("6. REVIEWER COMMENTS & CONCLUSION", styles['SectionHeader']))
    
    if summary_comments and summary_comments.strip():
        elements.append(Paragraph(summary_comments, styles['BodyTextJustified']))
    else:
        elements.append(Paragraph("<i>No summary comments provided.</i>", styles['SmallText']))
    
    elements.append(Spacer(1, 6*mm))
    
    # --- Footer ---
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    elements.append(Spacer(1, 2*mm))
    elements.append(Paragraph(
        f"Report generated by Scrutinise TXN | {datetime.now().strftime('%d/%m/%Y %H:%M')} | Page 1",
        styles['SmallText']
    ))
    elements.append(Paragraph(
        "This document is confidential and intended for compliance review purposes only.",
        styles['SmallText']
    ))
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


@app.route("/report/pdf/<customer_id>", methods=["GET", "POST"])
@login_required
def generate_pdf_report(customer_id):
    """Generate and download a PDF report for the customer."""
    from flask import Response
    
    # Get reviewer name from session
    reviewer_name = session.get('username', 'Unknown')
    
    # Get summary comments if provided
    summary_comments = request.form.get('summary_comments', '') if request.method == 'POST' else ''
    
    # Generate the PDF
    pdf_bytes = _generate_customer_report_pdf(customer_id, reviewer_name, summary_comments)
    
    # Create filename
    filename = f"Transaction_Review_{customer_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'application/pdf'
        }
    )


@app.route("/report/preview/<customer_id>")
@login_required
def report_preview(customer_id):
    """Show a full preview of the report before generating the PDF."""
    db = get_db()
    
    # Helper to safely get values from sqlite3.Row objects
    def safe_get(row, key, default=None):
        try:
            return row[key] if row and row[key] else default
        except (KeyError, IndexError):
            return default
    
    def format_uk_date(d):
        if not d:
            return 'N/A'
        try:
            dt = datetime.strptime(d[:10], '%Y-%m-%d')
            return dt.strftime('%d/%m/%Y')
        except:
            return d
    
    # Get transaction date range
    date_range = db.execute("""
        SELECT MIN(txn_date) as first_txn, MAX(txn_date) as last_txn, COUNT(*) as txn_count
        FROM transactions WHERE customer_id = ?
    """, (customer_id,)).fetchone()
    
    # Get KYC data
    kyc = db.execute("SELECT * FROM kyc_profile WHERE customer_id = ?", (customer_id,)).fetchone()
    
    # Get rationale data
    rationale = db.execute("""
        SELECT nature_of_business, est_income, est_expenditure 
        FROM ai_rationales WHERE customer_id = ? ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    nature_of_business = safe_get(rationale, 'nature_of_business') or safe_get(kyc, 'nature_of_business', 'Not specified')
    est_income = safe_get(rationale, 'est_income') or safe_get(kyc, 'expected_monthly_in')
    est_expenditure = safe_get(rationale, 'est_expenditure') or safe_get(kyc, 'expected_monthly_out')
    
    # Calculate metrics
    metrics = db.execute("""
        SELECT 
            COUNT(*) as total_txns,
            SUM(CASE WHEN direction='in' THEN base_amount ELSE 0 END) as total_in,
            SUM(CASE WHEN direction='out' THEN base_amount ELSE 0 END) as total_out,
            AVG(CASE WHEN direction='in' THEN base_amount END) as avg_in,
            AVG(CASE WHEN direction='out' THEN base_amount END) as avg_out,
            MAX(CASE WHEN direction='in' THEN base_amount END) as max_in,
            MAX(CASE WHEN direction='out' THEN base_amount END) as max_out,
            SUM(CASE WHEN direction='in' AND channel='cash' THEN base_amount ELSE 0 END) as cash_in,
            SUM(CASE WHEN direction='out' AND channel='cash' THEN base_amount ELSE 0 END) as cash_out,
            SUM(CASE WHEN country_iso2 IS NOT NULL AND country_iso2 != '' AND country_iso2 != 'GB' THEN base_amount ELSE 0 END) as overseas,
            COUNT(CASE WHEN direction='in' THEN 1 END) as count_in,
            COUNT(CASE WHEN direction='out' THEN 1 END) as count_out
        FROM transactions WHERE customer_id = ?
    """, (customer_id,)).fetchone()
    
    total_in = float(metrics['total_in'] or 0)
    total_out = float(metrics['total_out'] or 0)
    total_value = total_in + total_out
    overseas = float(metrics['overseas'] or 0)
    overseas_pct = (overseas / total_value * 100) if total_value > 0 else 0
    
    # High-risk value
    hr_row = db.execute("""
        SELECT COALESCE(SUM(t.base_amount), 0) as hr_val
        FROM transactions t
        JOIN ref_country_risk r ON t.country_iso2 = r.iso2
        WHERE t.customer_id = ? AND r.risk_level IN ('HIGH', 'HIGH_3RD', 'PROHIBITED')
    """, (customer_id,)).fetchone()
    hr_val = float(hr_row['hr_val'] or 0)
    hr_pct = (hr_val / total_value * 100) if total_value > 0 else 0
    
    # Alerts by severity
    severity_counts = db.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM alerts WHERE customer_id = ?
        GROUP BY severity ORDER BY 
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
    """, (customer_id,)).fetchall()
    
    # Alerts by type
    all_alerts = db.execute("SELECT rule_tags FROM alerts WHERE customer_id = ?", (customer_id,)).fetchall()
    tag_counts = defaultdict(int)
    for row in all_alerts:
        try:
            tags = json.loads(row['rule_tags']) if row['rule_tags'] else []
            for tag in tags:
                tag_counts[tag] += 1
        except:
            pass
    
    total_alerts = sum(r['cnt'] for r in severity_counts)
    
    # Get outreach Q&A
    case = db.execute("""
        SELECT * FROM ai_cases WHERE customer_id = ? ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    answers = []
    if case:
        answers = db.execute("""
            SELECT tag, question, answer FROM ai_answers WHERE case_id = ? ORDER BY id
        """, (case['id'],)).fetchall()
    
    answered_count = sum(1 for a in answers if (a['answer'] or '').strip()) if answers else 0
    
    reviewer_name = session.get('username', 'Unknown')
    
    return render_template('report_preview.html',
        customer_id=customer_id,
        reviewer_name=reviewer_name,
        report_date=datetime.now().strftime('%d/%m/%Y'),
        report_time=datetime.now().strftime('%H:%M'),
        first_txn=date_range['first_txn'] if date_range else None,
        last_txn=date_range['last_txn'] if date_range else None,
        first_txn_formatted=format_uk_date(date_range['first_txn']) if date_range else 'N/A',
        last_txn_formatted=format_uk_date(date_range['last_txn']) if date_range else 'N/A',
        txn_count=date_range['txn_count'] if date_range else 0,
        nature_of_business=nature_of_business,
        est_income=est_income,
        est_expenditure=est_expenditure,
        # Metrics
        total_in=total_in,
        total_out=total_out,
        total_value=total_value,
        avg_in=float(metrics['avg_in'] or 0),
        avg_out=float(metrics['avg_out'] or 0),
        max_in=float(metrics['max_in'] or 0),
        max_out=float(metrics['max_out'] or 0),
        count_in=metrics['count_in'] or 0,
        count_out=metrics['count_out'] or 0,
        cash_in=float(metrics['cash_in'] or 0),
        cash_out=float(metrics['cash_out'] or 0),
        overseas=overseas,
        overseas_pct=overseas_pct,
        hr_val=hr_val,
        hr_pct=hr_pct,
        # Alerts
        total_alerts=total_alerts,
        severity_counts=severity_counts,
        tag_counts=dict(sorted(tag_counts.items(), key=lambda x: -x[1])),
        # Outreach
        answers=answers,
        answered_count=answered_count,
        outstanding_count=len(answers) - answered_count if answers else 0,
    )


if __name__ == "__main__":
    # All DB init/seed must run inside the Flask app context
    with app.app_context():
        init_db()
        ensure_default_parameters()
        ensure_ai_tables()
        ensure_ai_rationale_table()
        ensure_users_table()      # Create users table and seed admin user
        ensure_customers_table()  # Create customers table
        ensure_statements_table() # Create statements table
        ensure_audit_log_table()  # Create audit log table for security events
        
        # Database security hardening
        secure_database_file(DB_PATH)
        security_warnings = verify_db_path_security(DB_PATH)
        if security_warnings:
            print("⚠️  DATABASE SECURITY WARNINGS:")
            for w in security_warnings:
                print(f"   - {w}")
        else:
            print("✓ Database security checks passed")
        
        db = get_db()
        if db.execute("SELECT COUNT(*) c FROM ref_country_risk").fetchone()["c"] == 0:
            load_csv_to_table(os.path.join(DATA_DIR, "ref_country_risk.csv"), "ref_country_risk")
        if db.execute("SELECT COUNT(*) c FROM ref_sort_codes").fetchone()["c"] == 0:
            load_csv_to_table(os.path.join(DATA_DIR, "ref_sort_codes.csv"), "ref_sort_codes")
        if db.execute("SELECT COUNT(*) c FROM kyc_profile").fetchone()["c"] == 0:
            load_csv_to_table(os.path.join(DATA_DIR, "kyc_profile.csv"), "kyc_profile")
        # Skip legacy transaction loading - require fresh customer population
        # if db.execute("SELECT COUNT(*) c FROM transactions").fetchone()["c"] == 0:
        #     with open(os.path.join(DATA_DIR, "transactions_sample.csv"), "rb") as f:
        #         ingest_transactions_csv(f)

    app.run(host='0.0.0.0', debug=os.getenv('FLASK_DEBUG', '').lower() == 'true', port=3000)