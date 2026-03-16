import os, csv, io, json, tempfile
import time
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
import string
import hashlib
import base64
import logging
import requests
from urllib.parse import urlparse
import logging
from urllib.parse import urlparse
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

import psycopg2
import psycopg2.extras
import psycopg2.pool

from flask import Flask, g, render_template, request, redirect, url_for, send_from_directory, flash, abort, session, Response, jsonify

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "tx_review")
DB_USER = os.getenv("POSTGRES_USER", "tx_user")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "tx_password")

# Encryption feature flags / secrets
ENCRYPT_SENSITIVE_FIELDS = os.getenv("ENCRYPT_SENSITIVE_FIELDS", "1") in ("1", "true", "True", "yes", "on")
DB_ENCRYPTION_KEY = os.getenv("DB_ENCRYPTION_KEY", "")

def get_db_connection_string():
    """Build PostgreSQL connection string from environment variables."""
    return f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD}"

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# ---------- Database wrapper for SQLite <-> PostgreSQL compatibility ----------
class DBWrapper:
    """Wrapper around psycopg2 connection to provide SQLite-like interface."""
    def __init__(self, connection):
        self.connection = connection
        self._lastrowid = None
    
    def execute(self, sql, params=()):
        """Execute SQL with parameter substitution and return cursor result."""
        # In PostgreSQL, we need %s placeholders instead of ?
        # Add light retry for transient deadlocks/serialization failures
        attempts = 3
        backoff = 0.15
        for i in range(attempts):
            try:
                sql_pg = sql.replace('?', '%s')
                cur = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(sql_pg, params)
                if hasattr(cur, 'lastrowid'):
                    self._lastrowid = cur.lastrowid
                return cur
            except (psycopg2.errors.DeadlockDetected, getattr(psycopg2.errors, 'SerializationFailure', psycopg2.Error)) as e:
                self.connection.rollback()
                if i < attempts - 1:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                app.logger.error(f"Database error occurred: {type(e).__name__}", exc_info=True)
                raise
            except psycopg2.Error as e:
                app.logger.error(f"Database error occurred: {type(e).__name__}", exc_info=True)
                raise
    
    def executemany(self, sql, seq_of_params):
        """Execute SQL with multiple parameter sets using execute_batch for bulk performance."""
        try:
            sql_pg = sql.replace('?', '%s')
            cur = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # execute_batch sends multiple statements per network round-trip (2-5x faster)
            psycopg2.extras.execute_batch(cur, sql_pg, list(seq_of_params), page_size=1000)
            return cur
        except psycopg2.Error as e:
            app.logger.error(f"Database error occurred: {type(e).__name__}", exc_info=True)
            raise

    def executescript(self, sql):
        """Execute multiple SQL statements."""
        cur = self.connection.cursor()
        try:
            cur.execute(sql)
        except psycopg2.Error as e:
            app.logger.error(f"Script execution error: {type(e).__name__}", exc_info=True)
            raise
    
    def commit(self):
        """Commit the transaction."""
        self.connection.commit()
    
    def rollback(self):
        """Rollback the transaction."""
        self.connection.rollback()
    
    def close(self):
        """Close the connection."""
        self.connection.close()

# Connection pool (initialised lazily on first use)
_db_pool = None
_db_pool_lock = __import__('threading').Lock()

def _get_pool():
    """Get or create the shared connection pool (thread-safe)."""
    global _db_pool
    if _db_pool is None:
        with _db_pool_lock:
            if _db_pool is None:
                _db_pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=4,
                    maxconn=150,
                    dsn=get_db_connection_string(),
                )
    return _db_pool

def _get_raw_db():
    """Get a pooled psycopg2 connection for the current request."""
    if "db_raw" not in g:
        try:
            conn = _get_pool().getconn()
            conn.autocommit = False
            g.db_raw = conn
        except psycopg2.Error as e:
            app.logger.error(f"Database connection error: {type(e).__name__}", exc_info=True)
            raise
    return g.db_raw

def get_db():
    """Get wrapped database connection."""
    if "db" not in g:
        g.db = DBWrapper(_get_raw_db())
    return g.db


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
    """PostgreSQL database security is handled at the server level and via connection parameters."""
    pass


def verify_db_path_security(db_path: str) -> list:
    """PostgreSQL database security is handled at the server level."""
    return []

app = Flask(__name__)
# SECRET_KEY must be consistent across Gunicorn workers. If not set
# explicitly, derive a stable key from the DB connection string so all
# workers share the same session signing key.
_secret_env = os.getenv("SECRET_KEY", "")
if not _secret_env:
    import hashlib
    _secret_env = hashlib.sha256(
        f"{DB_HOST}:{DB_PORT}:{DB_NAME}:{DB_USER}".encode()
    ).hexdigest()
app.secret_key = _secret_env


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
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB upload limit (AGRA-001-1-11)

# Security constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
PASSWORD_MIN_LENGTH = 10
COMMON_PASSWORDS = {'password', 'password123', 'admin123', '123456789', 'qwerty123', 'letmein123'}

# Pre-computed dummy hash for constant-time login (AGRA-001-1-4 pen test remediation)
# Used to equalise response times for valid vs invalid usernames
_DUMMY_PASSWORD_HASH = generate_password_hash("dummy-constant-time-placeholder")


# ---------- CSRF Protection ----------
def generate_csrf_token():
    """Generate or return existing CSRF token for the current session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.template_filter('uk_date')
def _jinja_uk_date(val):
    """Format a date/datetime for UK display. Shows time only when present."""
    if not val:
        return '-'
    try:
        if isinstance(val, datetime):
            if val.hour == 0 and val.minute == 0 and val.second == 0:
                return val.strftime('%d/%m/%Y')
            return val.strftime('%d/%m/%Y %H:%M')
        if isinstance(val, date):
            return val.strftime('%d/%m/%Y')
        s = str(val)
        dt = datetime.fromisoformat(s) if 'T' in s or len(s) > 10 else datetime.strptime(s[:10], '%Y-%m-%d')
        if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
            return dt.strftime('%d/%m/%Y')
        return dt.strftime('%d/%m/%Y %H:%M')
    except Exception:
        return str(val)


@app.before_request
def csrf_protect():
    """Validate CSRF token on all POST requests."""
    if request.method == "POST":
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            abort(403)
# ---------- One-time DB bootstrap under WSGI (Gunicorn) ----------
def is_safe_redirect_url(url):
    """Validate that redirect URL is safe (same origin only)."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
        # Ensure URL is relative or same origin
        return not parsed.netloc or parsed.netloc == request.host
    except Exception:
        return False

@app.before_request
def _bootstrap_db_once():
    """Ensure schema and baseline data exist when running under a WSGI server.
    Runs once per process using an in-memory flag.
    """
    if app.config.get('_DB_INIT_DONE'):
        return
    # Initialize PostgreSQL schema and seed defaults if needed
    init_db()
    try:
        ensure_default_parameters()
    except Exception as e:
        app.logger.error(f"Failed to ensure default parameters: {e}", exc_info=True)
    try:
        ensure_ai_tables()
        ensure_ai_rationale_table()
    except Exception as e:
        app.logger.error(f"Failed to initialize AI tables: {e}", exc_info=True)
    try:
        ensure_users_table()
        ensure_manager_roles()
        ensure_password_reset_tokens()
        ensure_customers_table()
        ensure_statements_table()
        ensure_audit_log_table()
    except Exception as e:
        app.logger.error(f"Failed to initialize core tables: {e}", exc_info=True)
    try:
        # Seed reference CSVs if empty
        db = get_db()
        if db.execute("SELECT COUNT(*) c FROM ref_country_risk").fetchone()["c"] == 0:
            load_csv_to_table(os.path.join(DATA_DIR, "ref_country_risk.csv"), "ref_country_risk")
        if db.execute("SELECT COUNT(*) c FROM ref_sort_codes").fetchone()["c"] == 0:
            load_csv_to_table(os.path.join(DATA_DIR, "ref_sort_codes.csv"), "ref_sort_codes")
        if db.execute("SELECT COUNT(*) c FROM kyc_profile").fetchone()["c"] == 0:
            load_csv_to_table(os.path.join(DATA_DIR, "kyc_profile.csv"), "kyc_profile")
    except Exception as e:
        app.logger.error(f"Failed to seed reference data: {e}", exc_info=True)
    app.config['_DB_INIT_DONE'] = True


# ---------- Robots.txt (ensures our security headers apply) ----------
@app.route('/robots.txt')
def robots_txt():
    resp = Response("User-agent: *\nDisallow: /\n", mimetype='text/plain')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

# ---------- Error handlers (ensure headers on 403/404/500 too) ----------
@app.errorhandler(403)
def forbidden(e):
    flash("Your session has expired or the request could not be verified. Please try again.", "warning")
    return redirect(request.referrer or url_for("login"))

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
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
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
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'credentialless'  # AGRA-001-1-14
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
    except Exception:
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
    return cfg_get('cfg_enforce_2fa', True, bool)


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
            'use_oauth': cfg_get('cfg_smtp_use_oauth', False, bool),
            'tenant_id': cfg_get('cfg_smtp_tenant_id', '', str),
        }
    except Exception:
        return None


def set_smtp_password(password: str):
    """Store SMTP password with encryption."""
    encrypted = encrypt_value(password) if password else ''
    cfg_set('cfg_smtp_password', encrypted)



def get_oauth2_access_token(tenant_id: str, client_id: str, client_secret: str) -> tuple[Optional[str], Optional[str]]:
    """Obtain an OAuth2 access token for Exchange Online SMTP using client credentials.

    Returns (access_token, error_message). On success, error_message is None.
    """

    try:
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://outlook.office365.com/.default",
            "grant_type": "client_credentials",
        }
        resp = requests.post(token_url, data=data, timeout=20)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        
        payload = resp.json()
        token = payload.get("access_token")
        if not token:
            return None, "No access_token in response"
        return token, None
    except Exception as ex:
        return None, str(ex)

_email_executor = __import__('concurrent.futures').futures.ThreadPoolExecutor(max_workers=3)

# --- Background scoring executor ---------------------------------------------------
_scoring_executor = __import__('concurrent.futures').futures.ThreadPoolExecutor(max_workers=6)

def _set_scoring_status(customer_id, status, msg=""):
    """Persist scoring status to the scoring_jobs table (DB-backed, cross-worker safe)."""
    import datetime as _dt
    conn = _get_pool().getconn()
    try:
        conn.autocommit = False
        cur = conn.cursor()
        now = _dt.datetime.utcnow()
        if status == "scoring":
            cur.execute(
                "UPDATE scoring_jobs SET message=%s, updated_at=%s "
                "WHERE id = (SELECT id FROM scoring_jobs WHERE customer_id=%s AND status='scoring' "
                "ORDER BY updated_at DESC LIMIT 1)",
                (msg, now, customer_id)
            )
            if cur.rowcount == 0:
                cur.execute(
                    "INSERT INTO scoring_jobs(customer_id, status, started_at, updated_at, message) "
                    "VALUES(%s, %s, %s, %s, %s)",
                    (customer_id, status, now, now, msg)
                )
        else:
            cur.execute(
                "UPDATE scoring_jobs SET status=%s, message=%s, updated_at=%s "
                "WHERE customer_id=%s AND status='scoring'",
                (status, msg, now, customer_id)
            )
        conn.commit()
    except Exception as e:
        app.logger.error(f"_set_scoring_status failed for {customer_id}/{status}: {e}", exc_info=True)
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        try:
            _get_pool().putconn(conn)
        except Exception:
            try:
                _get_pool().putconn(conn, close=True)
            except Exception:
                pass


def _get_scoring_status(customer_id):
    """Read scoring status from DB. Returns dict or None."""
    try:
        db = get_db()
        row = db.execute(
            "SELECT status, message AS msg, started_at "
            "FROM scoring_jobs WHERE customer_id = ? "
            "ORDER BY updated_at DESC LIMIT 1",
            (customer_id,)
        ).fetchone()
        try:
            db.execute(
                "UPDATE scoring_jobs SET status='error', message='Processing timed out — worker may have restarted' "
                "WHERE status = 'scoring' AND updated_at < CURRENT_TIMESTAMP - INTERVAL '10 minutes'"
            )
            db.execute(
                "DELETE FROM scoring_jobs WHERE status != 'scoring' "
                "AND updated_at < CURRENT_TIMESTAMP - INTERVAL '1 hour'"
            )
            db.commit()
        except Exception:
            pass
        if row:
            if row["status"] == "scoring":
                row = db.execute(
                    "SELECT status, message AS msg, started_at "
                    "FROM scoring_jobs WHERE customer_id = ? "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (customer_id,)
                ).fetchone()
            return {"status": row["status"], "msg": row["msg"] or "", "started": row["started_at"]}
        return None
    except Exception:
        return None


def _clear_scoring_status(customer_id):
    """Delete completed/errored scoring_jobs rows for this customer."""
    try:
        db = get_db()
        db.execute(
            "DELETE FROM scoring_jobs WHERE customer_id = ? AND status != 'scoring'",
            (customer_id,)
        )
        db.commit()
    except Exception:
        pass


def _run_scoring_background(customer_id, purge_first=False):
    """Run score_new_transactions() in a background thread with its own app context."""
    try:
        _set_scoring_status(customer_id, "scoring")
        with app.app_context():
            if purge_first:
                db = get_db()
                db.execute("DELETE FROM alerts WHERE customer_id = ?", (customer_id,))
                db.execute(
                    "DELETE FROM alerts WHERE txn_id IN "
                    "(SELECT id FROM transactions WHERE customer_id = ?)",
                    (customer_id,)
                )
                db.commit()
            score_new_transactions(customer_id=customer_id)
            refresh_customer_summary(customer_id)
        _set_scoring_status(customer_id, "done", f"Scoring complete for {customer_id}")
    except Exception as e:
        app.logger.error(f"Background scoring failed for {customer_id}: {e}", exc_info=True)
        _set_scoring_status(customer_id, "error", "Scoring failed — see server logs for details")


def submit_scoring(customer_id, purge_first=False):
    """Submit scoring to the background executor. Returns immediately."""
    _scoring_executor.submit(_run_scoring_background, customer_id, purge_first)


def _run_ingest_and_score_background(customer_id, tmp_path, stmt_id, original_filename,
                                     account_name, user_id, username):
    """Run file ingest + scoring in a background thread. Cleans up temp file when done."""
    try:
        _set_scoring_status(customer_id, "scoring", "Ingesting transactions…")
        with app.app_context():
            with open(tmp_path, "rb") as f:
                f.filename = original_filename
                n, date_from, date_to = ingest_transactions_csv_for_customer(
                    f, customer_id, statement_id=stmt_id
                )
            db = get_db()
            db.execute(
                "UPDATE statements SET record_count=?, date_from=?, date_to=? WHERE id=?",
                (n, date_from, date_to, stmt_id)
            )
            db.commit()
            log_audit_event("TRANSACTION_UPLOAD", user_id, username,
                            details=f"Uploaded {n} transactions for customer {customer_id} "
                                    f"(account: {account_name or 'N/A'}, file: {original_filename})")
            _set_scoring_status(customer_id, "scoring", "Scoring transactions…")
            db.execute("DELETE FROM alerts WHERE customer_id = ?", (customer_id,))
            db.execute(
                "DELETE FROM alerts WHERE txn_id IN "
                "(SELECT id FROM transactions WHERE customer_id = ?)",
                (customer_id,)
            )
            db.commit()
            score_new_transactions(customer_id=customer_id)
            refresh_customer_summary(customer_id)
        _set_scoring_status(customer_id, "done", f"Ingested {n} transactions and scoring complete")
    except Exception as e:
        app.logger.error(f"Background ingest+scoring failed for {customer_id}: {e}", exc_info=True)
        _set_scoring_status(customer_id, "error", "Upload/scoring failed — see server logs for details")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def submit_ingest_and_score(customer_id, tmp_path, stmt_id, original_filename,
                            account_name, user_id, username):
    """Submit ingest+scoring to the background executor. Returns immediately."""
    _scoring_executor.submit(
        _run_ingest_and_score_background,
        customer_id, tmp_path, stmt_id, original_filename,
        account_name, user_id, username
    )


def _send_email_sync(config, to_email, msg_string):
    """Internal: send a pre-built email synchronously (runs in background thread)."""
    try:
        if config['use_tls']:
            server = smtplib.SMTP(config['host'], config['port'], timeout=15)
            # Say hello before and after STARTTLS per SMTP best practice
            try:
                server.ehlo()
            except Exception:
                pass
            server.starttls()
            try:
                server.ehlo()
            except Exception:
                pass
        else:
            server = smtplib.SMTP_SSL(config['host'], config['port'], timeout=15)
            try:
                server.ehlo()
            except Exception:
                pass
        
        if config.get('use_oauth'):
            if not config.get('tenant_id'):
                server.quit()
                return False, "OAuth is enabled but Tenant ID is missing."
            if not config.get('username') or not config.get('password'):
                server.quit()
                return False, "OAuth is enabled but Client ID or Client Secret is missing."
            if not config.get('from_email'):
                server.quit()
                return False, "OAuth is enabled but From Email (SMTP user) is missing."

            print(f"{config['tenant_id']}:{config['username']}:{'***' if config['password'] else ''}", flush=True)
            print("Obtaining OAuth2 access token for SMTP authentication...", flush=True)

            token, err = get_oauth2_access_token(
                tenant_id=config['tenant_id'],
                client_id=config['username'],
                client_secret=config['password']
            )

            if not token:
                server.quit()
                return False, f"Failed to obtain OAuth token: {err}"

            smtp_user = config['from_email'] or ''
            auth_string = f"user={smtp_user}\x01auth=Bearer {token}\x01\x01"
            auth_b64 = base64.b64encode(auth_string.encode()).decode()
            # Ensure server is ready for AUTH after EHLO/STARTTLS
            code, resp = server.docmd("AUTH", "XOAUTH2 " + auth_b64)
            if code != 235:
                server.quit()
                return False, f"OAuth authentication failed: {code} {resp.decode() if isinstance(resp, (bytes, bytearray)) else resp}"
        else:
            if config['username'] and config['password']:
                server.login(config['username'], config['password'])

        server.sendmail(config['from_email'], to_email, msg_string)
        server.quit()
        return True, "Email sent successfully."
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"


def send_email(to_email: str, subject: str, html_body: str, text_body: str = None, blocking: bool = False) -> tuple[bool, str]:
    """Send email using configured SMTP settings.

    By default sends asynchronously (non-blocking). Set blocking=True for
    synchronous send (e.g. test emails where the caller needs the result).
    """
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

        msg_string = msg.as_string()

        if blocking:
            return _send_email_sync(config, to_email, msg_string)

        # Fire-and-forget in background thread
        _email_executor.submit(_send_email_sync, config, to_email, msg_string)
        return True, "Email queued for delivery."
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
CREATE TABLE IF NOT EXISTS config_versions(
  id BIGSERIAL PRIMARY KEY,
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
  expected_monthly_in DOUBLE PRECISION,
  expected_monthly_out DOUBLE PRECISION,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customer_cash_limits(
  customer_id TEXT PRIMARY KEY,
  daily_limit DOUBLE PRECISION,
  weekly_limit DOUBLE PRECISION,
  monthly_limit DOUBLE PRECISION,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions(
  id TEXT PRIMARY KEY,
  txn_date TIMESTAMP NOT NULL,
  customer_id TEXT NOT NULL,
  direction TEXT CHECK(direction IN ('in','out')) NOT NULL,
  amount DOUBLE PRECISION NOT NULL,
  currency TEXT DEFAULT 'GBP',
  base_amount DOUBLE PRECISION NOT NULL,
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
  id BIGSERIAL PRIMARY KEY,
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
CREATE INDEX IF NOT EXISTS idx_alerts_txn_id ON alerts(txn_id);

CREATE TABLE IF NOT EXISTS users(
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT CHECK(role IN ('admin','reviewer')) NOT NULL DEFAULT 'reviewer',
  must_change_password INTEGER DEFAULT 0,
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until TIMESTAMP,
  last_login TIMESTAMP,
  last_password_change TIMESTAMP,
  totp_enabled INTEGER DEFAULT 0,
  totp_verified INTEGER DEFAULT 0,
  totp_secret TEXT,
  backup_codes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log(
  id BIGSERIAL PRIMARY KEY,
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
  id BIGSERIAL PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS config_kv(
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_rationales(
  id BIGSERIAL PRIMARY KEY,
  customer_id TEXT NOT NULL,
  period_from TEXT,
  period_to TEXT,
  nature_of_business TEXT,
  est_income DOUBLE PRECISION,
  est_expenditure DOUBLE PRECISION,
  rationale_text TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(customer_id, period_from, period_to)
);

CREATE TABLE IF NOT EXISTS ai_cases(
  id BIGSERIAL PRIMARY KEY,
  customer_id TEXT NOT NULL,
  case_status TEXT DEFAULT 'open',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules(
  id BIGSERIAL PRIMARY KEY,
  category TEXT,
  rule TEXT,
  trigger_condition TEXT,
  score_impact TEXT,
  tags TEXT,
  outcome TEXT,
  description TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(category, rule)
);
"""

@app.teardown_appcontext
def close_db(exc):
    g.pop("db", None)
    db_raw = g.pop("db_raw", None)
    if db_raw is not None:
        try:
            if exc:
                db_raw.rollback()
            _get_pool().putconn(db_raw)
        except Exception:
            # Connection is broken; let pool discard it
            _get_pool().putconn(db_raw, close=True)

def exec_script(path):
    db = get_db()
    try:
        with open(path, "r") as f:
            script_sql = f.read()
            # Split by semicolon and execute each statement separately
            for statement in script_sql.split(';'):
                statement = statement.strip()
                if statement:
                    db.execute(statement)
    except FileNotFoundError:
        # Fallback to embedded schema
        for statement in SCHEMA_SQL.split(';'):
            statement = statement.strip()
            if statement:
                db.execute(statement)
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
          id BIGSERIAL PRIMARY KEY,
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
    try:
        user = db.execute("SELECT locked_until FROM users WHERE username=?", (username,)).fetchone()
    except psycopg2.Error as e:
        if "users" in str(e):
            init_db(); ensure_users_table()
            user = db.execute("SELECT locked_until FROM users WHERE username=?", (username,)).fetchone()
        else:
            raise
    
    if user and user["locked_until"]:
        # PostgreSQL returns TIMESTAMP as datetime object, not string
        locked_until = user["locked_until"] if isinstance(user["locked_until"], datetime) else datetime.fromisoformat(user["locked_until"])
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
    try:
        user = db.execute("SELECT id, failed_login_attempts FROM users WHERE username=?", (username,)).fetchone()
    except psycopg2.Error as e:
        if "users" in str(e):
            init_db(); ensure_users_table()
            user = db.execute("SELECT id, failed_login_attempts FROM users WHERE username=?", (username,)).fetchone()
        else:
            raise
    
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
    try:
        db.execute("UPDATE users SET failed_login_attempts=0, locked_until=NULL, last_login=? WHERE username=?",
                   (datetime.now().isoformat(), username))
        db.commit()
    except psycopg2.Error as e:
        if "users" in str(e):
            init_db(); ensure_users_table()
            db.execute("UPDATE users SET failed_login_attempts=0, locked_until=NULL, last_login=? WHERE username=?",
                       (datetime.now().isoformat(), username))
            db.commit()
        else:
            raise


# ---------- Authentication helpers ----------
def _column_exists(table_name, column_name):
    """Check if a column exists in a PostgreSQL table."""
    db = get_db()
    cur = db.execute("""
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = %s AND column_name = %s
    """, (table_name, column_name))
    return cur.fetchone() is not None

def ensure_users_table():
    """Create users table and seed default admin if needed."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users(
          id BIGSERIAL PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          email TEXT,
          password_hash TEXT NOT NULL,
          role TEXT CHECK(role IN ('admin','reviewer','bau_manager','remediation_manager')) NOT NULL DEFAULT 'reviewer',
          must_change_password INTEGER DEFAULT 0,
          failed_login_attempts INTEGER DEFAULT 0,
          locked_until TIMESTAMP,
          last_login TIMESTAMP,
          last_password_change TIMESTAMP,
          totp_secret TEXT,
          totp_enabled INTEGER DEFAULT 0,
          backup_codes TEXT,
          totp_verified INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()
    
    # Add 2FA columns if they don't exist
    if not _column_exists('users', 'totp_secret'):
        try:
            db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT;")
        except Exception:
            pass
    if not _column_exists('users', 'totp_enabled'):
        try:
            db.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;")
        except Exception:
            pass
    if not _column_exists('users', 'backup_codes'):
        try:
            db.execute("ALTER TABLE users ADD COLUMN backup_codes TEXT;")
        except Exception:
            pass
    if not _column_exists('users', 'totp_verified'):
        try:
            db.execute("ALTER TABLE users ADD COLUMN totp_verified INTEGER DEFAULT 0;")
        except Exception:
            pass
    if not _column_exists('users', 'user_type'):
        try:
            db.execute("ALTER TABLE users ADD COLUMN user_type TEXT DEFAULT 'BAU';")
        except Exception:
            pass
    db.commit()
    
    # Seed default admin if no users exist (with must_change_password flag)
    cur = db.execute("SELECT COUNT(*) c FROM users")
    if cur.fetchone()["c"] == 0:
        db.execute(
            "INSERT INTO users(username, password_hash, role, must_change_password) VALUES(%s, %s, %s, %s)",
            ("admin", generate_password_hash("Admin@12345"), "admin", 1)
        )
        db.commit()

def ensure_password_reset_tokens():
    """Create password_reset_tokens table for self-service password recovery."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens(
            id BIGSERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()

def ensure_manager_roles():
    """Migrate role CHECK constraint to include manager roles for existing databases."""
    db = get_db()
    try:
        db.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check")
        db.execute("""
            ALTER TABLE users ADD CONSTRAINT users_role_check
            CHECK (role IN ('admin','reviewer','bau_manager','remediation_manager'))
        """)
        db.commit()
    except Exception:
        db.rollback()

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
          id BIGSERIAL PRIMARY KEY,
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
    # Add account_name to statements if not exists
    if not _column_exists('statements', 'account_name'):
        try:
            db.execute("ALTER TABLE statements ADD COLUMN account_name TEXT;")
            db.commit()
        except Exception:
            pass
    # Add statement_id to transactions if not exists
    if not _column_exists('transactions', 'statement_id'):
        try:
            db.execute("ALTER TABLE transactions ADD COLUMN statement_id INTEGER;")
            db.commit()
        except Exception:
            pass
    # Add account_name to transactions if not exists
    if not _column_exists('transactions', 'account_name'):
        try:
            db.execute("ALTER TABLE transactions ADD COLUMN account_name TEXT;")
            db.commit()
        except Exception:
            db.rollback()
    # Indexes for account filtering and scoring performance
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_tx_account_name ON transactions(customer_id, account_name);",
        "CREATE INDEX IF NOT EXISTS idx_tx_customer_dir_date ON transactions(customer_id, direction, txn_date);",
        "CREATE INDEX IF NOT EXISTS idx_tx_base_amount ON transactions(customer_id, base_amount);",
    ]:
        try:
            db.execute(idx_sql)
            db.commit()
        except Exception:
            db.rollback()
    # Backfill account_name from statements for previously uploaded transactions
    try:
        db.execute("""
            UPDATE transactions
            SET account_name = s.account_name
            FROM statements s
            WHERE transactions.statement_id = s.id
              AND transactions.account_name IS NULL
              AND s.account_name IS NOT NULL
        """)
        db.commit()
    except Exception:
        db.rollback()
    # Add CBS-schema columns to transactions if not exists
    for cbs_col in ['transaction_type', 'instrument', 'originating_customer',
                     'originating_bank', 'beneficiary_customer', 'beneficiary_bank',
                     'posting_date', 'counterparty_account_no', 'counterparty_bank_code']:
        if not _column_exists('transactions', cbs_col):
            col_type = "DATE" if cbs_col == "posting_date" else "TEXT"
            try:
                db.execute(f"ALTER TABLE transactions ADD COLUMN {cbs_col} {col_type};")
                db.commit()
            except Exception:
                pass
    # Create ref_bank_country table if not exists
    db.execute("""
        CREATE TABLE IF NOT EXISTS ref_bank_country(
          bank_name_pattern TEXT PRIMARY KEY,
          country_iso2 TEXT NOT NULL,
          country_name TEXT,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()

def ensure_scoring_jobs_table():
    """Create scoring_jobs table for cross-worker scoring status tracking."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS scoring_jobs(
            id BIGSERIAL PRIMARY KEY,
            customer_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'scoring',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            message TEXT
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_scoring_jobs_cust ON scoring_jobs(customer_id, updated_at DESC)")
    db.commit()

def ensure_customer_summaries_table():
    """Create customer_summaries table for materialised dashboard metrics."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS customer_summaries(
            customer_id TEXT PRIMARY KEY,
            total_tx INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0,
            critical_alerts INTEGER DEFAULT 0,
            total_in DOUBLE PRECISION DEFAULT 0,
            total_out DOUBLE PRECISION DEFAULT 0,
            cash_in DOUBLE PRECISION DEFAULT 0,
            cash_out DOUBLE PRECISION DEFAULT 0,
            high_risk_count INTEGER DEFAULT 0,
            high_risk_total DOUBLE PRECISION DEFAULT 0,
            avg_cash_in DOUBLE PRECISION,
            avg_cash_out DOUBLE PRECISION,
            avg_in DOUBLE PRECISION,
            avg_out DOUBLE PRECISION,
            max_in DOUBLE PRECISION,
            max_out DOUBLE PRECISION,
            overseas_in DOUBLE PRECISION DEFAULT 0,
            overseas_out DOUBLE PRECISION DEFAULT 0,
            total_value DOUBLE PRECISION DEFAULT 0,
            high_risk_value DOUBLE PRECISION DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()

def refresh_customer_summary(customer_id):
    """Recompute and upsert the materialised summary row for a customer."""
    db = get_db()

    row_a = db.execute("""
        SELECT
          COUNT(*) AS total_tx,
          SUM(CASE WHEN direction='in' THEN base_amount ELSE 0 END) AS total_in,
          SUM(CASE WHEN direction='out' THEN base_amount ELSE 0 END) AS total_out,
          SUM(CASE WHEN direction='in' AND lower(COALESCE(channel,''))='cash' THEN base_amount ELSE 0 END) AS cash_in,
          SUM(CASE WHEN direction='out' AND lower(COALESCE(channel,''))='cash' THEN base_amount ELSE 0 END) AS cash_out,
          AVG(CASE WHEN direction='in' AND lower(COALESCE(channel,''))='cash' THEN base_amount END) AS avg_cash_in,
          AVG(CASE WHEN direction='out' AND lower(COALESCE(channel,''))='cash' THEN base_amount END) AS avg_cash_out,
          AVG(CASE WHEN direction='in' THEN base_amount END) AS avg_in,
          AVG(CASE WHEN direction='out' THEN base_amount END) AS avg_out,
          MAX(CASE WHEN direction='in' THEN base_amount END) AS max_in,
          MAX(CASE WHEN direction='out' THEN base_amount END) AS max_out,
          SUM(CASE WHEN COALESCE(country_iso2,'')<>'' AND UPPER(country_iso2)<>'GB' AND direction='in' THEN base_amount ELSE 0 END) AS overseas_in,
          SUM(CASE WHEN COALESCE(country_iso2,'')<>'' AND UPPER(country_iso2)<>'GB' AND direction='out' THEN base_amount ELSE 0 END) AS overseas_out,
          SUM(base_amount) AS total_value
        FROM transactions WHERE customer_id = %s
    """, (customer_id,)).fetchone()

    row_b = db.execute("""
        SELECT COUNT(*) AS total_alerts,
               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical_alerts
        FROM alerts WHERE customer_id = %s
    """, (customer_id,)).fetchone()

    row_c = db.execute("""
        SELECT COUNT(*) AS high_risk_count, COALESCE(SUM(t.base_amount), 0) AS high_risk_total
        FROM transactions t
        JOIN ref_country_risk r ON r.iso2 = COALESCE(t.country_iso2, '')
        WHERE t.customer_id = %s AND r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
    """, (customer_id,)).fetchone()

    db.execute("""
        INSERT INTO customer_summaries(
            customer_id, total_tx, total_alerts, critical_alerts,
            total_in, total_out, cash_in, cash_out,
            high_risk_count, high_risk_total,
            avg_cash_in, avg_cash_out, avg_in, avg_out,
            max_in, max_out, overseas_in, overseas_out,
            total_value, high_risk_value, updated_at
        ) VALUES (
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, CURRENT_TIMESTAMP
        )
        ON CONFLICT(customer_id) DO UPDATE SET
            total_tx = EXCLUDED.total_tx,
            total_alerts = EXCLUDED.total_alerts,
            critical_alerts = EXCLUDED.critical_alerts,
            total_in = EXCLUDED.total_in,
            total_out = EXCLUDED.total_out,
            cash_in = EXCLUDED.cash_in,
            cash_out = EXCLUDED.cash_out,
            high_risk_count = EXCLUDED.high_risk_count,
            high_risk_total = EXCLUDED.high_risk_total,
            avg_cash_in = EXCLUDED.avg_cash_in,
            avg_cash_out = EXCLUDED.avg_cash_out,
            avg_in = EXCLUDED.avg_in,
            avg_out = EXCLUDED.avg_out,
            max_in = EXCLUDED.max_in,
            max_out = EXCLUDED.max_out,
            overseas_in = EXCLUDED.overseas_in,
            overseas_out = EXCLUDED.overseas_out,
            total_value = EXCLUDED.total_value,
            high_risk_value = EXCLUDED.high_risk_value,
            updated_at = CURRENT_TIMESTAMP
    """, (
        customer_id,
        int(row_a["total_tx"] or 0),
        int(row_b["total_alerts"] or 0),
        int(row_b["critical_alerts"] or 0),
        float(row_a["total_in"] or 0),
        float(row_a["total_out"] or 0),
        float(row_a["cash_in"] or 0),
        float(row_a["cash_out"] or 0),
        int(row_c["high_risk_count"] or 0),
        float(row_c["high_risk_total"] or 0),
        float(row_a["avg_cash_in"]) if row_a["avg_cash_in"] is not None else None,
        float(row_a["avg_cash_out"]) if row_a["avg_cash_out"] is not None else None,
        float(row_a["avg_in"]) if row_a["avg_in"] is not None else None,
        float(row_a["avg_out"]) if row_a["avg_out"] is not None else None,
        float(row_a["max_in"]) if row_a["max_in"] is not None else None,
        float(row_a["max_out"]) if row_a["max_out"] is not None else None,
        float(row_a["overseas_in"] or 0),
        float(row_a["overseas_out"] or 0),
        float(row_a["total_value"] or 0),
        float(row_c["high_risk_total"] or 0),
    ))
    db.commit()

def _get_accounts_for_customer(customer_id):
    """Return sorted list of distinct account_name values for a customer's transactions."""
    db = get_db()
    rows = db.execute("""
        SELECT DISTINCT account_name
        FROM transactions
        WHERE customer_id = ? AND account_name IS NOT NULL AND account_name != ''
        ORDER BY account_name
    """, (customer_id,)).fetchall()
    return [r["account_name"] for r in rows]

def get_current_user():
    """Return current user dict or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=%s", (user_id,)).fetchone()
    return dict(row) if row else None

def ensure_user_sessions_table():
    """Create user_sessions table for concurrent session prevention (AGRA-001-1-10)."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions(
            id BIGSERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            session_token TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id)")
    db.commit()

def login_required(f):
    """Decorator: require logged-in user and enforce 2FA if enabled globally."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Block pending-MFA users from accessing protected routes (AGRA-001-1-1)
        if session.get("pending_user_id") and not session.get("user_id"):
            flash("Please complete two-factor authentication first.")
            return redirect(url_for("login"))

        if not session.get("user_id"):
            flash("Please log in to continue.")
            return redirect(url_for("login", next=request.url))

        # Validate session token against DB (AGRA-001-1-10 concurrent session prevention)
        session_token = session.get("session_token")
        if session_token:
            try:
                ensure_user_sessions_table()
                db = get_db()
                active = db.execute(
                    "SELECT 1 FROM user_sessions WHERE user_id=%s AND session_token=%s",
                    (session["user_id"], session_token)
                ).fetchone()
                if not active:
                    session.clear()
                    flash("Your session has been ended because you logged in elsewhere.")
                    return redirect(url_for("login", next=request.url))
            except Exception:
                pass  # If table doesn't exist yet, allow through

        # Check if 2FA is enforced globally and user hasn't set it up
        if cfg_get('cfg_enforce_2fa', True, bool):
            # Skip check for 2FA setup pages to avoid redirect loop
            if request.endpoint not in ('setup_2fa', 'manage_2fa', 'change_password', 'logout', 'static'):
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
            return redirect(url_for("upload"))
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
          id BIGSERIAL PRIMARY KEY,
          customer_id TEXT NOT NULL,
          period_from TEXT,
          period_to TEXT,
          entity_type TEXT DEFAULT 'company',
          nature_of_business TEXT,
          est_income DOUBLE PRECISION,
          est_expenditure DOUBLE PRECISION,
          rationale_text TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(customer_id, period_from, period_to)
        );
    """)
    db.commit()
    _ensure_ai_rationale_columns()

def _load_rationale_row(customer_id: str, p_from: Optional[str], p_to: Optional[str]):
    db = get_db()
    return db.execute(
        "SELECT * FROM ai_rationales WHERE customer_id=? AND COALESCE(period_from,'')=COALESCE(?, '') AND COALESCE(period_to,'')=COALESCE(?, '')",
        (customer_id, p_from, p_to)
    ).fetchone()

def _ensure_ai_rationale_columns():
    db = get_db()
    if not _column_exists('ai_rationales', 'rationale_text'):
        try:
            db.execute("ALTER TABLE ai_rationales ADD COLUMN rationale_text TEXT;")
            db.commit()
        except Exception:
            db.rollback()
    if not _column_exists('ai_rationales', 'entity_type'):
        try:
            db.execute("ALTER TABLE ai_rationales ADD COLUMN entity_type TEXT DEFAULT 'company';")
            db.commit()
        except Exception:
            db.rollback()
    # Reviewer confirmation columns (AGRA pen test - audit trail for rationale sign-off)
    for col, typedef in [('reviewer_confirmed', 'BOOLEAN DEFAULT FALSE'),
                         ('reviewer_confirmed_by', 'TEXT'),
                         ('reviewer_confirmed_at', 'TIMESTAMP'),
                         ('reviewer_confirmed_type', 'TEXT')]:
        if not _column_exists('ai_rationales', col):
            try:
                db.execute(f"ALTER TABLE ai_rationales ADD COLUMN {col} {typedef};")
                db.commit()
            except Exception:
                db.rollback()

def _upsert_rationale_row(customer_id: str, p_from: Optional[str], p_to: Optional[str],
                          entity_type: Optional[str],
                          nature_of_business: Optional[str], est_income: Optional[float],
                          est_expenditure: Optional[float], rationale_text: str):
    """
    Insert or update a rationale row. Uses DELETE + INSERT pattern to handle NULL values
    correctly (PostgreSQL's ON CONFLICT doesn't work properly with NULLs in unique constraints).
    """
    db = get_db()

    db.execute("""
        DELETE FROM ai_rationales
        WHERE customer_id = ?
          AND COALESCE(period_from, '') = COALESCE(?, '')
          AND COALESCE(period_to, '') = COALESCE(?, '')
    """, (customer_id, p_from, p_to))

    db.execute("""
        INSERT INTO ai_rationales(customer_id, period_from, period_to, entity_type,
                                  nature_of_business, est_income, est_expenditure,
                                  rationale_text, updated_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (customer_id, p_from, p_to, entity_type or 'company',
          nature_of_business, est_income, est_expenditure, rationale_text))
    db.commit()

def _format_date_pretty(date_str) -> str:
    """YYYY-MM-DD -> '18th July 2025'."""
    if isinstance(date_str, (datetime, date)):
        dt = date_str
    else:
        dt = datetime.strptime(str(date_str), "%Y-%m-%d")
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
    if isinstance(date_str, (datetime, date)):
        dt = date_str
    else:
        dt = datetime.strptime(str(date_str), "%Y-%m-%d")
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
    Ask the LLM to select and rank questions from the approved question bank.
    The LLM may NOT invent new questions — only select from the bank and base_questions.
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

    # build numbered catalogue of all allowed questions
    bank = ai_question_bank()
    catalogue = []  # list of {"idx": int, "tag": str, "question": str}
    idx = 0
    # include base_questions first (already context-specific)
    for q in base_questions:
        catalogue.append({"idx": idx, "tag": q["tag"], "question": q["question"]})
        idx += 1
    # include bank questions for observed tags not already covered
    base_qs_lower = {q["question"].lower() for q in base_questions}
    for tag in sorted(set(fired_tags or [])):
        for q_text in bank.get(tag, []):
            if q_text.lower() not in base_qs_lower:
                catalogue.append({"idx": idx, "tag": tag, "question": q_text})
                idx += 1

    try:
        import google.generativeai as genai
        import time as _time
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model_name = model or str(cfg_get("cfg_ai_model", "gemini-2.0-flash"))

        lines = [
            f"Customer: {customer_id}",
            f"Alert tags observed: {', '.join(sorted(set(fired_tags or [])))}",
            "Example alerts (tag / sev / score / date / txn_id):"
        ]
        for r in source_alerts[:15]:
            lines.append(f"- {r['tag']} / {r['severity']} / {r['score']} / {r['txn_date']} / {r['txn_id']}")
        lines.append("\nApproved question catalogue (select from these ONLY):")
        for c in catalogue:
            lines.append(f"  {c['idx']}. [{c['tag']}] {c['question']}")

        prompt = "\n".join(lines) + f"""

Select the best {max_count} questions from the catalogue above for this customer's alerts.
You MUST only use questions exactly as written in the catalogue — do NOT invent or rephrase.
Rank them by relevance to the alerts observed.
Return STRICT JSON array, each item exactly:
{{"idx":<catalogue number>,"tag":"<tag>","question":"<exact question text from catalogue>","sources":["<txn_id>", "..."]}}
If you cannot determine per-question sources from context, use an empty array [].
"""

        gmodel = genai.GenerativeModel(
            model_name,
            system_instruction="You are a financial-crime analyst. Select questions from the provided catalogue only. Never invent new questions.",
        )

        # Acquire semaphore to limit concurrent LLM calls
        if not _llm_semaphore.acquire(timeout=30):
            raise TimeoutError("LLM concurrency limit reached")
        try:
            resp = None
            for _attempt in range(2):
                try:
                    resp = gmodel.generate_content(
                        prompt,
                        generation_config=genai.GenerationConfig(temperature=0.1),
                        request_options={"timeout": _LLM_TIMEOUT},
                    )
                    break
                except Exception as e:
                    if _attempt == 0 and "429" in str(e):
                        _time.sleep(2)
                        continue
                    raise
        finally:
            _llm_semaphore.release()

        raw = _strip_json_fences(resp.text.strip())
        data = json.loads(raw)

        # validate: only accept questions that match the catalogue
        catalogue_lookup = {c["idx"]: c for c in catalogue}
        catalogue_qs = {c["question"].lower() for c in catalogue}

        out, seen = [], set()
        for item in data:
            q = (item.get("question") or "").strip()
            tag = (item.get("tag") or "").strip()
            src = item.get("sources") or []
            if not q:
                continue
            # strict validation: reject any question not in our catalogue
            if q.lower() not in catalogue_qs:
                continue
            if not tag:
                tag = fired_tags[0] if fired_tags else "NLP_RISK"
            if not src and tag in per_tag_src:
                src = per_tag_src[tag][:5]
            key = (tag, q.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"tag": tag, "question": q, "sources": src})
            if len(out) >= max_count:
                break
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
    # Will use schema.sql if present; otherwise uses embedded SCHEMA_SQL
    exec_script(os.path.join(os.path.dirname(__file__), "schema.sql"))
    db = get_db()
    cur = db.execute("SELECT COUNT(*) c FROM config_versions")
    if cur.fetchone()["c"] == 0:
        db.execute("INSERT INTO config_versions(name) VALUES (?)", ("init",))
        db.commit()
    
    # Create default admin account on first startup
    cur = db.execute("SELECT COUNT(*) c FROM users WHERE username = ?", ("super.admin",))
    user_count = cur.fetchone()["c"]
    
    if user_count == 0:
        # Generate random password: 16 chars, mix of upper, lower, digits, special
        password_chars = string.ascii_letters + string.digits + "!@#$%^&*"
        admin_password = ''.join(secrets.choice(password_chars) for _ in range(16))
        password_hash = generate_password_hash(admin_password)
        
        db.execute(
            "INSERT INTO users (username, password_hash, role, totp_enabled) VALUES (?, ?, ?, ?)",
            ("super.admin", password_hash, "admin", 0)
        )
        db.commit()
        
        # Log credentials (only on first startup)
        msg = f"\n{'='*70}\n🔐 DEFAULT ADMIN ACCOUNT CREATED\n{'='*70}\nUsername: super.admin\nPassword: {admin_password}\n{'='*70}\n⚠️  IMPORTANT: Change this password immediately after first login!\n{'='*70}\n"
        print(msg, flush=True)
        import sys
        sys.stderr.write(msg)
        sys.stderr.flush()
    # Ensure background scoring and summary tables exist
    ensure_scoring_jobs_table()
    ensure_customer_summaries_table()

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

def _strip_json_fences(text):
    """Strip markdown code fences from LLM response (Gemini often wraps JSON)."""
    s = text.strip()
    if s.startswith("```json"):
        s = s[7:]
    elif s.startswith("```"):
        s = s[3:]
    if s.endswith("```"):
        s = s[:-3]
    return s.strip()

# Limit concurrent LLM calls to avoid API rate exhaustion
_llm_semaphore = __import__('threading').Semaphore(10)
_LLM_TIMEOUT = 20  # seconds

def llm_enabled():
    # Toggle + API key present
    return bool(os.getenv("GEMINI_API_KEY")) and bool(cfg_get("cfg_ai_use_llm", False))

def ai_suggest_questions_llm(customer_id, fired_tags, sample_alerts, base_questions, model=None):
    """Select up to 3 additional questions from the approved bank via Gemini. Fails closed (returns [])."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model_name = model or str(cfg_get("cfg_ai_model", "gemini-2.0-flash"))

        # build catalogue of bank questions NOT already in base_questions
        bank = ai_question_bank()
        base_qs_lower = {q["question"].lower() for q in base_questions}
        catalogue = []
        idx = 0
        for tag in sorted(set(fired_tags or [])):
            for q_text in bank.get(tag, []):
                if q_text.lower() not in base_qs_lower:
                    catalogue.append({"idx": idx, "tag": tag, "question": q_text})
                    idx += 1
        # also include questions for related tags not in fired_tags
        for tag, qs in bank.items():
            if tag not in (fired_tags or []):
                for q_text in qs:
                    if q_text.lower() not in base_qs_lower:
                        catalogue.append({"idx": idx, "tag": tag, "question": q_text})
                        idx += 1

        if not catalogue:
            return []

        # Compact context
        lines = [f"Customer: {customer_id}", "Alert tags (severity/score/date):"]
        for r in (sample_alerts or [])[:10]:
            lines.append(f"- {r['tag']} / {r['severity']} / {r['score']} / {r['txn_date']}")
        lines.append("Base questions already selected:")
        for q in base_questions:
            lines.append(f"- [{q['tag']}] {q['question']}")
        lines.append("\nAdditional approved questions (select from these ONLY):")
        for c in catalogue:
            lines.append(f"  {c['idx']}. [{c['tag']}] {c['question']}")

        prompt = "\n".join(lines) + """

Select up to 3 additional questions from the catalogue above that would help clarify the customer's risk.
You MUST only use questions exactly as written — do NOT invent or rephrase.
Return pure JSON array: [{"idx":<number>,"tag":"<tag>","question":"<exact text>"}].
If none are relevant, return an empty array [].
"""

        gmodel = genai.GenerativeModel(
            model_name,
            system_instruction="You are a compliance analyst following AML/FCA best practice. Select questions from the provided catalogue only. Never invent new questions.",
        )

        # Acquire semaphore to limit concurrent LLM calls
        if not _llm_semaphore.acquire(timeout=30):
            raise TimeoutError("LLM concurrency limit reached")
        try:
            resp = None
            for _attempt in range(2):
                try:
                    resp = gmodel.generate_content(
                        prompt,
                        generation_config=genai.GenerationConfig(temperature=0.1),
                        request_options={"timeout": _LLM_TIMEOUT},
                    )
                    break
                except Exception as e:
                    if _attempt == 0 and "429" in str(e):
                        import time as _time
                        _time.sleep(2)
                        continue
                    raise
        finally:
            _llm_semaphore.release()

        txt = _strip_json_fences(resp.text.strip())
        extras = json.loads(txt)

        # validate: only accept questions that match the catalogue
        catalogue_qs = {c["question"].lower() for c in catalogue}
        out = []
        for e in extras:
            tag = (e.get("tag") or "").strip() or (fired_tags[0] if fired_tags else "NLP_RISK")
            q = (e.get("question") or "").strip()
            if q and q.lower() in catalogue_qs:
                out.append({"tag": tag, "question": q})
        return out[:3]
    except Exception:
        return []

def _default_question_bank():
    """Built-in default question bank. One or more questions per tag; simple, non-leading, regulator-friendly."""
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
            "Your monthly account outgoings exceed your average. What is the reason for the increase?",
            "Do we need to update your expected monthly outgoings moving forwards?"
        ],
        "EXPECTED_BREACH_IN": [
            "Your monthly account incomings exceed your average. What is the reason for the increase?",
            "Do we need to update your expected monthly incomings moving forwards?"
        ],
        "STRUCTURING": [
            "We have noticed a pattern of transactions of similar amounts on your account. Please can you tell us what these payments were for?",
        ],
        "FLOW_THROUGH": [
            "We have identified funds received and sent on within a short period. Please explain the purpose of these transactions and the nature of the relationship with the parties involved.",
        ],
        "HIGH_VELOCITY": [
            "A high number of transactions have been processed in a short period. Please explain the nature of this activity.",
        ],
        "DORMANCY_REACTIVATION": [
            "This account was dormant for an extended period before recent activity resumed. Please explain the reason for the renewed activity.",
        ],
    }

def ai_question_bank():
    """Return question bank, loading from DB config if available, falling back to defaults."""
    raw = cfg_get("tpl_question_bank", None)
    if raw:
        try:
            bank = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(bank, dict) and bank:
                return bank
        except (json.JSONDecodeError, TypeError):
            pass
    return _default_question_bank()

def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get((sev or "").upper(), 0)

def build_ai_questions(customer_id, dfrom=None, dto=None):
    """
    Returns:
      base_questions: [{"tag","question","sources":[txn_ids...]}]  (ONE per tag, covering ALL alerts)
      fired_tags: list[str] in importance order
      preview_alerts: compact list of all alerts for prompt
    """
    tagged = fetch_customer_alerts_with_tags(customer_id, dfrom, dto)
    if not tagged:
        return [], [], []

    from collections import defaultdict
    per_tag = defaultdict(list)
    for r in tagged:
        per_tag[r["tag"]].append(r)

    # order tags by worst severity → highest score → tag specificity → recency
    sev_rank = {"CRITICAL":1,"HIGH":2,"MEDIUM":3,"LOW":4,"INFO":5}
    tag_priority = {
        "PROHIBITED_COUNTRY": 1, "HIGH_RISK_COUNTRY": 2,
        "STRUCTURING": 3, "FLOW_THROUGH": 4,
        "DORMANCY_REACTIVATION": 5, "HIGH_VELOCITY": 6,
        "CASH_DAILY_BREACH": 7, "NLP_RISK": 8,
        "HISTORICAL_DEVIATION": 9,
        "EXPECTED_BREACH_IN": 10, "EXPECTED_BREACH_OUT": 10,
    }
    fired = sorted(
        per_tag.keys(),
        key=lambda tg: (
            min(sev_rank.get(x["severity"], 5) for x in per_tag[tg]),
            -max(x["score"] or 0 for x in per_tag[tg]),
            tag_priority.get(tg, 50),
            max(x["txn_date"] for x in per_tag[tg]),
        )
    )

    qbank = ai_question_bank()
    base = []

    # --- ONE question per tag; cap source alerts per tag ---
    max_per_tag = 5
    for tg in fired:
        qs = qbank.get(tg, [])
        if not qs:
            continue
        tag_txn_ids = [x["txn_id"] for x in per_tag[tg][:max_per_tag]]
        if not tag_txn_ids:
            continue
        q_text = qs[0].strip()
        base.append({
            "tag": tg,
            "question": q_text,
            "sources": tag_txn_ids
        })

    # compact alerts for prompt context
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
    """Return list of dict rules from PostgreSQL 'rules' table (if present)."""
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, category, rule, trigger_condition, score_impact, tags, outcome, description "
            "FROM rules ORDER BY category, rule"
        ).fetchall()
    except psycopg2.Error:
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
            "description": "Flag unusually large transactions compared to customer's typical behaviour.",
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
            "category": "Behavioural Deviation",
            "rule": "Outflows > Historical Average",
            "trigger_condition": "month_out_total > historical_avg_monthly_out × factor (min 3 months history)",
            "score_impact": "20",
            "tags": "EXPECTED_BREACH_OUT",
            "outcome": "Escalate",
            "description": "Monthly outflows exceed the customer's own historical average.",
        },
        {
            "category": "Behavioural Deviation",
            "rule": "Inflows > Historical Average",
            "trigger_condition": "month_in_total > historical_avg_monthly_in × factor (min 3 months history)",
            "score_impact": "15",
            "tags": "EXPECTED_BREACH_IN",
            "outcome": "Review",
            "description": "Monthly inflows exceed the customer's own historical average.",
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
        # We'll use 1899-12-30 which matches most CSV exports.
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
    fname = getattr(fobj, 'filename', '') or ''
    ext = os.path.splitext(fname)[1].lower()
    if ext in ('.xlsx', '.xls'):
        df = pd.read_excel(fobj, engine='openpyxl' if ext == '.xlsx' else None)
    else:
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
        # Drop rows with unparseable txn_date; we'll report how many were skipped
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
            """INSERT INTO transactions
               (id, txn_date, customer_id, direction, amount, currency, base_amount, country_iso2,
                payer_sort_code, payee_sort_code, channel, narrative)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 txn_date=EXCLUDED.txn_date, customer_id=EXCLUDED.customer_id,
                 direction=EXCLUDED.direction, amount=EXCLUDED.amount,
                 currency=EXCLUDED.currency, base_amount=EXCLUDED.base_amount,
                 country_iso2=EXCLUDED.country_iso2, payer_sort_code=EXCLUDED.payer_sort_code,
                 payee_sort_code=EXCLUDED.payee_sort_code, channel=EXCLUDED.channel,
                 narrative=EXCLUDED.narrative""",
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

    # Return count; the UI already flashes "Loaded N transactions"
    # If you want to surface skipped rows, you can also flash here, but
    # we'll just print to console to avoid changing routes:
    if bad_dates:
        print(f"[ingest_transactions_csv] Skipped {bad_dates} row(s) with invalid txn_date.")

    return n_inserted

def _parse_cbs_amount(val):
    """Parse CBS-format amount string like "' -GBP 2,534.59" into (currency, amount).
    Returns (currency_code: str, abs_amount: float). Amount is always positive.
    """
    if val is None:
        return ("GBP", 0.0)
    s = str(val).strip()
    if not s or s.lower() in ("nan", "none", "null"):
        return ("GBP", 0.0)
    s = s.lstrip("'").strip()
    if s.startswith('+'):
        s = s[1:].strip()
    elif s.startswith('-'):
        s = s[1:].strip()
    parts = s.split(None, 1)
    if len(parts) == 2:
        currency = parts[0].upper()
        num_str = parts[1]
    elif len(parts) == 1:
        currency = "GBP"
        num_str = parts[0]
    else:
        return ("GBP", 0.0)
    num_str = num_str.replace(",", "").strip()
    try:
        amount = abs(float(num_str))
    except ValueError:
        amount = 0.0
    return (currency, amount)


def lookup_bank_country(bank_name):
    """Look up country_iso2 from ref_bank_country table by bank name (case-insensitive)."""
    if not bank_name:
        return None
    db = get_db()
    row = db.execute(
        "SELECT country_iso2 FROM ref_bank_country WHERE UPPER(bank_name_pattern) = UPPER(?)",
        (str(bank_name).strip(),)
    ).fetchone()
    return row["country_iso2"] if row else None


def ingest_transactions_csv_for_customer(fobj, expected_customer_id, statement_id=None, account_name=None):
    """
    Ingest transactions for a specific customer only.
    Auto-detects CBS vs standard CSV format based on column headers.
    Streams rows to keep memory flat regardless of file size.
    Returns (n_inserted, date_from, date_to).
    """
    from datetime import datetime, timedelta, date as date_type
    import dateutil.parser as _dtparser

    BATCH_SIZE = 500

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

    # Formats with time component first, then date-only formats
    COMMON_FORMATS = [
        "%d/%m/%Y, %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M",
        "%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y",
        "%d-%m-%Y", "%Y/%m/%d",
    ]

    def _coerce_date(val):
        """Coerce a value to a datetime. Preserves time when present; defaults to midnight (00:00:00) when only a date is provided."""
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        if isinstance(val, date_type):
            return datetime(val.year, val.month, val.day)
        s = str(val).strip()
        if s == "" or s.lower() in ("nan", "none", "null"):
            return None
        try:
            if isinstance(val, (int, float)) or s.replace(".", "", 1).isdigit():
                d = _excel_serial_to_date(val)
                if d:
                    return datetime(d.year, d.month, d.day)
        except Exception:
            pass
        for fmt in COMMON_FORMATS:
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                pass
        try:
            d = _dtparser.parse(s, dayfirst=True)
            return d if isinstance(d, datetime) else datetime(d.year, d.month, d.day)
        except Exception:
            pass
        return None

    def _clean_text(val):
        """Clean CBS text fields: strip leading apostrophe, normalize nulls."""
        if val is None:
            return None
        s = str(val).strip()
        if s.lower() in ("", "nan", "none", "null"):
            return None
        s = s.lstrip("'").strip()
        return s if s else None

    def _safe_float(val, default=0.0):
        if val is None:
            return default
        try:
            f = float(val)
            return f if f == f else default  # NaN check
        except (ValueError, TypeError):
            return default

    def _norm_null(val):
        """Normalize a cell value: strip whitespace, convert null-ish strings to None."""
        if val is None:
            return None
        s = str(val).strip()
        if s.lower() in ("", "nan", "none", "null"):
            return None
        return s

    # --- open file & read headers (streaming) --------------------------------
    fname = getattr(fobj, 'filename', '') or getattr(fobj, 'name', '') or ''
    ext = os.path.splitext(fname)[1].lower()

    CBS_SIGNATURE = {"Transaction ID", "Transaction Date", "Debit/Credit", "Base Amount"}
    DIRECTION_MAP = {"debit": "out", "credit": "in"}

    INSERT_SQL = """INSERT INTO transactions
       (id, txn_date, customer_id, direction, amount, currency, base_amount,
        country_iso2, payer_sort_code, payee_sort_code, channel, narrative,
        transaction_type, instrument, originating_customer, originating_bank,
        beneficiary_customer, beneficiary_bank, posting_date,
        counterparty_account_no, counterparty_bank_code, statement_id, account_name)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET
         txn_date=EXCLUDED.txn_date, customer_id=EXCLUDED.customer_id,
         direction=EXCLUDED.direction, amount=EXCLUDED.amount,
         currency=EXCLUDED.currency, base_amount=EXCLUDED.base_amount,
         country_iso2=EXCLUDED.country_iso2, payer_sort_code=EXCLUDED.payer_sort_code,
         payee_sort_code=EXCLUDED.payee_sort_code, channel=EXCLUDED.channel,
         narrative=EXCLUDED.narrative, transaction_type=EXCLUDED.transaction_type,
         instrument=EXCLUDED.instrument, originating_customer=EXCLUDED.originating_customer,
         originating_bank=EXCLUDED.originating_bank, beneficiary_customer=EXCLUDED.beneficiary_customer,
         beneficiary_bank=EXCLUDED.beneficiary_bank, posting_date=EXCLUDED.posting_date,
         counterparty_account_no=EXCLUDED.counterparty_account_no,
         counterparty_bank_code=EXCLUDED.counterparty_bank_code,
         statement_id=EXCLUDED.statement_id,
         account_name=EXCLUDED.account_name"""

    # --- build row iterator + detect format ----------------------------------
    if ext in ('.xlsx', '.xls'):
        import openpyxl
        wb = openpyxl.load_workbook(fobj, read_only=True, data_only=True)
        ws = wb.active
        row_iter = ws.iter_rows(values_only=True)
        try:
            headers = [str(c) if c is not None else "" for c in next(row_iter)]
        except StopIteration:
            wb.close()
            raise ValueError("Empty file — no header row found.")
        cols = set(headers)

        def _rows():
            for values in row_iter:
                yield dict(zip(headers, values))
            wb.close()
    else:
        # CSV — wrap binary handle in text mode if needed
        if hasattr(fobj, 'mode') and 'b' in getattr(fobj, 'mode', ''):
            import io as _io
            text_fobj = _io.TextIOWrapper(fobj, encoding='utf-8-sig', errors='replace')
        else:
            text_fobj = fobj
        reader = csv.DictReader(text_fobj)
        if reader.fieldnames is None:
            raise ValueError("Empty file — no header row found.")
        cols = set(reader.fieldnames)

        def _rows():
            yield from reader

    is_cbs = CBS_SIGNATURE.issubset(cols)

    # Validate standard format columns up front
    if not is_cbs:
        needed = {"id", "txn_date", "direction", "amount", "base_amount"}
        missing = needed - cols
        if missing:
            raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")

    # --- load bank→country map -----------------------------------------------
    db = get_db()
    bank_rows = db.execute("SELECT bank_name_pattern, country_iso2 FROM ref_bank_country").fetchall()
    bank_map = {r["bank_name_pattern"].upper(): r["country_iso2"] for r in bank_rows if r["bank_name_pattern"]}

    # --- stream rows, transform, batch-insert --------------------------------
    batch = []
    n_inserted = 0
    bad_dates = 0
    date_min = None
    date_max = None

    for raw in _rows():
        # --- Transform row into canonical fields ---
        if is_cbs:
            txn_id = str(raw.get("Transaction ID", "")).strip()
            txn_date = _coerce_date(raw.get("Transaction Date"))
            direction_raw = str(raw.get("Debit/Credit", "")).strip().lower()
            direction = DIRECTION_MAP.get(direction_raw)
            if not direction:
                continue  # skip rows without valid direction

            currency, amount = _parse_cbs_amount(raw.get("Base Amount"))
            base_amount = amount

            transaction_type = _clean_text(raw.get("Transaction Type")) if "Transaction Type" in cols else None
            channel_val = _norm_null(raw.get("Transaction Channel"))
            channel = channel_val.lower() if channel_val else None
            instrument = _clean_text(raw.get("Instrument")) if "Instrument" in cols else None
            originating_customer = _clean_text(raw.get("Originating Customer")) if "Originating Customer" in cols else None
            originating_bank = _clean_text(raw.get("Originating Bank")) if "Originating Bank" in cols else None
            beneficiary_customer = _clean_text(raw.get("Beneficiary Customer")) if "Beneficiary Customer" in cols else None
            beneficiary_bank = _clean_text(raw.get("Beneficiary Bank")) if "Beneficiary Bank" in cols else None
            narrative = _clean_text(raw.get("Description")) if "Description" in cols else None
            posting_date = _coerce_date(raw.get("Posting Date")) if "Posting Date" in cols else None
            counterparty_account_no = _norm_null(raw.get("Counterparty Account No")) if "Counterparty Account No" in cols else None
            counterparty_bank_code = _norm_null(raw.get("Counterparty Bank Code")) if "Counterparty Bank Code" in cols else None

            # Infer country from bank name
            country_iso2 = None
            if direction == "in" and originating_bank:
                country_iso2 = bank_map.get(originating_bank.upper())
            elif direction == "out" and beneficiary_bank:
                country_iso2 = bank_map.get(beneficiary_bank.upper())

            payer_sort_code = None
            payee_sort_code = None
        else:
            # --- Standard format ---
            txn_id = str(raw.get("id", "")).strip()
            txn_date = _coerce_date(raw.get("txn_date"))
            direction = str(raw.get("direction", "")).strip().lower()
            if direction not in ("in", "out"):
                continue

            amount = _safe_float(raw.get("amount"))
            base_amount = _safe_float(raw.get("base_amount"))
            if amount == 0.0 and base_amount != 0.0:
                amount = base_amount
            elif base_amount == 0.0 and amount != 0.0:
                base_amount = amount

            currency_val = _norm_null(raw.get("currency"))
            currency = currency_val.strip() if currency_val else "GBP"

            country_raw = _norm_null(raw.get("country_iso2"))
            country_iso2 = country_raw.upper() if country_raw else None
            payer_sort_code = _norm_null(raw.get("payer_sort_code"))
            payee_sort_code = _norm_null(raw.get("payee_sort_code"))
            channel_val = _norm_null(raw.get("channel"))
            channel = channel_val.lower() if channel_val else None
            narrative = _norm_null(raw.get("narrative"))

            transaction_type = None
            instrument = None
            originating_customer = None
            originating_bank = None
            beneficiary_customer = None
            beneficiary_bank = None
            posting_date = None
            counterparty_account_no = None
            counterparty_bank_code = None

        # --- Common: validate date ---
        if txn_date is None:
            bad_dates += 1
            continue

        # Track date range
        if date_min is None or txn_date < date_min:
            date_min = txn_date
        if date_max is None or txn_date > date_max:
            date_max = txn_date

        # Build tuple for INSERT
        batch.append((
            txn_id,
            str(txn_date),
            expected_customer_id,
            direction,
            float(amount),
            currency,
            float(base_amount),
            country_iso2,
            payer_sort_code,
            payee_sort_code,
            channel,
            narrative,
            transaction_type,
            instrument,
            originating_customer,
            originating_bank,
            beneficiary_customer,
            beneficiary_bank,
            str(posting_date) if posting_date else None,
            counterparty_account_no,
            counterparty_bank_code,
            statement_id,
            account_name or None,
        ))

        # Flush batch
        if len(batch) >= BATCH_SIZE:
            db.executemany(INSERT_SQL, batch)
            n_inserted += len(batch)
            batch.clear()

    # Flush remaining rows
    if batch:
        db.executemany(INSERT_SQL, batch)
        n_inserted += len(batch)
        batch.clear()

    if n_inserted == 0:
        raise ValueError("No valid transactions found in the file.")

    db.commit()

    date_from = str(date_min) if date_min else None
    date_to = str(date_max) if date_max else None

    if bad_dates:
        print(f"[ingest_transactions_csv_for_customer] Skipped {bad_dates} row(s) with invalid txn_date.")

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
            "description": "Flag unusually large transactions compared to customer's typical behaviour.",
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
            "category": "Behavioural Deviation",
            "rule": "Outflows > Historical Average",
            "trigger": "month_out_total > (cfg_expected_out_factor × historical_avg_monthly_out)",
            "impact": "+20",
            "tags": "EXPECTED_BREACH_OUT",
            "outcome": "Escalate",
            "description": "Monthly outflows exceed the customer's own historical average.",
            "params": [
                {"key":"cfg_expected_out_factor","label":"Multiplier","suffix":"×"},
                {"key":"cfg_expected_min_months","label":"Min months history","suffix":""},
            ],
            "requires": "At least 3 months of prior transaction history (configurable)",
        },
        {
            "key": "expected_in",
            "category": "Behavioural Deviation",
            "rule": "Inflows > Historical Average",
            "trigger": "month_in_total > (cfg_expected_in_factor × historical_avg_monthly_in)",
            "impact": "+15",
            "tags": "EXPECTED_BREACH_IN",
            "outcome": "Review",
            "description": "Monthly inflows exceed the customer's own historical average.",
            "params": [
                {"key":"cfg_expected_in_factor","label":"Multiplier","suffix":"×"},
                {"key":"cfg_expected_min_months","label":"Min months history","suffix":""},
            ],
            "requires": "At least 3 months of prior transaction history (configurable)",
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
          id BIGSERIAL PRIMARY KEY,
          customer_id TEXT NOT NULL,
          period_from TEXT,
          period_to TEXT,
          assessment_risk TEXT,
          assessment_score INTEGER,
          assessment_summary TEXT,
          rationale_text TEXT,
          rationale_generated_at TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS ai_answers (
          id BIGSERIAL PRIMARY KEY,
          case_id BIGINT NOT NULL,
          tag TEXT,
          question TEXT NOT NULL,
          answer TEXT,
          sources TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(case_id) REFERENCES ai_cases(id) ON DELETE CASCADE
        );
    """)
    # Add columns idempotently
    if not _column_exists('ai_answers', 'sources'):
        try:
            db.execute("ALTER TABLE ai_answers ADD COLUMN sources TEXT;")
        except Exception:
            pass
    for col_name, col_type in [
        ('period_from', 'TEXT'),
        ('period_to', 'TEXT'),
        ('assessment_risk', 'TEXT'),
        ('assessment_score', 'INTEGER'),
        ('assessment_summary', 'TEXT'),
    ]:
        if not _column_exists('ai_cases', col_name):
            try:
                db.execute(f"ALTER TABLE ai_cases ADD COLUMN {col_name} {col_type};")
            except Exception:
                pass
    if not _column_exists('ai_cases', 'rationale_text'):
        try:
            db.execute("ALTER TABLE ai_cases ADD COLUMN rationale_text TEXT;")
        except Exception:
            pass
    if not _column_exists('ai_cases', 'rationale_generated_at'):
        try:
            db.execute("ALTER TABLE ai_cases ADD COLUMN rationale_generated_at TEXT;")
        except Exception:
            pass
    # "Not Required" support on ai_answers
    if not _column_exists('ai_answers', 'not_required'):
        try:
            db.execute("ALTER TABLE ai_answers ADD COLUMN not_required BOOLEAN DEFAULT FALSE;")
        except Exception:
            pass
    if not _column_exists('ai_answers', 'not_required_rationale'):
        try:
            db.execute("ALTER TABLE ai_answers ADD COLUMN not_required_rationale TEXT;")
        except Exception:
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
        "cfg_expected_min_months": 3,        # min months of history before expected breach rules fire
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
        "cfg_ai_model": "gemini-2.0-flash",

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

# Common single-word banking terms that cause false positives with substring matching.
# These are auto-disabled when importing keyword libraries in bulk.
COMMON_BANKING_WORDS = {
    "account", "acre", "advance", "agent", "aggregate", "agriculture", "aid",
    "allocation", "allowance", "amendment", "amount", "annuity", "app",
    "application", "appraisal", "approved", "apr", "arrangement", "arrears",
    "asset", "balance", "bank", "base", "bill", "bond", "branch", "card",
    "case", "change", "charge", "check", "claim", "class", "close", "code",
    "coin", "compound", "cost", "credit", "current", "deal", "debt", "deed",
    "demand", "draft", "draw", "due", "duty", "earn", "entry", "equity",
    "exchange", "face", "fee", "file", "fine", "firm", "fix", "flat", "flow",
    "form", "foundation", "free", "fund", "futures", "gain", "give", "gold",
    "good", "grant", "gross", "group", "growth", "guide", "hold", "house",
    "immutable", "income", "index", "interest", "issue", "item", "joint",
    "lead", "lease", "ledger", "lend", "leverage", "levy", "limit", "line",
    "link", "list", "loan", "long", "loss", "lot", "margin", "mark",
    "market", "match", "model", "money", "mortgage", "move", "name", "near",
    "net", "note", "offer", "one", "open", "option", "order", "output",
    "owe", "paid", "part", "pass", "pay", "plan", "point", "pool", "port",
    "post", "pound", "price", "prime", "profit", "rate", "real", "record",
    "rent", "report", "reserve", "return", "risk", "roll", "rule", "run",
    "safe", "sale", "save", "share", "short", "sign", "source", "stake",
    "stock", "store", "sum", "supply", "swap", "take", "tax", "term",
    "time", "title", "token", "total", "trade", "trust", "turn", "unit",
    "use", "value", "volume", "wage", "wire", "work", "worth", "yield",
}

def should_auto_disable(term_str):
    """Return True if a keyword should be force-disabled on bulk import."""
    t = term_str.strip()
    if len(t) < 4:
        return True
    words = t.split()
    if len(words) == 1 and t.lower() in COMMON_BANKING_WORDS:
        return True
    return False

def risky_terms_enabled():
    items = cfg_get("cfg_risky_terms2", [], list)
    return [i["term"] for i in items if isinstance(i, dict) and i.get("enabled")]

def score_new_transactions(customer_id=None):
    db = get_db()
    country_map = get_country_map()

    # Bulk-fetch ALL config values in one query (avoids ~30 individual DB queries)
    ensure_config_kv_table()
    _all_cfg = {}
    try:
        _cfg_rows = db.execute("SELECT key, value FROM config_kv").fetchall()
        _all_cfg = {r["key"]: r["value"] for r in _cfg_rows}
    except Exception:
        pass

    def _cfg(key, default, cast=float):
        raw = _all_cfg.get(key)
        if raw is None:
            return default
        try:
            if cast is float: return float(raw)
            if cast is int:   return int(float(raw))
            return raw
        except Exception:
            return default

    def _cfg_bool(key, default=True):
        raw = _all_cfg.get(key)
        if raw is None:
            return default
        return str(raw).lower() in ("1", "true", "yes", "on")

    # Params (all from cache, zero DB queries)
    high_risk_min_amount = _cfg("cfg_high_risk_min_amount", 0.0)
    median_mult = _cfg("cfg_median_multiplier", 3.0)
    exp_out_factor = _cfg("cfg_expected_out_factor", 1.2)
    exp_in_factor  = _cfg("cfg_expected_in_factor", 1.2)
    exp_min_months = _cfg("cfg_expected_min_months", 3, int)
    sev_crit = _cfg("cfg_sev_critical", 90, int)
    sev_high = _cfg("cfg_sev_high", 70, int)
    sev_med  = _cfg("cfg_sev_medium", 50, int)
    sev_low  = _cfg("cfg_sev_low", 30, int)

    # Risky terms (parse from cached value)
    enabled_terms = []
    try:
        raw_terms = _all_cfg.get("cfg_risky_terms2")
        if raw_terms:
            terms_list = json.loads(raw_terms) if isinstance(raw_terms, str) else raw_terms
            enabled_terms = [t["term"] for t in terms_list if t.get("enabled", True)]
    except Exception:
        pass

    # Pre-compile NLP terms into single regex for O(1) matching per narrative
    import re as _re
    _nlp_pattern = None
    if enabled_terms:
        escaped = [_re.escape(t) for t in enabled_terms]
        _nlp_pattern = _re.compile('|'.join(escaped), _re.IGNORECASE)

    # Toggles (all from cache)
    on = {
        "prohibited_country": _cfg_bool("cfg_rule_enabled_prohibited_country", True),
        "high_risk_corridor": _cfg_bool("cfg_rule_enabled_high_risk_corridor", True),
        "median_outlier": _cfg_bool("cfg_rule_enabled_median_outlier", True),
        "nlp_risky_terms": _cfg_bool("cfg_rule_enabled_nlp_risky_terms", True),
        "expected_out": _cfg_bool("cfg_rule_enabled_expected_out", True),
        "expected_in": _cfg_bool("cfg_rule_enabled_expected_in", True),
        "cash_daily_breach": _cfg_bool("cfg_rule_enabled_cash_daily_breach", True),
        "severity_mapping": _cfg_bool("cfg_rule_enabled_severity_mapping", True),
        "structuring": _cfg_bool("cfg_rule_enabled_structuring", True),
        "flowthrough": _cfg_bool("cfg_rule_enabled_flowthrough", True),
        "dormancy": _cfg_bool("cfg_rule_enabled_dormancy", True),
        "velocity": _cfg_bool("cfg_rule_enabled_velocity", True),
    }

    # Rule parameters (all from cache)
    structuring_threshold = _cfg("cfg_structuring_threshold", 10000.0)
    structuring_margin_pct = _cfg("cfg_structuring_margin_pct", 15.0)
    structuring_min_count = _cfg("cfg_structuring_min_count", 2, int)
    flowthrough_window_days = _cfg("cfg_flowthrough_window_days", 3, int)
    flowthrough_match_pct = _cfg("cfg_flowthrough_match_pct", 80.0)
    dormancy_inactive_days = _cfg("cfg_dormancy_inactive_days", 90, int)
    dormancy_reactivation_amount = _cfg("cfg_dormancy_reactivation_amount", 5000.0)
    velocity_window_hours = _cfg("cfg_velocity_window_hours", 24, int)
    velocity_min_count = _cfg("cfg_velocity_min_count", 5, int)

    # Identify which customers have unscored transactions (scope all queries to them)
    from collections import defaultdict
    if customer_id:
        _unscored_custs = db.execute("""
            SELECT DISTINCT t.customer_id FROM transactions t
            LEFT JOIN alerts a ON a.txn_id = t.id
            WHERE a.id IS NULL AND t.customer_id = ?
        """, (customer_id,)).fetchall()
    else:
        _unscored_custs = db.execute("""
            SELECT DISTINCT t.customer_id FROM transactions t
            LEFT JOIN alerts a ON a.txn_id = t.id
            WHERE a.id IS NULL
        """).fetchall()
    cust_ids = [r["customer_id"] for r in _unscored_custs]
    if not cust_ids:
        return  # Nothing to score

    # Build SQL IN clause for scoping
    cust_placeholders = ','.join(['?'] * len(cust_ids))
    cust_filter = f"customer_id IN ({cust_placeholders})"

    # Pre-aggregate: Medians via SQL (scoped to relevant customers)
    median_rows = db.execute(f"""
        SELECT customer_id, direction,
               PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY base_amount) AS med
        FROM transactions
        WHERE {cust_filter}
        GROUP BY customer_id, direction
    """, cust_ids).fetchall()
    cust_medians = {(r["customer_id"], r["direction"]): float(r["med"]) for r in median_rows}

    # Pre-aggregate: Monthly totals per customer/direction
    monthly_rows = db.execute(f"""
        SELECT customer_id, direction,
               TO_CHAR(txn_date, 'YYYY-MM-01') AS mstart,
               SUM(base_amount) AS total
        FROM transactions
        WHERE {cust_filter}
        GROUP BY customer_id, direction, TO_CHAR(txn_date, 'YYYY-MM-01')
    """, cust_ids).fetchall()
    monthly_totals = {}
    for r in monthly_rows:
        monthly_totals[(r["customer_id"], r["direction"], r["mstart"])] = float(r["total"])

    # Pre-aggregate: Historical average monthly totals per customer/direction
    _cust_dir_months = defaultdict(dict)
    for (cid, dirn, mstart), total in monthly_totals.items():
        _cust_dir_months[(cid, dirn)][mstart] = total
    hist_avg_cache = {}
    for (cid, dirn), months_map in _cust_dir_months.items():
        total_all = sum(months_map.values())
        count_all = len(months_map)
        for mstart, mtotal in months_map.items():
            excl_count = count_all - 1
            excl_avg = (total_all - mtotal) / excl_count if excl_count > 0 else 0.0
            hist_avg_cache[(cid, dirn, mstart)] = (excl_avg, excl_count)

    # Pre-aggregate: Cash daily totals (scoped)
    cash_daily_totals = {}
    if on["cash_daily_breach"]:
        cash_daily_rows = db.execute(f"""
            SELECT customer_id, CAST(txn_date AS DATE) AS txn_day, SUM(base_amount) AS total
            FROM transactions
            WHERE ({cust_filter})
              AND (lower(COALESCE(channel,''))='cash'
                   OR POSITION('cash' IN lower(COALESCE(narrative,'')))>0)
            GROUP BY customer_id, CAST(txn_date AS DATE)
        """, cust_ids).fetchall()
        for r in cash_daily_rows:
            cash_daily_totals[(r["customer_id"], str(r["txn_day"]))] = float(r["total"])

    # Pre-aggregate: Earliest transaction date per customer (scoped)
    earliest_rows = db.execute(f"""
        SELECT customer_id, MIN(txn_date) AS earliest
        FROM transactions WHERE {cust_filter}
        GROUP BY customer_id
    """, cust_ids).fetchall()
    cust_earliest = {r["customer_id"]: r["earliest"] for r in earliest_rows}

    # Pre-aggregate: Transaction counts per customer/date for velocity (scoped)
    txn_counts_by_date = {}
    if on["velocity"]:
        velocity_rows = db.execute(f"""
            SELECT customer_id, CAST(txn_date AS DATE) AS txn_day, COUNT(*) AS cnt
            FROM transactions WHERE {cust_filter}
            GROUP BY customer_id, CAST(txn_date AS DATE)
        """, cust_ids).fetchall()
        for r in velocity_rows:
            txn_counts_by_date[(r["customer_id"], str(r["txn_day"]))] = int(r["cnt"])

    # Pre-load months that already have an expected-breach alert
    _breach_cust_filter = ','.join(['?'] * len(cust_ids))
    existing_breach_rows = db.execute(f"""
        SELECT a.customer_id, t.direction, TO_CHAR(t.txn_date, 'YYYY-MM-01') AS mstart, a.rule_tags
        FROM alerts a JOIN transactions t ON t.id = a.txn_id
        WHERE a.customer_id IN ({_breach_cust_filter}) AND a.rule_tags LIKE ?
    """, cust_ids + ['%EXPECTED_BREACH%']).fetchall()
    _breach_fired = set()
    for r in existing_breach_rows:
        tags_str = r["rule_tags"] or ""
        if "EXPECTED_BREACH_OUT" in tags_str and r["direction"] == "out":
            _breach_fired.add((r["customer_id"], "out", r["mstart"]))
        if "EXPECTED_BREACH_IN" in tags_str and r["direction"] == "in":
            _breach_fired.add((r["customer_id"], "in", r["mstart"]))

    # Pre-aggregate: Structuring (scoped, skip if disabled)
    _structuring_cache = {}
    if on["structuring"] and structuring_threshold > 0:
        s_lower = structuring_threshold * (1 - structuring_margin_pct / 100)
        struct_rows = db.execute(f"""
            SELECT customer_id, CAST(txn_date AS DATE) AS txn_day, COUNT(*) AS cnt
            FROM transactions
            WHERE ({cust_filter}) AND base_amount >= ? AND base_amount < ?
            GROUP BY customer_id, CAST(txn_date AS DATE)
        """, cust_ids + [s_lower, structuring_threshold]).fetchall()
        _struct_daily = defaultdict(dict)
        for r in struct_rows:
            _struct_daily[r["customer_id"]][str(r["txn_day"])] = int(r["cnt"])
        for cid, date_counts in _struct_daily.items():
            for ds, cnt in date_counts.items():
                d_ref = date.fromisoformat(ds) if isinstance(ds, str) else ds
                rolling = 0
                for offset in range(8):
                    check = (d_ref - timedelta(days=offset)).isoformat()
                    rolling += date_counts.get(check, 0)
                _structuring_cache[(cid, ds)] = rolling

    # Pre-aggregate: Dormancy — use DISTINCT dates only (scoped, skip if disabled)
    _dormancy_cache = {}
    if on["dormancy"]:
        dorm_rows = db.execute(f"""
            SELECT DISTINCT customer_id, CAST(txn_date AS DATE) AS txn_day
            FROM transactions WHERE {cust_filter}
            ORDER BY customer_id, txn_day
        """, cust_ids).fetchall()
        _cust_dates = defaultdict(list)
        for r in dorm_rows:
            v = r["txn_day"]
            _cust_dates[r["customer_id"]].append(
                v if isinstance(v, date) else date.fromisoformat(str(v)[:10]))
        for cid, dates in _cust_dates.items():
            sorted_dates = sorted(set(dates))
            for i, d_val in enumerate(sorted_dates):
                if i > 0:
                    _dormancy_cache[(cid, d_val.isoformat())] = sorted_dates[i-1]

    # Pre-aggregate: Flow-through — date-bucketed index (scoped, skip if disabled)
    _flowthrough_by_date = defaultdict(lambda: defaultdict(list))
    if on["flowthrough"]:
        ft_rows = db.execute(f"""
            SELECT id, customer_id, direction, CAST(txn_date AS DATE) AS txn_day, base_amount
            FROM transactions WHERE {cust_filter}
            ORDER BY customer_id, txn_day
        """, cust_ids).fetchall()
        for r in ft_rows:
            d_val = r["txn_day"] if isinstance(r["txn_day"], date) else date.fromisoformat(str(r["txn_day"])[:10])
            _flowthrough_by_date[r["customer_id"]][d_val].append({
                "id": r["id"],
                "direction": r["direction"],
                "base_amount": float(r["base_amount"]),
            })

    # Pre-fetch config values used inside the loop (avoid per-txn DB queries)
    cash_daily_limit = float(cfg_get("cfg_cash_daily_limit", 0.0, float))

    # Worklist (scoped to customers with unscored transactions)
    txns = db.execute(f"""
        SELECT t.* FROM transactions t
        LEFT JOIN alerts a ON a.txn_id = t.id
        WHERE a.id IS NULL AND t.{cust_filter}
        ORDER BY t.txn_date ASC
    """, cust_ids).fetchall()

    alert_batch = []

    for t in txns:
        reasons, tags, score = [], [], 0
        severity = "LOW"
        chan = (t["channel"] or "").lower()
        narrative = (t["narrative"] or "")

        _td = t["txn_date"]
        if isinstance(_td, datetime):
            d = _td.date()
        elif isinstance(_td, date):
            d = _td
        else:
            d = date.fromisoformat(str(_td)[:10])
        month_start = d.replace(day=1).isoformat()

        # Use pre-aggregated monthly totals instead of per-txn queries
        month_in_total = monthly_totals.get((t["customer_id"], "in", month_start), 0.0)
        month_out_total = monthly_totals.get((t["customer_id"], "out", month_start), 0.0)

        # Dynamic expected baselines from historical monthly averages
        expected_monthly_out, hist_months_out = hist_avg_cache.get((t["customer_id"], "out", month_start), (0.0, 0))
        expected_monthly_in, hist_months_in   = hist_avg_cache.get((t["customer_id"], "in",  month_start), (0.0, 0))
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
        if on["cash_daily_breach"] and cash_daily_limit > 0 and (chan == "cash" or "cash" in narrative.lower()):
            # Use pre-aggregated cash daily totals
            d_total = cash_daily_totals.get((t["customer_id"], str(t["txn_date"])), 0.0)
            if d_total > cash_daily_limit:
                reasons.append(f"Cash daily limit breached (global £{cash_daily_limit:,.2f}; activity £{d_total:,.2f})")
                tags.append("CASH_DAILY_BREACH")
                score += 20        

        # Median outlier
        if on["median_outlier"] and med > 0 and float(t["base_amount"]) > med * float(median_mult):
            reasons.append(f"Significant deviation (×{t['base_amount']/med:.1f})")
            tags.append("HISTORICAL_DEVIATION")
            score += 25

        # NLP risky terms (pre-compiled regex for O(1) matching)
        if on["nlp_risky_terms"] and _nlp_pattern and _nlp_pattern.search(narrative):
            reasons.append("Narrative contains risky term(s)")
            tags.append("NLP_RISK")
            score += 10

        # Expected breaches (dynamic baseline from historical averages, once per customer/month)
        _out_key = (t["customer_id"], "out", month_start)
        if on["expected_out"] and t["direction"]=="out" and expected_monthly_out > 0 and hist_months_out >= exp_min_months and _out_key not in _breach_fired:
            if month_out_total > expected_monthly_out * float(exp_out_factor):
                reasons.append(f"Outflows exceed historical average (actual £{month_out_total:,.2f} vs avg £{expected_monthly_out:,.2f})")
                tags.append("EXPECTED_BREACH_OUT")
                score += 20
                _breach_fired.add(_out_key)

        _in_key = (t["customer_id"], "in", month_start)
        if on["expected_in"] and t["direction"]=="in" and expected_monthly_in > 0 and hist_months_in >= exp_min_months and _in_key not in _breach_fired:
            if month_in_total > expected_monthly_in * float(exp_in_factor):
                reasons.append(f"Inflows exceed historical average (actual £{month_in_total:,.2f} vs avg £{expected_monthly_in:,.2f})")
                tags.append("EXPECTED_BREACH_IN")
                score += 15
                _breach_fired.add(_in_key)

        # Structuring detection - transactions just below reporting threshold (pre-aggregated)
        if on["structuring"] and structuring_threshold > 0:
            lower_bound = structuring_threshold * (1 - structuring_margin_pct / 100)
            amt = float(t["base_amount"])
            if lower_bound <= amt < structuring_threshold:
                similar_count = _structuring_cache.get((t["customer_id"], d.isoformat()), 0)
                if similar_count >= structuring_min_count:
                    reasons.append(f"Potential structuring: {similar_count} transactions just below £{structuring_threshold:,.0f} threshold")
                    tags.append("STRUCTURING")
                    score += 30

        # Flow-through detection - funds in then out within short window (date-bucketed)
        if on["flowthrough"]:
            amt = float(t["base_amount"])
            match_lower = amt * (flowthrough_match_pct / 100)
            match_upper = amt * (2 - flowthrough_match_pct / 100)
            opposite_dir = "out" if t["direction"] == "in" else "in"
            matching_txn = None
            cust_dates = _flowthrough_by_date.get(t["customer_id"])
            if cust_dates:
                for offset_d in range(flowthrough_window_days + 1):
                    for sign in (1, -1):
                        check_d = d + timedelta(days=offset_d * sign)
                        for ft in cust_dates.get(check_d, []):
                            if ft["id"] == t["id"]:
                                continue
                            if ft["direction"] != opposite_dir:
                                continue
                            if match_lower <= ft["base_amount"] <= match_upper:
                                matching_txn = ft
                                break
                        if matching_txn:
                            break
                    if matching_txn:
                        break
            if matching_txn:
                reasons.append(f"Flow-through pattern: £{amt:,.2f} {t['direction']} matched by £{matching_txn['base_amount']:,.2f} {opposite_dir} within {flowthrough_window_days} days")
                tags.append("FLOW_THROUGH")
                score += 25

        # Dormancy detection - sudden activity after period of inactivity (pre-aggregated)
        if on["dormancy"] and float(t["base_amount"]) >= dormancy_reactivation_amount:
            earliest = cust_earliest.get(t["customer_id"])
            if earliest:
                earliest_d = earliest if isinstance(earliest, date) else date.fromisoformat(str(earliest))
                dormancy_cutoff = d - timedelta(days=dormancy_inactive_days)
                if earliest_d < dormancy_cutoff:
                    prev_date = _dormancy_cache.get((t["customer_id"], d.isoformat()))
                    if prev_date and prev_date < dormancy_cutoff:
                        reasons.append(f"Dormancy reactivation: £{t['base_amount']:,.2f} after {dormancy_inactive_days}+ days of inactivity")
                        tags.append("DORMANCY_REACTIVATION")
                        score += 20

        # Velocity detection - use pre-aggregated daily counts
        if on["velocity"]:
            velocity_days = max(1, velocity_window_hours // 24) if velocity_window_hours >= 24 else 1
            txn_count = 0
            for offset_d in range(velocity_days + 1):
                check_date = (d - timedelta(days=offset_d)).isoformat()
                txn_count += txn_counts_by_date.get((t["customer_id"], check_date), 0)
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
            alert_batch.append((
                t["id"], t["customer_id"], int(min(score, 100)), severity,
                json.dumps(reasons), json.dumps(list(dict.fromkeys(tags)))
            ))

    # Bulk insert all alerts at once
    if alert_batch:
        config_ver = db.execute("SELECT MAX(id) AS v FROM config_versions").fetchone()
        cv = config_ver["v"] if config_ver else None
        db.executemany(
            """INSERT INTO alerts(txn_id, customer_id, score, severity, reasons, rule_tags, config_version)
               VALUES(?,?,?,?,?,?,?)""",
            [(a[0], a[1], a[2], a[3], a[4], a[5], cv) for a in alert_batch]
        )
    db.commit()

# ---------- Routes ----------

# --- Authentication routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    # Ensure DB and users table exist before any auth queries
    init_db()
    ensure_users_table()
    if session.get("user_id") and not session.get("awaiting_2fa") and not session.get("awaiting_2fa_setup"):
        # Check if user must change password
        if session.get("must_change_password"):
            return redirect(url_for("change_password"))
        return _default_landing()

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

        # Always run password hash check to prevent timing-based username
        # enumeration (AGRA-001-1-4 pen test remediation)
        pw_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
        password_valid = check_password_hash(pw_hash, password)

        if user and password_valid:
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
                session["pending_2fa_started"] = datetime.now().isoformat()
                log_audit_event("LOGIN_2FA_PENDING", user["id"], username, "Awaiting 2FA verification")
                return redirect(url_for("verify_2fa"))

            # No 2FA — enter pending state for MFA setup (AGRA-001-1-1)
            # Do NOT call complete_login() yet; session_token must wait until MFA is configured
            session["pending_user_id"] = user["id"]
            session["pending_username"] = user["username"]
            session["awaiting_2fa_setup"] = True
            session["pending_2fa_started"] = datetime.now().isoformat()
            log_audit_event("LOGIN_2FA_SETUP_PENDING", user["id"], username, "Awaiting 2FA setup")
            return redirect(url_for("setup_2fa"))
        else:
            # Record failed attempt
            record_failed_login(username)
            flash("Invalid username or password.")
    
    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Self-service password reset — sends a one-time link via email."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Please enter your username.")
            return render_template("forgot_password.html")

        db = get_db()
        ensure_password_reset_tokens()
        user = db.execute("SELECT id, email, username FROM users WHERE username=%s", (username,)).fetchone()

        if user and user["email"]:
            token = secrets.token_urlsafe(48)
            expires = (datetime.now() + timedelta(hours=1)).isoformat()
            db.execute(
                "INSERT INTO password_reset_tokens(user_id, token, expires_at) VALUES(%s, %s, %s)",
                (user["id"], token, expires),
            )
            db.commit()

            reset_url = url_for("reset_password", token=token, _external=True)
            html_body = f"""
            <html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Password Reset Request</h2>
                <p>Hello <strong>{user['username']}</strong>,</p>
                <p>A password reset was requested for your account. Click the link below to set a new password:</p>
                <p><a href="{reset_url}" style="display:inline-block;padding:10px 24px;background:#0d6efd;color:#fff;text-decoration:none;border-radius:5px;">Reset Password</a></p>
                <p style="color:#6c757d;font-size:13px;">This link expires in 1 hour. If you did not request this, please ignore this email.</p>
            </div></body></html>
            """
            send_email(user["email"], "Password Reset — Transaction Review Tool", html_body,
                       f"Reset your password: {reset_url}\n\nThis link expires in 1 hour.")
            log_audit_event("PASSWORD_RESET_REQUESTED", user["id"], user["username"])

        # Always show the same message to prevent username enumeration
        flash("If an account with that username exists and has an email address, a reset link has been sent.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Handle the one-time password reset link."""
    db = get_db()
    ensure_password_reset_tokens()

    row = db.execute(
        "SELECT * FROM password_reset_tokens WHERE token=%s AND used=0", (token,)
    ).fetchone()

    if not row:
        flash("Invalid or expired reset link.")
        return redirect(url_for("login"))

    expires = row["expires_at"] if isinstance(row["expires_at"], datetime) else datetime.fromisoformat(str(row["expires_at"]))
    if datetime.now() > expires:
        flash("This reset link has expired. Please request a new one.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_pw = request.form.get("password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if new_pw != confirm_pw:
            flash("Passwords do not match.")
            return render_template("reset_password.html", token=token)

        is_valid, msg = validate_password(new_pw)
        if not is_valid:
            flash(msg)
            return render_template("reset_password.html", token=token)

        user = db.execute("SELECT id, username FROM users WHERE id=%s", (row["user_id"],)).fetchone()
        if not user:
            flash("User account not found.")
            return redirect(url_for("login"))

        db.execute("UPDATE users SET password_hash=%s, must_change_password=0 WHERE id=%s",
                   (generate_password_hash(new_pw), user["id"]))
        db.execute("UPDATE password_reset_tokens SET used=1 WHERE user_id=%s", (row["user_id"],))
        db.commit()

        log_audit_event("PASSWORD_RESET_COMPLETED", user["id"], user["username"])
        flash("Password has been reset. Please log in with your new password.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


def _default_landing():
    """Return the default post-login redirect based on user role."""
    role = session.get("role", "")
    if role in ("bau_manager", "remediation_manager"):
        return redirect(url_for("manager_dashboard"))
    return redirect(url_for("upload"))

def complete_login(user):
    """Complete the login process after password (and optionally 2FA) verification."""
    # Clear any pending 2FA state
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("awaiting_2fa", None)
    session.pop("awaiting_2fa_setup", None)
    session.pop("pending_2fa_started", None)
    
    # Set session
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["user_type"] = user.get("user_type", "BAU")
    session["last_activity"] = datetime.now().isoformat()

    # Concurrent session prevention (AGRA-001-1-10 pen test remediation)
    # Invalidate all prior sessions for this user, then store the new token
    try:
        ensure_user_sessions_table()
        db = get_db()
        db.execute("DELETE FROM user_sessions WHERE user_id=%s", (user["id"],))
        session_token = secrets.token_urlsafe(32)
        session["session_token"] = session_token
        db.execute("INSERT INTO user_sessions(user_id, session_token) VALUES(%s, %s)",
                   (user["id"], session_token))
        db.commit()
    except Exception:
        db = get_db()  # re-acquire in case of error

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
    return None


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
            # Clear pending state before complete_login (it also clears, but be explicit)
            session.pop("pending_2fa_started", None)
            result = complete_login(user)
            if result:
                return result
            # Validate and use safe redirect URL
            next_url = request.args.get("next")
            if next_url and is_safe_redirect_url(next_url):
                return redirect(next_url)
            return _default_landing()
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
        return _default_landing()
    
    return render_template("change_password.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    """Setup 2FA for the current user (or pending-MFA user during login)."""
    # Determine user_id: either fully authenticated or in pending MFA-setup state
    user_id = session.get("user_id") or session.get("pending_user_id")
    is_pending = session.get("awaiting_2fa_setup", False)

    if not user_id and not is_pending:
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    # If not pending (i.e. already authenticated), enforce login_required semantics
    if not is_pending and not session.get("user_id"):
        flash("Please log in to continue.")
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    # Check if already enabled
    try:
        if user["totp_enabled"] and user["totp_verified"]:
            if is_pending:
                # User already has 2FA (race condition / back-button) — just verify
                return redirect(url_for("verify_2fa"))
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
        db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user_id))
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
            """, (json.dumps(backup_codes), user_id))
            db.commit()

            if is_pending:
                # Complete the login now that MFA is set up (AGRA-001-1-1)
                session.pop("pending_2fa_started", None)
                session.pop("awaiting_2fa_setup", None)
                complete_login(user)
                log_audit_event("2FA_ENABLED", user["id"], user["username"], "2FA setup completed during login")
            else:
                log_audit_event("2FA_ENABLED", user_id, session.get("username"), "2FA setup completed")

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
    # Remove session from DB (AGRA-001-1-10 concurrent session prevention)
    session_token = session.get("session_token")
    if user_id and session_token:
        try:
            db = get_db()
            db.execute("DELETE FROM user_sessions WHERE user_id=%s AND session_token=%s",
                       (user_id, session_token))
            db.commit()
        except Exception:
            pass
    session.clear()
    if user_id:
        log_audit_event("LOGOUT", user_id, username)
    flash("You have been logged out.")
    return redirect(url_for("login"))


# --- Session timeout check ---
@app.before_request
def check_pending_mfa_timeout():
    """Expire pending MFA sessions after 5 minutes (AGRA-001-1-1)."""
    if session.get("pending_user_id") and not session.get("user_id"):
        started = session.get("pending_2fa_started")
        if started:
            try:
                start_time = datetime.fromisoformat(started)
                if datetime.now() - start_time > timedelta(minutes=5):
                    pending_user = session.get("pending_username", "unknown")
                    session.clear()
                    log_audit_event("PENDING_MFA_TIMEOUT", None, pending_user, "Pending MFA session expired")
                    flash("Your session has expired. Please log in again.")
                    return redirect(url_for("login"))
            except (ValueError, TypeError):
                session.clear()
                return redirect(url_for("login"))

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

    # If no customer selected, show blank state prompting user to search
    if not customer_id:
        return render_template(
            "dashboard.html",
            months=months,
            selected_period=period,
            filter_meta=None,
            overview_mode=True,
        )

    # --- Normal (filtered) dashboard below ---
    period = request.args.get("period", "all")
    account = request.args.get("account", "").strip()
    start, end = _period_bounds(period)

    # Predicates for transactions and alerts
    tx_where, tx_params = ["t.customer_id = ?"], [customer_id]
    a_where, a_params = ["a.customer_id = ?"], [customer_id]

    if account:
        tx_where.append("t.account_name = ?"); tx_params.append(account)

    if start and end:
        tx_where.append("t.txn_date BETWEEN ? AND ?"); tx_params += [start, end]
        a_where.append("a.created_at BETWEEN ? AND ?"); a_params += [start + " 00:00:00", end + " 23:59:59"]

    tx_pred = "WHERE " + " AND ".join(tx_where)
    a_pred  = "WHERE " + " AND ".join(a_where)

    # Alert predicates for queries that join transactions (need account filter)
    at_where = list(a_where)
    at_params = list(a_params)
    if account:
        at_where.append("t.account_name = ?"); at_params.append(account)
    at_pred = "WHERE " + " AND ".join(at_where)

    # Use materialised summary when viewing unfiltered (all time, no account filter)
    _use_summary = (not start) and (not account)
    _summary = None
    if _use_summary:
        try:
            _summary = db.execute(
                "SELECT * FROM customer_summaries WHERE customer_id = %s", (customer_id,)
            ).fetchone()
        except Exception:
            _summary = None

    if _summary:
        total_tx = int(_summary["total_tx"] or 0)
        total_alerts = int(_summary["total_alerts"] or 0)
        critical = int(_summary["critical_alerts"] or 0)
        total_in = float(_summary["total_in"] or 0)
        total_out = float(_summary["total_out"] or 0)
        total_value = total_in + total_out
        cash_in = float(_summary["cash_in"] or 0)
        cash_out = float(_summary["cash_out"] or 0)
        high_risk_volume = int(_summary["high_risk_count"] or 0)
        high_risk_total = float(_summary["high_risk_total"] or 0)
        avg_cash_deposits = float(_summary["avg_cash_in"] or 0)
        avg_cash_withdrawals = float(_summary["avg_cash_out"] or 0)
        avg_in = float(_summary["avg_in"] or 0)
        avg_out = float(_summary["avg_out"] or 0)
        max_in = float(_summary["max_in"] or 0)
        max_out = float(_summary["max_out"] or 0)
        overseas_in = float(_summary["overseas_in"] or 0)
        overseas_out = float(_summary["overseas_out"] or 0)
        highrisk_value = float(_summary["high_risk_value"] or 0)
        denom_total = total_value if total_value > 0 else float(_summary["total_value"] or 0)
        highrisk_pct = (highrisk_value / denom_total * 100.0) if denom_total > 0 else 0.0
    else:
        # Fallback: live aggregate queries (used when filters active or no summary yet)
        total_tx = db.execute(f"SELECT COUNT(*) c FROM transactions t {tx_pred}", tx_params).fetchone()["c"]
        total_alerts = db.execute(f"SELECT COUNT(*) c FROM alerts a {a_pred}", a_params).fetchone()["c"]
        critical = db.execute(f"SELECT COUNT(*) c FROM alerts a {a_pred} AND a.severity='CRITICAL'", a_params).fetchone()["c"]

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
                       AND lower(COALESCE(t.channel,''))='cash'
                     THEN t.base_amount ELSE 0 END) AS cash_in,
            SUM(CASE WHEN t.direction='out'
                       AND lower(COALESCE(t.channel,''))='cash'
                     THEN t.base_amount ELSE 0 END) AS cash_out
          FROM transactions t {tx_pred}
        """, tx_params).fetchone()
        cash_in  = float(cash["cash_in"]  or 0)
        cash_out = float(cash["cash_out"] or 0)

        hr = db.execute(f"""
          SELECT COUNT(*) AS cnt, SUM(t.base_amount) AS total
          FROM transactions t
          JOIN ref_country_risk r ON r.iso2 = COALESCE(t.country_iso2, '')
          {tx_pred + (' AND ' if tx_pred else 'WHERE ')} r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
        """, tx_params).fetchone()
        high_risk_volume = int(hr["cnt"] or 0)
        high_risk_total  = float(hr["total"] or 0)

        m = db.execute(f"""
          SELECT
            AVG(CASE WHEN t.direction='in'  AND lower(COALESCE(t.channel,''))='cash' THEN t.base_amount END) AS avg_cash_in,
            AVG(CASE WHEN t.direction='out' AND lower(COALESCE(t.channel,''))='cash' THEN t.base_amount END) AS avg_cash_out,
            AVG(CASE WHEN t.direction='in'  THEN t.base_amount END) AS avg_in,
            AVG(CASE WHEN t.direction='out' THEN t.base_amount END) AS avg_out,
            MAX(CASE WHEN t.direction='in'  THEN t.base_amount END) AS max_in,
            MAX(CASE WHEN t.direction='out' THEN t.base_amount END) AS max_out,
            SUM(CASE WHEN COALESCE(t.country_iso2,'')<>'' AND UPPER(t.country_iso2)<>'GB' AND t.direction='in' THEN t.base_amount ELSE 0 END) AS overseas_in,
            SUM(CASE WHEN COALESCE(t.country_iso2,'')<>'' AND UPPER(t.country_iso2)<>'GB' AND t.direction='out' THEN t.base_amount ELSE 0 END) AS overseas_out,
            SUM(t.base_amount) AS total_value
          FROM transactions t {tx_pred}
        """, tx_params).fetchone()
        avg_cash_deposits    = float(m["avg_cash_in"]  or 0.0)
        avg_cash_withdrawals = float(m["avg_cash_out"] or 0.0)
        avg_in               = float(m["avg_in"]       or 0.0)
        avg_out              = float(m["avg_out"]      or 0.0)
        max_in               = float(m["max_in"]       or 0.0)
        max_out              = float(m["max_out"]      or 0.0)
        overseas_in          = float(m["overseas_in"] or 0.0)
        overseas_out         = float(m["overseas_out"] or 0.0)
        total_val_from_query = float(m["total_value"]  or 0.0)
        denom_total = total_value if total_value > 0 else total_val_from_query

        hr_val_row = db.execute(f"""
          SELECT SUM(t.base_amount) AS v
          FROM transactions t
          JOIN ref_country_risk r ON r.iso2 = COALESCE(t.country_iso2, '')
          {tx_pred + (' AND ' if tx_pred else 'WHERE ')} r.risk_level IN ('HIGH','HIGH_3RD','PROHIBITED')
        """, tx_params).fetchone()
        highrisk_value = float(hr_val_row["v"] or 0.0)
        highrisk_pct   = (highrisk_value / denom_total * 100.0) if denom_total > 0 else 0.0

    kpis = {
        "total_tx": total_tx,
        "total_alerts": total_alerts,
        "alert_rate": (total_alerts / total_tx) if total_tx else 0,
        "critical": critical,
    }

    tiles = {
        "total_in": total_in,
        "total_out": total_out,
        "cash_in": cash_in,
        "cash_out": cash_out,
        "high_risk_volume": high_risk_volume,
        "high_risk_total": high_risk_total,
    }

    # Alerts over time — group by TRANSACTION DATE (t.txn_date)
    if start and end:
        aot_sql = """
          SELECT to_char(t.txn_date, 'YYYY-MM-DD') d, COUNT(*) c
          FROM alerts a
          JOIN transactions t ON t.id = a.txn_id
          WHERE t.customer_id = %s AND t.txn_date BETWEEN %s AND %s
        """
        aot_params = [customer_id, start, end]
    else:
        aot_sql = """
          SELECT to_char(t.txn_date, 'YYYY-MM-DD') d, COUNT(*) c
          FROM alerts a
          JOIN transactions t ON t.id = a.txn_id
          WHERE t.customer_id = %s
        """
        aot_params = [customer_id]
    if account:
        aot_sql += " AND t.account_name = %s"
        aot_params.append(account)
    aot_sql += " GROUP BY to_char(t.txn_date, 'YYYY-MM-DD') ORDER BY d"
    rows = db.execute(aot_sql, aot_params).fetchall()
    labels = [r["d"] for r in rows]
    values = [int(r["c"]) for r in rows]

    # Top countries (alerts) — show full country names
    tc_rows = db.execute(f"""
      SELECT t.country_iso2, COUNT(*) cnt
      FROM alerts a
      JOIN transactions t ON t.id = a.txn_id
      {at_pred}
      GROUP BY t.country_iso2
      ORDER BY cnt DESC
      LIMIT 10
    """, at_params).fetchall()
    top_countries = [
        {"name": country_full_name(r["country_iso2"]), "cnt": int(r["cnt"] or 0)}
        for r in tc_rows
    ]

    # Monthly trend of money in/out with cash breakdown (ALL TIME for this customer)
    trend_where = "WHERE t.customer_id = ?"
    trend_params = [customer_id]
    if account:
        trend_where += " AND t.account_name = ?"
        trend_params.append(account)
    trend_rows = db.execute(f"""
      SELECT to_char(t.txn_date, 'YYYY-MM') ym,
             SUM(CASE WHEN t.direction='in'  THEN t.base_amount ELSE 0 END) AS in_sum,
             SUM(CASE WHEN t.direction='out' THEN t.base_amount ELSE 0 END) AS out_sum,
             SUM(CASE WHEN t.direction='in'  AND LOWER(COALESCE(t.channel,''))='cash' THEN t.base_amount ELSE 0 END) AS cash_in_sum,
             SUM(CASE WHEN t.direction='out' AND LOWER(COALESCE(t.channel,''))='cash' THEN t.base_amount ELSE 0 END) AS cash_out_sum
      FROM transactions t
      {trend_where}
      GROUP BY ym
      ORDER BY ym
    """, trend_params).fetchall()
    trend_labels = [r["ym"] for r in trend_rows]
    trend_in  = [float(r["in_sum"]  or 0) for r in trend_rows]
    trend_out = [float(r["out_sum"] or 0) for r in trend_rows]
    trend_cash_in = [float(r["cash_in_sum"] or 0) for r in trend_rows]
    trend_cash_out = [float(r["cash_out_sum"] or 0) for r in trend_rows]

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
        filter_meta={"customer_id": customer_id, "account": account},
        accounts=_get_accounts_for_customer(customer_id),
        selected_account=account,
        metrics=metrics,
        scoring_status=_get_scoring_status(customer_id),
    )

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    """Data & Ingest landing page - create customers and upload transaction statements."""
    init_db()
    ensure_customers_table()
    ensure_statements_table()

    db = get_db()

    if request.method == "POST":
        action = request.form.get("action", "upload")

        # --- Add new customer inline ---
        if action == "add_customer":
            cust_id = request.form.get("new_customer_id", "").strip()
            cust_name = request.form.get("new_customer_name", "").strip()
            if not cust_id:
                flash("Customer ID is required.")
                return redirect(url_for("upload"))
            db.execute("""
                INSERT INTO customers(customer_id, customer_name, status)
                VALUES(?, ?, 'active')
                ON CONFLICT(customer_id) DO UPDATE SET
                    customer_name=COALESCE(excluded.customer_name, customers.customer_name),
                    updated_at=CURRENT_TIMESTAMP
            """, (cust_id, cust_name or None))
            db.commit()
            log_audit_event("CUSTOMER_CREATED", session.get("user_id"), session.get("username"),
                            details=f"Customer {cust_id} created via Data & Ingest")
            flash(f"Customer {cust_id} created. You can now upload their transactions.")
            return redirect(url_for("upload", customer_id=cust_id))

        # --- Delete a statement and its transactions ---
        if action == "delete_statement":
            stmt_id = request.form.get("statement_id", "").strip()
            cust_id = request.form.get("customer_id", "").strip()
            if stmt_id:
                # Get statement info for audit log
                stmt = db.execute("SELECT * FROM statements WHERE id=?", (stmt_id,)).fetchone()
                if stmt:
                    # Delete transactions that belong to this statement
                    db.execute("DELETE FROM alerts WHERE txn_id IN (SELECT id FROM transactions WHERE statement_id=?)", (stmt_id,))
                    db.execute("DELETE FROM transactions WHERE statement_id=?", (stmt_id,))
                    db.execute("DELETE FROM statements WHERE id=?", (stmt_id,))
                    db.commit()
                    log_audit_event("STATEMENT_DELETED", session.get("user_id"), session.get("username"),
                                    details=f"Deleted statement {stmt_id} (file: {stmt['filename']}) for customer {stmt['customer_id']}")
                    flash(f"Statement '{stmt['filename']}' and its transactions deleted.")
                else:
                    flash("Statement not found.")
            return redirect(url_for("upload", customer_id=cust_id))

        # --- Upload customer population CSV ---
        if action == "upload_customers":
            cust_file = request.files.get("customer_file")
            if cust_file and cust_file.filename:
                # Server-side file extension validation (AGRA-001-1-11)
                allowed_extensions = {'.csv', '.xlsx', '.xls'}
                cust_file_ext = os.path.splitext(cust_file.filename)[1].lower()
                if cust_file_ext not in allowed_extensions:
                    flash(f"Invalid file type '{cust_file_ext}'. Only CSV and Excel files (.csv, .xlsx, .xls) are accepted.")
                    return redirect(url_for("admin_customers"))
                try:
                    import pandas as pd
                    fname = getattr(cust_file, 'filename', '') or ''
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in ('.xlsx', '.xls'):
                        df = pd.read_excel(cust_file, engine='openpyxl' if ext == '.xlsx' else None)
                    else:
                        df = pd.read_csv(cust_file)
                    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
                    if "customer_id" not in df.columns:
                        flash("File must have a 'customer_id' column.")
                        return redirect(url_for("upload"))
                    n_added = 0
                    for _, r in df.iterrows():
                        cid = str(r.get("customer_id", "")).strip()
                        if not cid:
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
                            cid,
                            str(r.get("customer_name", "")).strip() or None,
                            str(r.get("business_type", "")).strip() or None,
                            str(r.get("onboarded_date", "")).strip() or None,
                            str(r.get("status", "active")).strip() or "active",
                        ))
                        n_added += 1
                    db.commit()
                    log_audit_event("BULK_CUSTOMER_IMPORT", session.get("user_id"), session.get("username"),
                                    details=f"Bulk imported {n_added} customers from file '{cust_file.filename}'")
                    flash(f"Imported {n_added} customer(s).")
                except Exception as e:
                    flash(f"Error importing customers: {e}")
            else:
                flash("Please select a file.")
            return redirect(url_for("upload"))

        # --- Re-score customer ---
        if action == "rescore":
            cid = request.form.get("customer_id", "").strip()
            if cid:
                submit_scoring(cid, purge_first=True)
                flash(f"Scoring started for customer {cid}. This will complete in the background.")
            return redirect(url_for("upload", customer_id=cid))

        # --- Upload transaction statement ---
        customer_id = request.form.get("customer_id", "").strip()
        account_name = request.form.get("account_name", "").strip()
        tx_file = request.files.get("tx_file")

        if not customer_id:
            flash("Please select a customer.")
            return redirect(url_for("upload"))

        cust = db.execute("SELECT * FROM customers WHERE customer_id=?", (customer_id,)).fetchone()
        if not cust:
            flash(f"Customer {customer_id} not found in the system.")
            return redirect(url_for("upload"))

        if not account_name:
            flash("Please enter an account name/number.")
            return redirect(url_for("upload", customer_id=customer_id))

        if not tx_file or not tx_file.filename:
            flash("Please select a transaction file to upload.")
            return redirect(url_for("upload", customer_id=customer_id))

        # Server-side file extension validation
        allowed_extensions = {'.csv', '.xlsx', '.xls'}
        file_ext = os.path.splitext(tx_file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            flash(f"Invalid file type '{file_ext}'. Only CSV and Excel files (.csv, .xlsx, .xls) are accepted.")
            return redirect(url_for("upload", customer_id=customer_id))

        try:
            # Insert statement record (fast) so we have a stmt_id
            user_id = session.get("user_id")
            username = session.get("username")
            db.execute("""
                INSERT INTO statements(customer_id, account_name, filename, uploaded_by, record_count, date_from, date_to)
                VALUES(?, ?, ?, ?, 0, NULL, NULL)
            """, (customer_id, account_name or None, tx_file.filename, user_id))
            db.commit()
            stmt_id = db.execute("SELECT MAX(id) AS sid FROM statements WHERE customer_id=?", (customer_id,)).fetchone()["sid"]

            # Save uploaded file to temp path (request.files won't survive after response)
            orig_ext = os.path.splitext(tx_file.filename)[1] or ".csv"
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=orig_ext)
            try:
                with os.fdopen(tmp_fd, "wb") as tmp_f:
                    tx_file.save(tmp_f)
            except Exception:
                os.close(tmp_fd)
                raise

            # Submit ingest + scoring to background thread — returns immediately
            submit_ingest_and_score(
                customer_id, tmp_path, stmt_id, tx_file.filename,
                account_name, user_id, username
            )

            acct_label = f" (Account: {account_name})" if account_name else ""
            flash(f"Upload received for customer {customer_id}{acct_label} ({tx_file.filename}). "
                  f"Ingesting and scoring in the background — this page will update automatically.")
        except Exception as e:
            app.logger.error(f"Upload failed for {customer_id}: {e}", exc_info=True)
            flash(f"Error starting upload: {e}")

        return redirect(url_for("upload", customer_id=customer_id))

    # --- GET: build page data ---
    customers = db.execute("SELECT customer_id, customer_name FROM customers WHERE status='active' ORDER BY customer_id").fetchall()
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

    # Summary stats scoped to the logged-in user
    uid = session.get("user_id")
    stats = {
        "total_customers": db.execute(
            "SELECT COUNT(DISTINCT customer_id) as c FROM statements WHERE uploaded_by = %s", (uid,)
        ).fetchone()["c"],
        "total_statements": db.execute(
            "SELECT COUNT(*) as c FROM statements WHERE uploaded_by = %s", (uid,)
        ).fetchone()["c"],
        "total_transactions": db.execute(
            "SELECT COALESCE(SUM(record_count), 0) as c FROM statements WHERE uploaded_by = %s", (uid,)
        ).fetchone()["c"],
    }

    scoring_info = _get_scoring_status(selected_customer) if selected_customer else None
    return render_template("upload.html", customers=customers, selected_customer=selected_customer,
                           statements=statements, stats=stats,
                           scoring_status=scoring_info)

@app.route("/scoring_status/<customer_id>")
@login_required
def scoring_status(customer_id):
    info = _get_scoring_status(customer_id)
    if info and info["status"] == "scoring":
        return jsonify({"status": "scoring"})
    elif info and info["status"] == "error":
        return jsonify({"status": "error", "message": info.get("msg", "")})
    elif info and info["status"] == "done":
        _clear_scoring_status(customer_id)
        return jsonify({"status": "done"})
    else:
        return jsonify({"status": "idle"})

@app.route("/alerts")
@login_required
def alerts():
    db = get_db()

    # Read filters
    sev  = (request.args.get("severity") or "").strip().upper()
    cust = (request.args.get("customer_id") or "").strip()
    tag  = (request.args.get("tag") or "").strip()  # NEW
    acct = (request.args.get("account") or "").strip()

    # Blank state: require a customer to be selected
    if not cust:
        return render_template("alerts.html", alerts=[], available_tags=[], accounts=[], no_customer=True)

    # Base query — always filtered by customer
    where, params = ["a.customer_id = ?"], [cust]
    if sev:
        where.append("a.severity = ?"); params.append(sev)
    if acct:
        where.append("t.account_name = ?"); params.append(acct)

    sql = f"""
      SELECT a.*, t.country_iso2, t.txn_date
        FROM alerts a
        LEFT JOIN transactions t ON t.id = a.txn_id
       WHERE {' AND '.join(where)}
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
        
        # Format dates in UK format (DD/MM/YYYY or DD/MM/YYYY HH:MM if time present)
        if d.get("txn_date"):
            try:
                from datetime import datetime, date as date_type
                val = d["txn_date"]
                if isinstance(val, datetime):
                    if val.hour == 0 and val.minute == 0 and val.second == 0:
                        d["txn_date_uk"] = val.strftime("%d/%m/%Y")
                    else:
                        d["txn_date_uk"] = val.strftime("%d/%m/%Y %H:%M")
                elif isinstance(val, date_type):
                    d["txn_date_uk"] = val.strftime("%d/%m/%Y")
                else:
                    s = str(val)
                    dt = datetime.fromisoformat(s) if 'T' in s or len(s) > 10 else datetime.strptime(s[:10], "%Y-%m-%d")
                    if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
                        d["txn_date_uk"] = dt.strftime("%d/%m/%Y")
                    else:
                        d["txn_date_uk"] = dt.strftime("%d/%m/%Y %H:%M")
            except Exception:
                d["txn_date_uk"] = str(d["txn_date"])

        if d.get("created_at"):
            try:
                from datetime import datetime
                val = d["created_at"]
                if isinstance(val, datetime):
                    d["created_at_uk"] = val.strftime("%d/%m/%Y %H:%M")
                else:
                    ca = str(val)[:19]
                    dt = datetime.strptime(ca, "%Y-%m-%d %H:%M:%S")
                    d["created_at_uk"] = dt.strftime("%d/%m/%Y %H:%M")
            except Exception:
                d["created_at_uk"] = str(d["created_at"])[:16] if d["created_at"] else "—"
        
        out.append(d)

    return render_template(
        "alerts.html",
        alerts=out,
        available_tags=available_tags,  # for the dropdown
        accounts=_get_accounts_for_customer(cust),
    )

# ---------- Manager Dashboard ----------
@app.route("/manager-dashboard")
@login_required
def manager_dashboard():
    """Dashboard for BAU Manager and Remediation Manager roles showing team KPIs."""
    role = session.get("role", "")
    if role not in ("bau_manager", "remediation_manager"):
        flash("Manager access required.")
        return redirect(url_for("upload"))

    # Determine team type from role
    if role == "bau_manager":
        team_type = "BAU"
        team_label = "BAU"
    else:
        team_type = "Remediation"
        team_label = "Remediation"

    db = get_db()

    # Total team users
    total_team_users = db.execute(
        "SELECT COUNT(*) c FROM users WHERE user_type = %s", (team_type,)
    ).fetchone()["c"]

    # Users who have logged in
    users_logged_in = db.execute(
        "SELECT COUNT(*) c FROM users WHERE user_type = %s AND last_login IS NOT NULL", (team_type,)
    ).fetchone()["c"]

    # Get team user IDs for filtering
    team_user_ids = [r["id"] for r in db.execute(
        "SELECT id FROM users WHERE user_type = %s", (team_type,)
    ).fetchall()]

    if team_user_ids:
        placeholders = ",".join(["%s"] * len(team_user_ids))

        # Total customers (distinct customer_ids from statements uploaded by team users)
        total_customers = db.execute(f"""
            SELECT COUNT(DISTINCT customer_id) c FROM statements WHERE uploaded_by IN ({placeholders})
        """, team_user_ids).fetchone()["c"]

        # Customers by month
        customers_by_month = db.execute(f"""
            SELECT TO_CHAR(s.uploaded_at, 'YYYY-MM') AS month, COUNT(DISTINCT s.customer_id) AS cnt
            FROM statements s
            WHERE s.uploaded_by IN ({placeholders})
            GROUP BY TO_CHAR(s.uploaded_at, 'YYYY-MM')
            ORDER BY month
        """, team_user_ids).fetchall()

        # Total statements
        total_statements = db.execute(f"""
            SELECT COUNT(*) c FROM statements WHERE uploaded_by IN ({placeholders})
        """, team_user_ids).fetchone()["c"]

        # Get team customer IDs for transaction/alert queries
        team_customer_ids = [r["customer_id"] for r in db.execute(f"""
            SELECT DISTINCT customer_id FROM statements WHERE uploaded_by IN ({placeholders})
        """, team_user_ids).fetchall()]
    else:
        total_customers = 0
        customers_by_month = []
        total_statements = 0
        team_customer_ids = []

    if team_customer_ids:
        c_placeholders = ",".join(["%s"] * len(team_customer_ids))

        # Total transactions
        total_transactions = db.execute(f"""
            SELECT COUNT(*) c FROM transactions WHERE customer_id IN ({c_placeholders})
        """, team_customer_ids).fetchone()["c"]

        # Avg transactions per customer
        avg_transactions = round(total_transactions / total_customers, 1) if total_customers else 0

        # Avg accounts per customer
        avg_accounts_row = db.execute(f"""
            SELECT AVG(acct_count) avg_accts FROM (
                SELECT customer_id, COUNT(DISTINCT account_name) acct_count
                FROM statements
                WHERE customer_id IN ({c_placeholders})
                GROUP BY customer_id
            ) sub
        """, team_customer_ids).fetchone()
        avg_accounts = round(float(avg_accounts_row["avg_accts"] or 0), 1)

        # Total alerts
        total_alerts = db.execute(f"""
            SELECT COUNT(*) c FROM alerts WHERE customer_id IN ({c_placeholders})
        """, team_customer_ids).fetchone()["c"]

        # Avg alerts per customer
        avg_alerts = round(total_alerts / total_customers, 1) if total_customers else 0

        # Customers awaiting outreach (at least 1 question with no response)
        awaiting_outreach = db.execute(f"""
            SELECT COUNT(DISTINCT ac.customer_id) c
            FROM ai_cases ac
            JOIN ai_answers aa ON aa.case_id = ac.id
            WHERE ac.customer_id IN ({c_placeholders})
              AND (aa.answer IS NULL OR aa.answer = '')
        """, team_customer_ids).fetchone()["c"]
    else:
        total_transactions = 0
        avg_transactions = 0
        avg_accounts = 0
        total_alerts = 0
        avg_alerts = 0
        awaiting_outreach = 0

    return render_template(
        "manager_dashboard.html",
        team_label=team_label,
        total_team_users=total_team_users,
        users_logged_in=users_logged_in,
        total_customers=total_customers,
        customers_by_month=customers_by_month,
        total_statements=total_statements,
        total_transactions=total_transactions,
        avg_transactions=avg_transactions,
        avg_accounts=avg_accounts,
        total_alerts=total_alerts,
        avg_alerts=avg_alerts,
        awaiting_outreach=awaiting_outreach,
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
                try:
                    db.execute("DELETE FROM alerts WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM transactions WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM statements WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM kyc_profile WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM customer_cash_limits WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM ai_rationales WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM ai_cases WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM scoring_jobs WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM customer_summaries WHERE customer_id=?", (cust_id,))
                    db.execute("DELETE FROM customers WHERE customer_id=?", (cust_id,))
                    db.commit()
                    log_audit_event("CUSTOMER_DELETED", session.get("user_id"), session.get("username"),
                                    details=f"Deleted customer {cust_id} and all associated data")
                    flash(f"Customer {cust_id} and all associated data deleted.")
                except Exception:
                    db.connection.rollback()
                    flash(f"Failed to delete customer {cust_id}.")

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
            user_type = request.form.get("user_type", "BAU").strip()
            send_email_flag = request.form.get("send_email") == "on"

            if not username:
                flash("Username is required.")
            elif role not in ("admin", "reviewer", "bau_manager", "remediation_manager"):
                flash("Invalid role.")
            elif user_type not in ("BAU", "Remediation"):
                flash("Invalid user type.")
            else:
                existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                if existing:
                    flash(f"Username '{username}' already exists.")
                else:
                    # Generate temporary password that meets policy
                    temp_password = secrets.token_urlsafe(8) + "A1!"  # Ensures complexity

                    db.execute(
                        """INSERT INTO users(username, email, password_hash, role, user_type, must_change_password)
                           VALUES(?, ?, ?, ?, ?, 1)""",
                        (username, email or None, generate_password_hash(temp_password), role, user_type)
                    )
                    db.commit()

                    log_audit_event("USER_CREATED", session.get("user_id"), session.get("username"),
                                  f"Created user '{username}' with role '{role}', type '{user_type}'")
                    
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
            new_user_type = request.form.get("user_type", "").strip()
            new_password = request.form.get("new_password", "").strip()
            force_password_change = request.form.get("force_password_change") == "on"

            if user_id:
                target_user = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
                updates = []

                if new_role in ("admin", "reviewer", "bau_manager", "remediation_manager"):
                    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
                    updates.append(f"role={new_role}")

                if new_user_type in ("BAU", "Remediation"):
                    db.execute("UPDATE users SET user_type=? WHERE id=?", (new_user_type, user_id))
                    updates.append(f"type={new_user_type}")
                
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
            current = cfg_get('cfg_enforce_2fa', True, bool)
            cfg_set('cfg_enforce_2fa', not current)
            status = "enabled" if not current else "disabled"
            log_audit_event("2FA_ENFORCEMENT_CHANGED", session.get("user_id"), session.get("username"),
                          f"2FA enforcement {status}")
            flash(f"Two-factor authentication enforcement has been {status}.")
        
        return redirect(url_for("admin_users"))
    
    # GET: list users with extended info
    users = db.execute("""
        SELECT id, username, email, role, user_type, must_change_password,
               failed_login_attempts, locked_until, last_login, created_at,
               totp_enabled, totp_verified
        FROM users ORDER BY username
    """).fetchall()
    
    # Get SMTP configuration status
    smtp_configured = bool(cfg_get('cfg_smtp_host', '', str))
    
    # Get 2FA enforcement status
    enforce_2fa = cfg_get('cfg_enforce_2fa', True, bool)
    
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
            # OAuth (XOAUTH2) settings
            cfg_set("cfg_smtp_use_oauth", request.form.get("smtp_use_oauth") == "on")
            cfg_set("cfg_smtp_tenant_id", request.form.get("smtp_tenant_id", "").strip())
            
            log_audit_event("SMTP_CONFIG_UPDATED", session.get("user_id"), session.get("username"))
            flash("SMTP settings saved. Password is encrypted at rest.")
        
        elif action == "test":
            test_email = request.form.get("test_email", "").strip()
            if test_email:
                success, msg = send_email(
                    test_email,
                    "Transaction Review Tool - Test Email",
                    "<h2>Test Email</h2><p>This is a test email from Transaction Review Tool.</p><p>If you received this, your SMTP configuration is working correctly!</p>",
                    "Test Email\n\nThis is a test email from Transaction Review Tool.\n\nIf you received this, your SMTP configuration is working correctly!",
                    blocking=True,
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
        "use_oauth": cfg_get("cfg_smtp_use_oauth", False, bool),
        "tenant_id": cfg_get("cfg_smtp_tenant_id", "", str),
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
    
    where = ["created_at >= CURRENT_TIMESTAMP - make_interval(days => ?)"]
    params = [days]
    
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


# ---------- Admin: Usage Report ----------
@app.route("/admin/usage-report")
@admin_required
def admin_usage_report():
    """Usage report: statements uploaded, rules fired, by user type and month."""
    ensure_users_table()
    db = get_db()

    # Statement uploads per user per month
    upload_rows = db.execute("""
        SELECT
            u.username, u.user_type,
            TO_CHAR(s.uploaded_at, 'YYYY-MM') AS month,
            COUNT(s.id) AS statement_count,
            COALESCE(SUM(s.record_count), 0) AS total_records
        FROM statements s
        JOIN users u ON u.id = s.uploaded_by
        GROUP BY u.username, u.user_type, TO_CHAR(s.uploaded_at, 'YYYY-MM')
        ORDER BY month DESC, u.user_type, u.username
    """).fetchall()

    # Alerts linked to uploaded statements (via customer + date range)
    alert_rows = db.execute("""
        SELECT
            u.username, u.user_type,
            TO_CHAR(s.uploaded_at, 'YYYY-MM') AS month,
            COUNT(a.id) AS alert_count,
            a.rule_tags
        FROM alerts a
        JOIN transactions t ON t.id = a.txn_id
        JOIN statements s ON s.customer_id = t.customer_id
            AND t.txn_date BETWEEN s.date_from AND s.date_to
        JOIN users u ON u.id = s.uploaded_by
        GROUP BY u.username, u.user_type, TO_CHAR(s.uploaded_at, 'YYYY-MM'), a.rule_tags
        ORDER BY month DESC
    """).fetchall()

    # Build structured report data
    from collections import defaultdict
    report = defaultdict(lambda: {
        "statements": 0, "records": 0, "alerts": 0, "rule_breakdown": defaultdict(int)
    })

    for r in upload_rows:
        key = (r["month"], r["username"], r["user_type"])
        report[key]["statements"] += r["statement_count"]
        report[key]["records"] += r["total_records"]

    for r in alert_rows:
        key = (r["month"], r["username"], r["user_type"])
        report[key]["alerts"] += r["alert_count"]
        if r["rule_tags"]:
            for tag in r["rule_tags"].split("|"):
                tag = tag.strip()
                if tag:
                    report[key]["rule_breakdown"][tag] += r["alert_count"]

    # Convert to sorted list for template
    report_list = []
    all_rule_types = set()
    def _usage_sort_key(item):
        month, username, user_type = item[0]
        # Sort by month descending, then user_type ascending, then username ascending
        # Invert month for descending: replace each char with its complement
        month_key = month or ""
        inverted_month = "".join(chr(255 - ord(c)) for c in month_key) if month_key else "~"
        return (inverted_month, user_type or "", username or "")
    for (month, username, user_type), data in sorted(report.items(), key=_usage_sort_key):
        avg_rules = round(data["alerts"] / data["statements"], 1) if data["statements"] else 0
        entry = {
            "month": month,
            "username": username,
            "user_type": user_type,
            "statements": data["statements"],
            "records": data["records"],
            "alerts": data["alerts"],
            "avg_rules_per_statement": avg_rules,
            "rule_breakdown": dict(data["rule_breakdown"]),
        }
        report_list.append(entry)
        all_rule_types.update(data["rule_breakdown"].keys())

    # Type-level summaries
    type_totals = defaultdict(lambda: {"statements": 0, "records": 0, "alerts": 0})
    for entry in report_list:
        tt = type_totals[entry["user_type"]]
        tt["statements"] += entry["statements"]
        tt["records"] += entry["records"]
        tt["alerts"] += entry["alerts"]
    for tt in type_totals.values():
        tt["avg_rules_per_statement"] = round(tt["alerts"] / tt["statements"], 1) if tt["statements"] else 0

    return render_template("admin_usage_report.html",
                          report=report_list,
                          type_totals=dict(type_totals),
                          all_rule_types=sorted(all_rule_types))


# ---------- Admin: Templates ----------
@app.route("/admin/templates", methods=["GET", "POST"])
@admin_required
def admin_templates():
    """Admin page to view and edit outreach question templates, outreach email template, and rationale template."""
    if request.method == "POST":
        action = request.form.get("action", "")
        user = get_current_user()

        if action == "save_questions":
            bank = {}
            tags = request.form.getlist("tag")
            for tag in tags:
                raw = request.form.get(f"questions_{tag}", "").strip()
                if raw:
                    bank[tag] = [q.strip() for q in raw.split("\n") if q.strip()]
            cfg_set("tpl_question_bank", json.dumps(bank))
            log_audit_event(
                event_type="TEMPLATE_EDIT",
                user_id=user["id"] if user else None,
                username=user.get("username") if user else None,
                details=json.dumps({"template": "question_bank"}),
            )
            flash("Outreach question templates saved.")

        elif action == "save_outreach_email":
            tpl = {
                "subject": request.form.get("email_subject", "").strip(),
                "greeting": request.form.get("email_greeting", "").strip(),
                "intro": request.form.get("email_intro", "").strip(),
                "questions_header": request.form.get("email_questions_header", "").strip(),
                "closing": request.form.get("email_closing", "").strip(),
                "sign_off": request.form.get("email_sign_off", "").strip(),
            }
            cfg_set("tpl_outreach_email", json.dumps(tpl))
            log_audit_event(
                event_type="TEMPLATE_EDIT",
                user_id=user["id"] if user else None,
                username=user.get("username") if user else None,
                details=json.dumps({"template": "outreach_email"}),
            )
            flash("Outreach email template saved.")

        elif action == "save_rationale":
            tpl = request.form.get("rationale_template", "").strip()
            cfg_set("tpl_rationale_structure", tpl)
            log_audit_event(
                event_type="TEMPLATE_EDIT",
                user_id=user["id"] if user else None,
                username=user.get("username") if user else None,
                details=json.dumps({"template": "rationale_structure"}),
            )
            flash("Rationale output template saved.")

        elif action == "reset_questions":
            cfg_set("tpl_question_bank", "")
            flash("Question templates reset to defaults.")

        elif action == "reset_outreach_email":
            cfg_set("tpl_outreach_email", "")
            flash("Outreach email template reset to defaults.")

        elif action == "reset_rationale":
            cfg_set("tpl_rationale_structure", "")
            flash("Rationale template reset to defaults.")

        return redirect(url_for("admin_templates"))

    # GET: load current values
    question_bank = ai_question_bank()
    email_tpl = _get_outreach_email_template()
    rationale_tpl = cfg_get("tpl_rationale_structure", None) or ""

    return render_template("admin_templates.html",
        question_bank=question_bank,
        email_tpl=email_tpl,
        rationale_tpl=rationale_tpl,
    )


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
        "cfg_ai_model":             str(cfg_get("cfg_ai_model", "gemini-2.0-flash")),
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
    cfg_set("cfg_ai_model", (request.form.get("cfg_ai_model") or "gemini-2.0-flash").strip())

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


def _month_bounds_for(date_str):
    if isinstance(date_str, datetime):
        d = date_str.date()
    elif isinstance(date_str, date):
        d = date_str
    else:
        d = date.fromisoformat(str(date_str)[:10])
    start = d.replace(day=1)
    # end of month
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
    return start.isoformat(), end.isoformat()

def _expected_vs_actual_month(customer_id: str, direction: str, any_date: str):
    """Return (expected_avg, actual_y, ym_label) for the month containing any_date."""
    db = get_db()
    start, end = _month_bounds_for(any_date)
    # Actual month sum for that direction
    y = float(db.execute(
        "SELECT SUM(base_amount) s FROM transactions "
        "WHERE customer_id=? AND direction=? AND txn_date BETWEEN ? AND ?",
        (customer_id, direction.lower(), start, end)
    ).fetchone()["s"] or 0.0)
    # Dynamic baseline: average of all other months
    month_rows = db.execute(
        """SELECT TO_CHAR(txn_date, 'YYYY-MM-01') AS mstart, SUM(base_amount) AS total
           FROM transactions
           WHERE customer_id=? AND direction=?
           GROUP BY TO_CHAR(txn_date, 'YYYY-MM-01')""",
        (customer_id, direction.lower())
    ).fetchall()
    current_mstart = start[:10]
    other_totals = [float(r["total"]) for r in month_rows if r["mstart"] != current_mstart]
    x = (sum(other_totals) / len(other_totals)) if other_totals else 0.0
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
        return "We've seen a spike compared to your typical activity. What is the reason, and should we expect similar amounts going forward?"

    if tag == "EXPECTED_BREACH_OUT":
        return "Your outgoings are higher than your average. What is the reason, and should we expect this level to continue?"

    if tag == "EXPECTED_BREACH_IN":
        return "Your incomings are higher than your average. What is the reason, and should we expect this level to continue?"

    if tag == "NLP_RISK" or "narrative" in q or "documentation" in q:
        return "Please clarify the purpose of the payment(s) and your relationship with the payer/payee, and share any supporting documents (e.g., invoices/contracts)."

    if "relationship" in q or "party you made the payment to" in q:
        return "Please tell us who the payment(s) were to and your relationship with the recipient(s)."

    if tag in ("PROHIBITED_COUNTRY", "HIGH_RISK_COUNTRY"):
        return "Please confirm the reasons for these transactions."

    if tag == "STRUCTURING":
        return "Please can you tell us what these payments were for?"

    if tag == "FLOW_THROUGH":
        return "Please explain the purpose of these transactions and the nature of the relationship with the parties involved."

    if tag == "HIGH_VELOCITY":
        return "Please explain the nature of this activity."

    if tag == "DORMANCY_REACTIVATION":
        return "Please explain the reason for the renewed activity on this account."

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
            "account_name": s.get("account_name") or "",
        })
    norm.sort(key=lambda x: x["date"])

    # Determine account reference for the question (use the first available)
    _acct = next((n["account_name"] for n in norm if n["account_name"]), "")
    _acct_phrase = f" (account {_acct})" if _acct else ""

    def _fmt_date(d) -> str:
        from datetime import date as date_type
        if isinstance(d, (datetime, date_type)):
            dt = d
        else:
            dt = datetime.strptime(str(d), "%Y-%m-%d")
        day = dt.day
        suf = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        return f"{day}{suf} {dt.strftime('%B %Y')}"

    def _list_amount_dates(items):
        return ", ".join(f"£{i['amount']:,.2f} on {_fmt_date(i['date'])}" for i in items)

    closing = _closing_prompt_for_base_question(row.get("question"), tag)

    # ---- CASH_DAILY_BREACH (ignore country; focus on cash usage) ----
    if tag == "CASH_DAILY_BREACH":
        inc_cash = [i for i in norm if i["direction"] == "IN"  and (i.get("channel") or "").lower() == "cash"]
        out_cash = [i for i in norm if i["direction"] == "OUT" and (i.get("channel") or "").lower() == "cash"]
        # Fallback: if channel not present on source txns, treat all sources as cash (conservative)
        if not inc_cash and not out_cash:
            inc_cash = [i for i in norm if i["direction"] == "IN"]
            out_cash = [i for i in norm if i["direction"] == "OUT"]
        bits = []
        if inc_cash:
            bits.append(f"{len(inc_cash)} cash deposit{'s' if len(inc_cash)!=1 else ''} valued at {_list_amount_dates(inc_cash)}")
        if out_cash:
            bits.append(f"{len(out_cash)} cash withdrawal{'s' if len(out_cash)!=1 else ''} valued at {_list_amount_dates(out_cash)}")
        front = f"Our records show{_acct_phrase} " + " and ".join(bits) + "."
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- HISTORICAL_DEVIATION (spike vs median) ----
    if tag == "HISTORICAL_DEVIATION":
        # Use direction of the largest txn among sources
        spike = max(norm, key=lambda x: x["amount"])
        front = (f"Our records show{_acct_phrase} a higher-than-usual transaction of £{spike['amount']:,.2f} "
                 f"on {_fmt_date(spike['date'])}.")
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
        except Exception:
            ym_formatted = ym
        front = (f"Our records show{_acct_phrase} your {dir_word} in {ym_formatted} totalled £{y:,.2f}, "
                 f"compared to your average of £{x:,.2f}.")
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- NLP_RISK (surface risky terms; ask for purpose + relationship) ----
    if tag == "NLP_RISK":
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
        front = (f"Our records show{_acct_phrase} " + " and ".join(bits) + "." if bits else "We are reviewing recent activity.")
        total = len(inc) + len(out)
        payment_word = "this payment" if total == 1 else "these payments"
        s = f"{front} We'd like to understand {payment_word}. {closing}"
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
        front = f"Our records show{_acct_phrase} " + " and ".join(parts) + "."
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- STRUCTURING (transactions of similar amounts) ----
    if tag == "STRUCTURING":
        amounts = sorted(norm, key=lambda x: x["amount"], reverse=True)
        front = (f"Our records show{_acct_phrase} {len(amounts)} transaction{'s' if len(amounts)!=1 else ''} "
                 f"of similar amounts, valued at {_list_amount_dates(amounts)}.")
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- FLOW_THROUGH (funds in then out within short window) ----
    if tag == "FLOW_THROUGH":
        inc = [i for i in norm if i["direction"] == "IN"]
        out = [i for i in norm if i["direction"] == "OUT"]
        bits = []
        if inc:
            verb = "was received" if len(inc) == 1 else "were received"
            bits.append(f"{len(inc)} transaction{'s' if len(inc)!=1 else ''} {verb} valued at {_list_amount_dates(inc)}")
        if out:
            verb = "was sent" if len(out) == 1 else "were sent"
            bits.append(f"{len(out)} transaction{'s' if len(out)!=1 else ''} {verb} valued at {_list_amount_dates(out)}")
        front = f"Our records show{_acct_phrase} " + " and ".join(bits) + " within a short period."
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- HIGH_VELOCITY (high frequency of transactions) ----
    if tag == "HIGH_VELOCITY":
        total_amt = sum(i["amount"] for i in norm)
        date_range = f"between {_fmt_date(norm[0]['date'])} and {_fmt_date(norm[-1]['date'])}" if len(norm) > 1 else f"on {_fmt_date(norm[0]['date'])}"
        front = (f"Our records show{_acct_phrase} {len(norm)} transactions totalling £{total_amt:,.2f} "
                 f"{date_range}, which represents a higher-than-usual level of activity.")
        s = f"{front} {closing}"
        return s if s.endswith("?") else s.rstrip('.') + "?"

    # ---- DORMANCY_REACTIVATION (account inactive then resumed) ----
    if tag == "DORMANCY_REACTIVATION":
        total_amt = sum(i["amount"] for i in norm)
        front = (f"Our records show{_acct_phrase} that after an extended period of inactivity, "
                 f"{len(norm)} transaction{'s' if len(norm)!=1 else ''} totalling £{total_amt:,.2f} "
                 f"{'have' if len(norm)!=1 else 'has'} recently been processed on your account.")
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
    front = f"Our records show{_acct_phrase} " + " and ".join(bits) + "."
    s = f"{front} {closing}"
    return s if s.endswith("?") else s.rstrip('.') + "?"

# ---------- AI route (with outreach support) ----------

def _default_outreach_email_template():
    """Built-in defaults for the outreach email template."""
    return {
        "subject": "Information request regarding recent account activity ({customer_id})",
        "greeting": "Dear Customer,",
        "intro": "We're reviewing recent activity on your account and would be grateful if you could provide further information to help us complete our checks.",
        "questions_header": "Please respond to the questions below:",
        "closing": "If you have any supporting documents (e.g., invoices or contracts), please include them.",
        "sign_off": "Kind regards,\nCompliance Team",
    }

def _get_outreach_email_template():
    """Return outreach email template, loading from DB config if available."""
    raw = cfg_get("tpl_outreach_email", None)
    if raw:
        try:
            tpl = json.loads(raw)
            if isinstance(tpl, dict) and tpl:
                defaults = _default_outreach_email_template()
                defaults.update(tpl)
                return defaults
        except (json.JSONDecodeError, TypeError):
            pass
    return _default_outreach_email_template()

def _build_outreach_email(customer_id: str, rows: list) -> str:
    """
    Build a plain-text outreach email using the customer-friendly questions.
    Questions marked as 'not required' are excluded from the email.
    """
    active_rows = [r for r in rows if not r.get("not_required")]

    tpl = _get_outreach_email_template()
    when = datetime.now().strftime("%d %B %Y")
    lines = []
    lines.append(f"Subject: {tpl['subject'].format(customer_id=customer_id)}")
    lines.append("")
    lines.append(tpl["greeting"])
    lines.append("")
    lines.append(tpl["intro"])
    lines.append("")
    lines.append(tpl["questions_header"])
    lines.append("")
    for i, r in enumerate(active_rows, start=1):
        q = (r.get("question_nice") or r.get("question") or "").strip()
        if q and not q.endswith("?"):
            q += "?"
        lines.append(f"{i}. {q}")
    lines.append("")
    lines.append(tpl["closing"])
    lines.append("")
    for sign_line in tpl["sign_off"].split("\n"):
        lines.append(sign_line)
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

    # remember the user's current customer for this browser session
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
        return render_template("ai.html", customer_id=None, period=period,
                               period_from=None, period_to=None, case=None,
                               answers=[], proposed_questions=[], params={},
                               outreach_text=None, country_full_name=None, no_customer=True)

    db = get_db()
    params = {
        "cfg_ai_use_llm": bool(cfg_get("cfg_ai_use_llm", False)),
        "cfg_ai_model":   str(cfg_get("cfg_ai_model", "gemini-2.0-flash")),
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
                tag_count = max(len(set(fired_tags)), len(base_questions), 6)
                final_questions = ai_normalise_questions_llm(cust, fired_tags, source_alerts, base_questions, max_count=tag_count)
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
                nr = request.values.get(f"nr_{qid}") == "1"
                nr_rationale = request.values.get(f"nr_rationale_{qid}", "").strip() if nr else ""
                ans = request.values.get(f"answer_{qid}", "")
                db.execute(
                    "UPDATE ai_answers SET answer=?, not_required=?, not_required_rationale=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (ans, nr, nr_rationale, qid),
                )
            db.execute("UPDATE ai_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (case_id,))
            db.commit()
            user = get_current_user()
            log_audit_event(
                event_type="OUTREACH_RESPONSES_SAVED",
                user_id=user["id"] if user else None,
                username=user.get("username") if user else None,
                details=json.dumps({"customer_id": cust, "case_id": case_id, "questions_count": len(request.values.getlist("qid"))}),
            )
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

def _format_date_uk(date_str) -> str:
    """Format YYYY-MM-DD as '1st January 2026' (UK style)."""
    try:
        from datetime import date as date_type
        if isinstance(date_str, (datetime, date_type)):
            dt = date_str
        else:
            dt = datetime.strptime(str(date_str), "%Y-%m-%d")
        day = dt.day
        suffix = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        return f"{day}{suffix} {dt.strftime('%B %Y')}"
    except Exception:
        return str(date_str)

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
    entity_type: Optional[str] = "company",
    nature_of_business: Optional[str] = None,
    est_income: Optional[float] = None,
    est_expenditure: Optional[float] = None,
) -> str:
    m = _customer_metrics(customer_id, p_from, p_to)
    case, answers = _answers_summary(customer_id)
    is_individual = (entity_type or "").lower() == "individual"
    review_date = datetime.now().strftime("%d %B %Y")

    def _period_text(pf, pt):
        if pf and pt:
            return f"{_format_date_uk(pf)} to {_format_date_uk(pt)}"
        return "all available data"

    period_txt = _period_text(p_from, p_to)
    months = int(m.get("period_months") or 1)

    # --- Plausibility scoring for outreach tone ---
    def _plausibility_score(ans, tag):
        if not ans: return 0
        a = ans.lower()
        s = 0
        # +detail
        if len(a) >= 80: s += 2
        if any(w in a for w in ["invoice","payroll","utilities","supplier","contract","order","shipment"]): s += 2
        if any(w in a for w in ["bank statement","receipt","evidence","documentation","proof"]): s += 2
        if any(w in a for w in ["gift","loan","family","friend"]): s += 1
        if any(w in a for w in ["awaiting","will provide","checking","confirming"]): s += 1
        # vagueness / hedging
        if any(w in a for w in ["don't know","no idea","can't remember","misc","various"]): s -= 3
        if any(w in a for w in ["just because","personal reasons"]): s -= 2
        if any(w in a for w in ["cash","cash deposit"]) and tag.upper() != "CASH_DAILY_BREACH": s -= 1
        # tag-specific alignment
        t = (tag or "").upper()
        if t == "PROHIBITED_COUNTRY" and any(w in a for w in ["russia","ru","sanction","export control"]): s += 1
        if t in ("HIGH_RISK_COUNTRY","HIGH_3RD") and any(w in a for w in ["third party","intermediary","agent"]): s += 1
        return s

    n_answers = 0
    plaus_scores = []
    if answers:
        for r in answers:
            ans = (r.get("answer") or "").strip()
            if ans:
                n_answers += 1
                plaus_scores.append(_plausibility_score(ans, r.get("tag") or ""))

    if n_answers:
        avg_p = sum(plaus_scores) / max(1, len(plaus_scores))
        if avg_p >= 3: outreach_tone = "Customer explanations appear broadly plausible and evidence-led."
        elif avg_p >= 1: outreach_tone = "Customer explanations provide some relevant detail; further corroboration may be appropriate."
        else: outreach_tone = "Customer explanations lack sufficient detail and require clarification."
    else:
        outreach_tone = "Outreach questions prepared; responses currently awaited."

    avg_monthly_in  = (m.get("total_in") or 0.0) / months
    avg_monthly_out = (m.get("total_out") or 0.0) / months

    # --- Helper: get answer for a specific tag ---
    def _answer_for_tag(tag_name):
        if not answers: return ""
        tag_answers = [r for r in answers if (r.get("tag") or "").upper() == tag_name.upper()]
        return (tag_answers[0].get("answer") or "").strip() if tag_answers else ""

    # --- Helper: documentation heuristic ---
    def _doc_status(answer_txt):
        if not answer_txt: return ""
        al = answer_txt.lower()
        doc_words = ["invoice","contract","agreement","evidence","documentation","proof","bank statement","receipt","attached","enclosed"]
        neg_words = ["no ","not ","haven't ","hasn't ","without ","missing ","awaiting "]
        has_doc = any(w in al for w in doc_words)
        has_neg = any(n in al and any(w in al[al.find(n):al.find(n)+30] for w in doc_words) for n in neg_words)
        if has_doc and not has_neg: return "Supporting documentation referenced."
        if has_doc and has_neg: return "No supporting documentation provided."
        return ""

    # --- Helper: country query for jurisdictional tags ---
    def _country_detail_for_tag(rule_tag):
        qp = [customer_id]
        wh = f"a.customer_id=? AND a.rule_tags LIKE ?"
        qp.append(f'%{rule_tag}%')
        if p_from and p_to:
            wh += " AND t.txn_date BETWEEN ? AND ?"
            qp += [p_from, p_to]
        rows = get_db().execute(f"""
            SELECT t.country_iso2, COUNT(DISTINCT t.id) AS cnt, SUM(t.base_amount) AS val
            FROM alerts a JOIN transactions t ON t.id=a.txn_id
            WHERE {wh} GROUP BY t.country_iso2
        """, qp).fetchall()
        parts = []
        total_val = 0.0
        total_cnt = 0
        for r in rows:
            if r["country_iso2"]:
                cn = country_full_name(r["country_iso2"])
                parts.append(f"{cn} ({r['country_iso2']}): {r['cnt']} transaction(s), GBP {float(r['val'] or 0):,.2f}")
                total_val += float(r["val"] or 0)
                total_cnt += int(r["cnt"])
        return parts, total_cnt, total_val

    # --- Business alignment ---
    def _alignment_phrase():
        if is_individual: return None
        nob = (nature_of_business or "").strip().lower()
        if not nob: return None
        stop = {"and","the","of","for","to","with","a","an","in","on","ltd","plc","inc","co"}
        kws = sorted({w.strip(",./-()") for w in nob.split() if len(w) >= 4 and w not in stop})
        if not kws: return None
        rows = get_db().execute("""
            SELECT narrative FROM transactions
            WHERE customer_id=? AND (? IS NULL OR txn_date>=?) AND (? IS NULL OR txn_date<=?)
            LIMIT 5000
        """, (customer_id, p_from, p_from, p_to, p_to)).fetchall()
        total = len(rows)
        if total == 0: return None
        hits = sum(1 for r in rows if any(k in (r["narrative"] or "").lower() for k in kws))
        ratio = hits / total
        eg = ", ".join(kws[:3])
        if ratio >= 0.5:
            return f"   Most transactions ({ratio*100:.0f}%) reference terms consistent with the declared business (e.g. {eg})."
        if ratio >= 0.2:
            return f"   A minority of transactions ({ratio*100:.0f}%) reference business-aligned terms (e.g. {eg}); the remainder appear generic."
        return "   Transaction descriptions do not strongly indicate the declared business; consider corroborating with additional evidence."

    # --- Per-tag alert detail ---
    def _alert_detail_for_tag(tag_name, count):
        lines = []
        tag = tag_name.upper()

        if tag in ("PROHIBITED_COUNTRY", "HIGH_RISK_COUNTRY"):
            label = "prohibited" if tag == "PROHIBITED_COUNTRY" else "high-risk"
            parts, total_cnt, total_val = _country_detail_for_tag(tag)
            lines.append(f"       Transactions: {total_cnt} involving {label} jurisdiction(s)")
            lines.append(f"       Total value: GBP {total_val:,.2f}")
            if parts:
                for p in parts:
                    lines.append(f"         - {p}")

        elif tag == "CASH_DAILY_BREACH":
            lines.append(f"       Breach events: {count}")
            ci, co = float(m.get("cash_in") or 0), float(m.get("cash_out") or 0)
            lines.append(f"       Total cash activity in period: deposits GBP {ci:,.2f}, withdrawals GBP {co:,.2f}")

        elif tag == "HISTORICAL_DEVIATION":
            lines.append(f"       Transactions flagged: {count}")
            lines.append(f"       Largest credit: GBP {float(m.get('max_in') or 0):,.2f} (avg GBP {float(m.get('avg_in') or 0):,.2f})")
            lines.append(f"       Largest debit:  GBP {float(m.get('max_out') or 0):,.2f} (avg GBP {float(m.get('avg_out') or 0):,.2f})")

        elif tag == "NLP_RISK":
            lines.append(f"       Transactions flagged: {count}")
            lines.append("       Flagged due to narrative content analysis.")

        elif tag == "STRUCTURING":
            lines.append(f"       Transactions flagged: {count}")
            lines.append("       Pattern of transactions at similar amounts just below reporting threshold detected.")

        elif tag == "FLOW_THROUGH":
            lines.append(f"       Transactions flagged: {count}")
            lines.append("       Funds received and sent within a short period in matching amounts.")

        elif tag == "DORMANCY_REACTIVATION":
            lines.append(f"       Transactions flagged: {count}")
            lines.append("       Significant transaction after a prolonged period of account inactivity.")

        elif tag == "HIGH_VELOCITY":
            lines.append(f"       Transactions flagged: {count}")
            lines.append("       High volume of transactions processed within a short timeframe.")

        elif tag in ("EXPECTED_BREACH_IN", "EXPECTED_BREACH_OUT"):
            direction = "incomings" if "IN" in tag else "outgoings"
            avg_val = avg_monthly_in if "IN" in tag else avg_monthly_out
            exp_val = float(m.get("expected_in") or 0) if "IN" in tag else float(m.get("expected_out") or 0)
            lines.append(f"       Monthly {direction} exceeded declared expectations.")
            if exp_val > 0:
                lines.append(f"       Actual avg: GBP {avg_val:,.0f} vs Expected: GBP {exp_val:,.0f}")

        else:
            lines.append(f"       Transactions flagged: {count}")

        # Customer response
        ans_txt = _answer_for_tag(tag_name)
        if ans_txt:
            lines.append(f"       Customer response: \"{ans_txt}\"")
            doc = _doc_status(ans_txt)
            if doc:
                lines.append(f"       {doc}")
        else:
            lines.append("       No customer response received.")

        return lines

    # ===================================================================
    # CHECK FOR CUSTOM RATIONALE TEMPLATE
    # ===================================================================
    total_in = float(m.get("total_in") or 0)
    total_out = float(m.get("total_out") or 0)
    tags = dict(m.get("tag_counter") or {})
    alerts_line = f"{len(tags)} alert type(s) fired across {sum(tags.values())} transaction(s)." if tags else "No alerts were noted during the review period."

    # Build outreach status line
    outreach_status_line = ""
    qa_section_text = ""
    if answers:
        active_answers = [r for r in answers if not r.get("not_required")]
        answered_count = sum(1 for r in active_answers if (r.get("answer") or "").strip())
        outstanding_count = len(active_answers) - answered_count
        status_parts = []
        if answered_count:
            status_parts.append(f"{answered_count} of {len(active_answers)} responses received")
        if outstanding_count:
            status_parts.append(f"{outstanding_count} response(s) outstanding")
        if not status_parts:
            status_parts.append(f"{len(answers)} question(s) prepared; responses currently outstanding")
        outreach_status_line = f"Outreach status: {'; '.join(status_parts)}."
        # Build Q&A section text
        qa_lines = []
        for idx, r in enumerate(answers, 1):
            q = r.get("question", "")
            ans = (r.get("answer") or "").strip()
            qa_lines.append(f"Q{idx}: {q}")
            qa_lines.append(f"A{idx}: {ans if ans else '[No response received]'}")
        qa_section_text = "\n".join(qa_lines)

    custom_tpl = cfg_get("tpl_rationale_structure", None) or ""
    if custom_tpl.strip():
        replacements = {
            "{nature_of_business}": (nature_of_business or "").strip(),
            "{credits_total}": f"\u00a3{total_in:,.2f}",
            "{debits_total}": f"\u00a3{total_out:,.2f}",
            "{period}": period_txt,
            "{avg_monthly_credits}": f"\u00a3{avg_monthly_in:,.2f}",
            "{avg_monthly_debits}": f"\u00a3{avg_monthly_out:,.2f}",
            "{declared_income}": f"\u00a3{est_income:,.2f}" if est_income else "Not specified",
            "{declared_expenditure}": f"\u00a3{est_expenditure:,.2f}" if est_expenditure else "Not specified",
            "{alerts}": alerts_line,
            "{outreach_status}": outreach_status_line,
            "{qa_section}": qa_section_text,
        }
        result = custom_tpl
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)
        return result

    # ===================================================================
    # COMPOSE STRUCTURED RATIONALE (default 9-section format)
    # ===================================================================
    out = []

    # --- Header ---
    out.append("=" * 80)
    out.append("                     TRANSACTION REVIEW RATIONALE")
    out.append("=" * 80)
    out.append("")

    # --- 1. Review Overview ---
    out.append("1. REVIEW OVERVIEW")
    out.append(f"   Customer ID:     {customer_id}")
    out.append(f"   Entity Type:     {'Individual' if is_individual else 'Company'}")
    if not is_individual and nature_of_business:
        out.append(f"   Nature of Business: {nature_of_business.strip()}")
    out.append(f"   Review Period:   {period_txt} ({months} month{'s' if months != 1 else ''})")
    out.append(f"   Date of Review:  {review_date}")
    acct_names = m.get("account_names") or []
    if acct_names:
        out.append(f"   Accounts:        {len(acct_names)} ({', '.join(acct_names)})")
    out.append("")

    # --- 2. Transaction Summary ---
    out.append("2. TRANSACTION SUMMARY")
    n_total = int(m.get("n_total") or 0)
    n_in = int(m.get("n_in") or 0)
    n_out = int(m.get("n_out") or 0)
    out.append(f"   Total Transactions:    {n_total:,} ({n_in:,} credits, {n_out:,} debits)")
    out.append(f"   Total Credits:         GBP {float(m.get('total_in') or 0):,.2f}  (avg GBP {float(m.get('avg_in') or 0):,.2f}; largest GBP {float(m.get('max_in') or 0):,.2f})")
    out.append(f"   Total Debits:          GBP {float(m.get('total_out') or 0):,.2f}  (avg GBP {float(m.get('avg_out') or 0):,.2f}; largest GBP {float(m.get('max_out') or 0):,.2f})")
    n_cpty = int(m.get("n_counterparties") or 0)
    if n_cpty > 0:
        out.append(f"   Unique Counterparties: {n_cpty:,}")
    n_countries = int(m.get("n_countries") or 0)
    if n_countries > 0:
        country_codes = list((m.get("country_breakdown") or {}).keys())
        out.append(f"   Distinct Countries:    {n_countries} ({', '.join(country_codes[:10])})")
    out.append("")

    # --- 3. Cash Activity ---
    out.append("3. CASH ACTIVITY")
    ci, co = float(m.get("cash_in") or 0), float(m.get("cash_out") or 0)
    if ci == 0 and co == 0:
        out.append("   No cash usage recorded during the review period.")
    else:
        out.append(f"   Cash Deposits:     GBP {ci:,.2f}")
        out.append(f"   Cash Withdrawals:  GBP {co:,.2f}")
    out.append("")

    # --- 4. Overseas & High-Risk Activity ---
    out.append("4. OVERSEAS & HIGH-RISK ACTIVITY")
    ov = float(m.get("overseas") or 0)
    hr = float(m.get("hr_val") or 0)
    if ov == 0:
        out.append("   No overseas transactions recorded during the review period.")
    else:
        out.append(f"   Overseas Activity:   {float(m.get('overseas_pct') or 0):.1f}% of total value (GBP {ov:,.2f})")
    if hr == 0:
        out.append("   No transactions through high-risk or prohibited corridors.")
    else:
        out.append(f"   High-Risk Corridors: {float(m.get('hr_pct') or 0):.1f}% of total value (GBP {hr:,.2f})")
    # Country breakdown
    cbd = m.get("country_breakdown") or {}
    non_gb = {k: v for k, v in cbd.items() if k.upper() != "GB"}
    if non_gb:
        out.append("   Country Breakdown (non-GB):")
        for iso2, info in sorted(non_gb.items(), key=lambda x: x[1]["total_amount"], reverse=True):
            cn = country_full_name(iso2)
            out.append(f"     - {cn} ({iso2}): {info['count']} transaction(s), GBP {info['total_amount']:,.2f}")
    out.append("")

    # --- 5. Profile Alignment ---
    out.append("5. PROFILE ALIGNMENT")
    has_profile_data = False
    if est_income and est_income > 0:
        diff_pct = ((avg_monthly_in - est_income) / est_income) * 100
        if abs(diff_pct) <= 20: stance = "In line with estimate"
        elif diff_pct > 0: stance = f"Above estimate by {abs(diff_pct):.0f}%"
        else: stance = f"Below estimate by {abs(diff_pct):.0f}%"
        out.append(f"   Estimated Monthly Income:       GBP {est_income:,.0f}")
        out.append(f"   Actual Average Monthly Income:   GBP {avg_monthly_in:,.0f}")
        out.append(f"   Assessment: {stance}")
        out.append("")
        has_profile_data = True

    if est_expenditure and est_expenditure > 0:
        diff_pct = ((avg_monthly_out - est_expenditure) / est_expenditure) * 100
        if abs(diff_pct) <= 20: stance = "In line with estimate"
        elif diff_pct > 0: stance = f"Above estimate by {abs(diff_pct):.0f}%"
        else: stance = f"Below estimate by {abs(diff_pct):.0f}%"
        out.append(f"   Estimated Monthly Expenditure:       GBP {est_expenditure:,.0f}")
        out.append(f"   Actual Average Monthly Expenditure:   GBP {avg_monthly_out:,.0f}")
        out.append(f"   Assessment: {stance}")
        out.append("")
        has_profile_data = True

    if not is_individual:
        al = _alignment_phrase()
        if al:
            out.append(f"   Business Alignment:")
            out.append(al)
            has_profile_data = True

    if not has_profile_data:
        out.append("   No estimated income/expenditure provided for comparison.")
    out.append("")

    # --- 6. Alerts & Findings ---
    out.append("6. ALERTS & FINDINGS")
    tags = dict(m.get("tag_counter") or {})
    if not tags:
        out.append("   No alerts were noted during the review period.")
        out.append("   Activity appears consistent with the overall profile; no material anomalies identified.")
    else:
        total_alert_txns = sum(tags.values())
        out.append(f"   Total: {len(tags)} alert type(s) fired across {total_alert_txns} transaction(s).")
        out.append("")
        sub_idx = ord('a')
        for tag_name in sorted(tags.keys(), key=lambda t: tags[t], reverse=True):
            nice = tag_name.replace("_", " ").title()
            out.append(f"   {chr(sub_idx)}. {nice}")
            detail = _alert_detail_for_tag(tag_name, tags[tag_name])
            out.extend(detail)
            out.append("")
            sub_idx += 1
    out.append("")

    # --- 7. Outreach Status ---
    out.append("7. OUTREACH STATUS")
    if answers:
        total_q = len(answers)
        nr_count = sum(1 for r in answers if r.get("not_required"))
        active_answers = [r for r in answers if not r.get("not_required")]
        answered = sum(1 for r in active_answers if (r.get("answer") or "").strip())
        outstanding = len(active_answers) - answered
        out.append(f"   Questions Sent:          {total_q}")
        if nr_count:
            out.append(f"   Excluded (Not Required): {nr_count}")
        out.append(f"   Responses Received:      {answered} of {len(active_answers)}")
        if outstanding > 0:
            out.append(f"   Responses Outstanding:   {outstanding}")
        out.append(f"   Assessment: {outreach_tone}")
    else:
        out.append("   No outreach questions have been prepared for this customer.")
    out.append("")

    # --- 8. Outreach Q&A ---
    # Marker used to strip Q&A from rationale when shown alongside separate Q&A display
    if answers:
        out.append("--- Outreach Questions & Responses ---")
        out.append("8. OUTREACH QUESTIONS & RESPONSES")
        for idx, r in enumerate(answers, 1):
            q = (r.get("question") or "").strip()
            tag = (r.get("tag") or "").upper()
            tag_nice = tag.replace("_", " ").title() if tag else "General"
            out.append(f"   Q{idx} ({tag_nice}): {q}")
            if r.get("not_required"):
                nr_rationale = (r.get("not_required_rationale") or "").strip()
                out.append(f"   A{idx}: [Not Required — excluded from outreach] Rationale: {nr_rationale or 'No rationale provided'}")
            else:
                ans = (r.get("answer") or "").strip()
                if ans:
                    doc = _doc_status(ans)
                    out.append(f"   A{idx}: {ans}{' [' + doc + ']' if doc else ''}")
                else:
                    out.append(f"   A{idx}: [No response received]")
            out.append("")

    # --- 9. Risk Assessment Conclusion ---
    section_num = 9 if answers else 8
    out.append(f"{section_num}. RISK ASSESSMENT CONCLUSION")
    conclusion_parts = []
    if not tags:
        conclusion_parts.append("No alert types were identified during the review period.")
        conclusion_parts.append("Transaction activity appears consistent with the declared profile.")
    else:
        conclusion_parts.append(f"{len(tags)} alert type(s) were identified across {sum(tags.values())} transaction(s).")
        if "PROHIBITED_COUNTRY" in tags:
            conclusion_parts.append("Transactions to prohibited jurisdictions require escalation and further review.")
        if answers:
            active_for_conclusion = [r for r in answers if not r.get("not_required")]
            answered = sum(1 for r in active_for_conclusion if (r.get("answer") or "").strip())
            if answered == len(active_for_conclusion):
                conclusion_parts.append("Customer outreach is complete; all questions have been answered.")
            elif answered > 0:
                conclusion_parts.append(f"Customer outreach is partially complete ({answered} of {len(active_for_conclusion)} responses received).")
            else:
                conclusion_parts.append("Customer outreach responses are currently outstanding.")
        conclusion_parts.append(outreach_tone)

    # Profile alignment conclusion
    if est_income and est_income > 0:
        in_diff = abs(((avg_monthly_in - est_income) / est_income) * 100)
        out_diff = abs(((avg_monthly_out - (est_expenditure or 0)) / max(est_expenditure or 1, 1)) * 100) if est_expenditure else 0
        if in_diff <= 20 and out_diff <= 20:
            conclusion_parts.append("Transaction volumes are broadly consistent with declared expectations.")
        else:
            conclusion_parts.append("Transaction volumes show deviation from declared expectations; further review recommended.")

    for cp in conclusion_parts:
        out.append(f"   {cp}")
    out.append("")
    out.append("=" * 80)

    return "\n".join(out)

from flask import session

from typing import Optional

@app.route("/ai-rationale", methods=["GET", "POST"])
@login_required
def ai_rationale():
    ensure_ai_rationale_table()  # your existing creator (with rationale_text + UNIQUE key)

    # Always read from values (works for both GET & POST)
    customer_id = (request.values.get("customer_id") or "").strip() or None
    period      = (request.values.get("period") or "all").strip()
    entity_type = (request.values.get("entity_type") or "company").strip()
    if entity_type not in ("company", "individual"):
        entity_type = "company"

    # Blank state: require a customer to be selected
    if not customer_id:
        return render_template("ai_rationale.html", customer_id=None, period=period,
                               entity_type="company",
                               metrics=None, nature_of_business="", est_income="",
                               est_expenditure="", rationale_text=None,
                               answers_preview=[], no_customer=True)

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

    # POST: reviewer confirmation (AGRA pen test - rationale sign-off audit trail)
    if request.method == "POST" and action == "confirm_review" and customer_id:
        confirmed = request.form.get("reviewer_confirmed") == "1"
        confirmed_type = request.form.get("confirmed_type", "consistent")
        db = get_db()
        user = get_current_user()
        if confirmed:
            db.execute("""
                UPDATE ai_rationales SET reviewer_confirmed=TRUE, reviewer_confirmed_by=%s,
                    reviewer_confirmed_at=CURRENT_TIMESTAMP, reviewer_confirmed_type=%s,
                    updated_at=CURRENT_TIMESTAMP
                WHERE customer_id=%s AND COALESCE(period_from,'')=COALESCE(%s,'') AND COALESCE(period_to,'')=COALESCE(%s,'')
            """, (user.get("username") if user else "Unknown", confirmed_type, customer_id, p_from, p_to))
        else:
            db.execute("""
                UPDATE ai_rationales SET reviewer_confirmed=FALSE, reviewer_confirmed_by=NULL,
                    reviewer_confirmed_at=NULL, reviewer_confirmed_type=NULL,
                    updated_at=CURRENT_TIMESTAMP
                WHERE customer_id=%s AND COALESCE(period_from,'')=COALESCE(%s,'') AND COALESCE(period_to,'')=COALESCE(%s,'')
            """, (customer_id, p_from, p_to))
        db.commit()
        log_audit_event(
            event_type="REVIEWER_CONFIRMATION",
            user_id=user["id"] if user else None,
            username=user.get("username") if user else None,
            details=json.dumps({"customer_id": customer_id, "confirmed": confirmed, "type": confirmed_type if confirmed else None}),
        )
        flash("Reviewer confirmation updated." if confirmed else "Reviewer confirmation removed.")
        return redirect(url_for("ai_rationale", customer_id=customer_id, period=period))

    # POST: save manual edits to rationale text with audit trail
    if request.method == "POST" and action == "save_edit" and customer_id:
        edited_text = request.form.get("rationale_text", "")
        existing = _load_rationale_row(customer_id, p_from, p_to)
        old_text = existing["rationale_text"] if existing else ""
        if edited_text != old_text:
            db = get_db()
            db.execute("""
                UPDATE ai_rationales SET rationale_text=%s, updated_at=CURRENT_TIMESTAMP
                WHERE customer_id=%s AND COALESCE(period_from,'')=COALESCE(%s,'') AND COALESCE(period_to,'')=COALESCE(%s,'')
            """, (edited_text, customer_id, p_from, p_to))
            db.commit()
            user = get_current_user()
            log_audit_event(
                event_type="RATIONALE_EDIT",
                user_id=user["id"] if user else None,
                username=user.get("username") if user else None,
                details=json.dumps({
                    "customer_id": customer_id,
                    "period_from": p_from,
                    "period_to": p_to,
                    "before": old_text,
                    "after": edited_text,
                }),
            )
            flash("Rationale saved.")
        return redirect(url_for("ai_rationale", customer_id=customer_id, period=period))

    # POST: generate + persist, then PRG redirect to avoid resubmits
    if request.method == "POST" and action == "generate" and customer_id:
        metrics = _customer_metrics(customer_id, p_from, p_to)
        rationale_text = build_rationale_text(
            customer_id=customer_id,
            p_from=p_from,
            p_to=p_to,
            entity_type=entity_type,
            nature_of_business=nature_of_business,
            est_income=est_income_num,
            est_expenditure=est_expenditure_num,
        )
        _upsert_rationale_row(
            customer_id=customer_id,
            p_from=p_from,
            p_to=p_to,
            entity_type=entity_type,
            nature_of_business=nature_of_business,
            est_income=est_income_num,
            est_expenditure=est_expenditure_num,
            rationale_text=rationale_text,
        )
        user = get_current_user()
        log_audit_event(
            event_type="RATIONALE_GENERATED",
            user_id=user["id"] if user else None,
            username=user.get("username") if user else None,
            details=json.dumps({
                "customer_id": customer_id,
                "entity_type": entity_type,
                "period_from": p_from,
                "period_to": p_to,
            }),
        )
        # Redirect with both params kept
        return redirect(url_for("ai_rationale", customer_id=customer_id, period=period))

    # GET: load saved state if we have a customer
    reviewer_confirmed = False
    reviewer_confirmed_by = None
    reviewer_confirmed_at = None
    reviewer_confirmed_type = None
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
            # Load saved entity_type if not explicitly set via query param
            if not request.values.get("entity_type") and row.get("entity_type"):
                entity_type = row["entity_type"]
            reviewer_confirmed = bool(row.get("reviewer_confirmed"))
            reviewer_confirmed_by = row.get("reviewer_confirmed_by")
            reviewer_confirmed_at = row.get("reviewer_confirmed_at")
            reviewer_confirmed_type = row.get("reviewer_confirmed_type")
        case, answers_preview = _answers_summary(customer_id)

    return render_template(
        "ai_rationale.html",
        customer_id=customer_id,
        period=period,
        entity_type=entity_type,
        metrics=metrics,
        nature_of_business=nature_of_business or "",
        est_income=est_income or "",
        est_expenditure=est_expenditure or "",
        rationale_text=rationale_text,
        answers_preview=answers_preview,
        reviewer_confirmed=reviewer_confirmed,
        reviewer_confirmed_by=reviewer_confirmed_by or "",
        reviewer_confirmed_at=reviewer_confirmed_at,
        reviewer_confirmed_type=reviewer_confirmed_type or "",
    )

@app.route("/explore")
@login_required
def explore():
    db = get_db()
    customer_id = request.args.get("customer_id","").strip()
    direction = request.args.get("direction","").strip()
    channel = request.args.get("channel","").strip()
    account = request.args.get("account","").strip()
    risk_param = request.args.get("risk","").strip()   # e.g. "HIGH,HIGH_3RD,PROHIBITED" or "HIGH"
    date_from = request.args.get("date_from","").strip()
    date_to = request.args.get("date_to","").strip()
    export = request.args.get("export","") == "csv"

    # Blank state: require a customer to be selected
    if not customer_id:
        return render_template("explore.html", rows=[], channels=[], accounts=[], no_customer=True)

    where, params = [], []
    join_risk = False

    where.append("t.customer_id = ?"); params.append(customer_id)
    if account:
        where.append("t.account_name = ?"); params.append(account)
    if direction in ("in","out"):
        where.append("t.direction = ?"); params.append(direction)
    if channel:
        where.append("lower(COALESCE(t.channel,'')) = ?"); params.append(channel.lower())

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

    join_clause = "JOIN ref_country_risk r ON r.iso2 = COALESCE(t.country_iso2, '')" if join_risk else ""
    where_clause = ("WHERE " + " AND ".join(where)) if where else ""

    sql = f"""
      SELECT t.id, t.txn_date, t.customer_id, t.direction, t.base_amount, t.currency,
             t.country_iso2, t.channel, t.payer_sort_code, t.payee_sort_code, t.narrative,
             t.account_name
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
    ch_rows = db.execute("SELECT DISTINCT lower(COALESCE(channel,'')) as ch FROM transactions ORDER BY ch").fetchall()
    channels = [r["ch"] for r in ch_rows if r["ch"]]

    return render_template("explore.html", rows=recs, channels=channels,
                           accounts=_get_accounts_for_customer(customer_id))

# ------- Rules table utilities (safe to add near other helpers) -------
def ensure_rules_table():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id BIGSERIAL PRIMARY KEY,
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
    cash_in  = _sum_q(f"SELECT SUM(base_amount) s FROM transactions {where} AND direction='in'  AND lower(COALESCE(channel,''))='cash'",  params)
    cash_out = _sum_q(f"SELECT SUM(base_amount) s FROM transactions {where} AND direction='out' AND lower(COALESCE(channel,''))='cash'", params)

    # Overseas (anything not GB and not NULL)
    overseas = _sum_q(f"""
        SELECT SUM(base_amount) s
          FROM transactions
         {where} AND COALESCE(country_iso2,'')<>'' AND UPPER(country_iso2)!='GB'
    """, params)
    total_val = total_in + total_out
    overseas_pct = (overseas / total_val * 100.0) if total_val else 0.0

    # High-risk / prohibited
    hr_val = _sum_q(f"""
        SELECT SUM(t.base_amount) s
          FROM transactions t
          JOIN ref_country_risk r ON r.iso2 = COALESCE(t.country_iso2,'')
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

    # Enhanced metrics
    n_total = n_in + n_out

    # Distinct counterparties
    cpty_row = db.execute(f"""
        SELECT COUNT(DISTINCT counterparty_account_no) AS n
        FROM transactions {where}
        AND counterparty_account_no IS NOT NULL AND counterparty_account_no != ''
    """, params).fetchone()
    n_counterparties = int(cpty_row["n"] or 0)

    # Country breakdown
    country_rows = db.execute(f"""
        SELECT country_iso2, COUNT(*) AS cnt, SUM(base_amount) AS total_amt
        FROM transactions {where}
        AND COALESCE(country_iso2, '') != ''
        GROUP BY country_iso2
        ORDER BY total_amt DESC
    """, params).fetchall()
    n_countries = len(country_rows)
    country_breakdown = {
        r["country_iso2"]: {"count": int(r["cnt"]), "total_amount": float(r["total_amt"] or 0)}
        for r in country_rows
    }

    # Distinct accounts
    acct_rows = db.execute(f"""
        SELECT DISTINCT account_name FROM transactions {where}
        AND account_name IS NOT NULL AND account_name != ''
        ORDER BY account_name
    """, params).fetchall()
    account_names = [r["account_name"] for r in acct_rows]
    n_accounts = len(account_names)

    # Period months
    period_months = 1
    if p_from and p_to:
        try:
            d1 = date.fromisoformat(p_from)
            d2 = date.fromisoformat(p_to)
            period_months = max(1, round((d2 - d1).days / 30))
        except Exception:
            pass

    return {
        "total_in": total_in, "total_out": total_out,
        "n_in": n_in, "n_out": n_out, "n_total": n_total,
        "avg_in": avg_in, "avg_out": avg_out,
        "max_in": max_in, "max_out": max_out,
        "cash_in": cash_in, "cash_out": cash_out,
        "overseas": overseas, "overseas_pct": overseas_pct,
        "hr_val": hr_val, "hr_pct": hr_pct,
        "n_counterparties": n_counterparties,
        "n_countries": n_countries, "country_breakdown": country_breakdown,
        "n_accounts": n_accounts, "account_names": account_names,
        "period_months": period_months,
        "alerts": [dict(a) for a in alerts],
        "tag_counter": tag_counter,
        "expected_in": exp_in, "expected_out": exp_out,
    }


def _answers_summary(customer_id: str):
    """
    Pull latest AI case answers and summarise whether they're answered.
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
        category = (request.form.get("new_category") or "").strip()
        if term and not any(t for t in items if (t.get("term") or "").lower() == term.lower()):
            items.append({"term": term, "enabled": True, "category": category})
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

@app.post("/admin/keywords-bulk")
@admin_required
def admin_keywords_bulk():
    """Bulk import keywords from Excel/CSV or wipe all keywords."""
    action = request.form.get("action", "").lower()

    if action == "wipe":
        cfg_set("cfg_risky_terms2", [])
        flash("All keywords wiped.")
        return redirect(url_for("admin") + "#keyword-library")

    if action != "import":
        flash("Unknown action.")
        return redirect(url_for("admin") + "#keyword-library")

    file = request.files.get("keywords_file")
    if not file or not file.filename:
        flash("Please select a file to upload.")
        return redirect(url_for("admin") + "#keyword-library")

    fname = file.filename.lower()
    if not fname.endswith((".xlsx", ".xls", ".csv")):
        flash("Please upload an Excel (.xlsx) or CSV (.csv) file.")
        return redirect(url_for("admin") + "#keyword-library")

    try:
        import pandas as pd
    except ImportError:
        flash("pandas is required. Install with: pip install pandas openpyxl")
        return redirect(url_for("admin") + "#keyword-library")

    try:
        if fname.endswith(".csv"):
            file.seek(0)
            df = pd.read_csv(file)
        else:
            # Read the primary import sheet
            try:
                df = pd.read_excel(file, sheet_name="App Import Format")
            except Exception:
                file.seek(0)
                try:
                    df = pd.read_excel(file, sheet_name=0)
                except Exception as e:
                    flash(f"Failed to read Excel: {e}")
                    return redirect(url_for("admin") + "#keyword-library")

        df.columns = [str(c).strip().lower() for c in df.columns]
        if "term" not in df.columns:
            for c in df.columns:
                if c in ("keyword", "keywords", "word", "phrase"):
                    df = df.rename(columns={c: "term"})
                    break
        if "term" not in df.columns:
            flash(f"File must contain a 'term' column. Found columns: {', '.join(df.columns)}")
            return redirect(url_for("admin") + "#keyword-library")

        # Try to read category mapping from 'Keyword Library' sheet (Excel only)
        category_map = {}
        if not fname.endswith(".csv"):
            try:
                file.seek(0)
                df_lib = pd.read_excel(file, sheet_name="Keyword Library")
                df_lib.columns = [str(c).strip().lower() for c in df_lib.columns]
                kw_col = "keyword" if "keyword" in df_lib.columns else "term"
                cat_col = "category" if "category" in df_lib.columns else None
                if kw_col in df_lib.columns and cat_col:
                    for _, row in df_lib.iterrows():
                        kw = str(row.get(kw_col, "")).strip().lower()
                        cat = str(row.get(cat_col, "")).strip()
                        if kw and cat and cat != "nan":
                            category_map[kw] = cat
            except Exception:
                pass  # No category sheet; categories will be empty

        # Build keyword list
        mode = request.form.get("mode", "merge")
        existing = cfg_get("cfg_risky_terms2", [], list) if mode == "merge" else []
        existing_lower = {(i.get("term") or "").lower() for i in existing if isinstance(i, dict)}

        imported = 0
        auto_disabled = 0
        skipped = 0

        for _, row in df.iterrows():
            term = str(row.get("term", "")).strip()
            if not term or term.lower() == "nan":
                continue
            if term.lower() in existing_lower:
                skipped += 1
                continue

            raw_en = row.get("enabled", True)
            if isinstance(raw_en, str):
                enabled = raw_en.strip().lower() in ("true", "1", "yes", "on")
            else:
                enabled = bool(raw_en) if not pd.isna(raw_en) else True

            if should_auto_disable(term):
                enabled = False
                auto_disabled += 1

            cat = category_map.get(term.lower(), "")
            existing.append({"term": term, "enabled": enabled, "category": cat})
            existing_lower.add(term.lower())
            imported += 1

        cfg_set("cfg_risky_terms2", existing)

        parts = [f"Imported {imported} keyword(s)"]
        if auto_disabled:
            parts.append(f"{auto_disabled} auto-disabled (short/common)")
        if skipped:
            parts.append(f"{skipped} duplicates skipped")
        cats = {i.get("category") for i in existing if i.get("category")}
        if cats:
            parts.append(f"{len(cats)} categories")
        flash(". ".join(parts) + ".")

    except Exception as e:
        app.logger.error(f"Keyword bulk import failed: {e}", exc_info=True)
        flash(f"Keyword import failed: {e}")

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

    n_stmts = db.execute("SELECT COUNT(*) c FROM statements").fetchone()["c"]

    # Delete dependents first
    db.execute("DELETE FROM alerts;")
    db.execute("DELETE FROM transactions;")
    db.execute("DELETE FROM statements;")

    # Optional: clear AI working tables if you like
    try:
        db.execute("DELETE FROM ai_answers;")
        db.execute("DELETE FROM ai_cases;")
    except psycopg2.Error:
        pass

    db.commit()
    try:
        db.execute("ANALYZE;")
    except psycopg2.Error:
        pass

    flash(f"Wiped {n_tx} transactions, {n_alerts} alerts, and {n_stmts} statements. Any AI cases/answers were cleared.")
    return redirect(url_for("admin") + "#danger")

@app.route("/sample/<path:name>")
def download_sample(name):
    return send_from_directory(DATA_DIR, name, as_attachment=True)


# --- PDF Report Generation ---
from xml.sax.saxutils import escape as xml_escape
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
            from datetime import date as date_type
            if isinstance(d, datetime):
                if d.hour == 0 and d.minute == 0 and d.second == 0:
                    return d.strftime('%d/%m/%Y')
                return d.strftime('%d/%m/%Y %H:%M')
            if isinstance(d, date_type):
                return d.strftime('%d/%m/%Y')
            s = str(d)
            dt = datetime.fromisoformat(s) if 'T' in s or len(s) > 10 else datetime.strptime(s[:10], '%Y-%m-%d')
            if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
                return dt.strftime('%d/%m/%Y')
            return dt.strftime('%d/%m/%Y %H:%M')
        except Exception:
            return str(d)

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
        SELECT nature_of_business, est_income, est_expenditure,
               reviewer_confirmed, reviewer_confirmed_by, reviewer_confirmed_at, reviewer_confirmed_type
        FROM ai_rationales
        WHERE customer_id = ?
        ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    # Helper to safely get values from row dict-like objects
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
            SUM(CASE WHEN direction='in' AND lower(COALESCE(channel,''))='cash' THEN base_amount ELSE 0 END) as cash_in,
            SUM(CASE WHEN direction='out' AND lower(COALESCE(channel,''))='cash' THEN base_amount ELSE 0 END) as cash_out,
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
        except Exception:
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
            SELECT tag, question, answer, not_required, not_required_rationale
            FROM ai_answers WHERE case_id = ? ORDER BY id
        """, (case['id'],)).fetchall()

        if answers:
            answered = sum(1 for a in answers if (a['answer'] or '').strip() and not a.get('not_required'))
            not_req = sum(1 for a in answers if a.get('not_required'))
            active = [a for a in answers if not a.get('not_required')]
            outstanding = len(active) - answered

            elements.append(Paragraph(
                f"Questions Prepared: {len(answers)} | Answered: {answered} | Not Required: {not_req} | Outstanding: {outstanding}",
                styles['BodyTextJustified']))
            elements.append(Spacer(1, 2*mm))

            for idx, ans in enumerate(answers, 1):
                tag = xml_escape((ans['tag'] or '').replace('_', ' ').title())
                question = xml_escape(ans['question'] or '')
                answer = ans['answer'] or ''

                elements.append(Paragraph(f"<b>Q{idx} ({tag}):</b> {question}", styles['BodyTextJustified']))

                if ans.get('not_required'):
                    nr_rationale = xml_escape((ans.get('not_required_rationale') or '').strip())
                    nr_text = f"<b>A{idx}:</b> <i>[Not Required]</i>"
                    if nr_rationale:
                        nr_text += f" — Rationale: <i>{nr_rationale}</i>"
                    elements.append(Paragraph(nr_text, styles['SmallText']))
                elif answer.strip():
                    elements.append(Paragraph(f"<b>A{idx}:</b> {xml_escape(answer)}", styles['BodyTextJustified']))
                else:
                    elements.append(Paragraph(f"<b>A{idx}:</b> <i>[No response received]</i>", styles['SmallText']))

                elements.append(Spacer(1, 2*mm))
        else:
            elements.append(Paragraph("No outreach questions have been sent for this customer.", styles['BodyTextJustified']))
    else:
        elements.append(Paragraph("No outreach case exists for this customer.", styles['BodyTextJustified']))
    
    elements.append(Spacer(1, 4*mm))
    
    # --- Section 6: Reviewer Confirmation ---
    elements.append(Paragraph("6. REVIEWER CONFIRMATION", styles['SectionHeader']))

    reviewer_confirmed = bool(safe_get(rationale_row, 'reviewer_confirmed')) if rationale_row else False
    reviewer_confirmed_type = (safe_get(rationale_row, 'reviewer_confirmed_type') or 'consistent') if rationale_row else 'consistent'
    if reviewer_confirmed:
        confirmed_by = safe_get(rationale_row, 'reviewer_confirmed_by') or 'Unknown'
        confirmed_at = safe_get(rationale_row, 'reviewer_confirmed_at')
        confirmed_date_str = 'N/A'
        if confirmed_at:
            try:
                if isinstance(confirmed_at, str):
                    confirmed_at = datetime.strptime(confirmed_at[:19], '%Y-%m-%d %H:%M:%S')
                confirmed_date_str = confirmed_at.strftime('%d/%m/%Y at %H:%M')
            except Exception:
                confirmed_date_str = str(confirmed_at)

        if reviewer_confirmed_type == 'inconsistent':
            confirm_text = 'Customer activity appears inconsistent with the customer profile'
            confirm_color = colors.HexColor('#dc3545')
        else:
            confirm_text = 'Customer activity is consistent with the customer profile'
            confirm_color = colors.HexColor('#198754')

        confirm_data = [
            ['Confirmation:', confirm_text],
            ['Confirmed By:', confirmed_by],
            ['Confirmed Date:', confirmed_date_str],
        ]
        confirm_table = Table(confirm_data, colWidths=[100, 340])
        confirm_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4a5568')),
            ('TEXTCOLOR', (1, 0), (1, 0), confirm_color),
            ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(confirm_table)
    else:
        elements.append(Paragraph(
            "<i>Reviewer has not yet confirmed whether customer activity is consistent with the customer profile.</i>",
            styles['SmallText']))

    elements.append(Spacer(1, 4*mm))

    # --- Section 7: Summary Comments ---
    elements.append(Paragraph("7. REVIEWER COMMENTS & CONCLUSION", styles['SectionHeader']))

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
    try:
        pdf_bytes = _generate_customer_report_pdf(customer_id, reviewer_name, summary_comments)
    except Exception as e:
        app.logger.error("PDF generation failed for %s: %s", customer_id, e)
        flash("Failed to generate PDF report. Please try again.", "danger")
        return redirect(url_for('report_preview', customer_id=customer_id))

    # Create filename
    filename = secure_filename(f"Transaction_Review_{customer_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

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
    
    # Helper to safely get values from row dict-like objects
    def safe_get(row, key, default=None):
        try:
            return row[key] if row and row[key] else default
        except (KeyError, IndexError):
            return default
    
    def format_uk_date(d):
        if not d:
            return 'N/A'
        try:
            from datetime import date as date_type
            if isinstance(d, datetime):
                if d.hour == 0 and d.minute == 0 and d.second == 0:
                    return d.strftime('%d/%m/%Y')
                return d.strftime('%d/%m/%Y %H:%M')
            if isinstance(d, date_type):
                return d.strftime('%d/%m/%Y')
            s = str(d)
            dt = datetime.fromisoformat(s) if 'T' in s or len(s) > 10 else datetime.strptime(s[:10], '%Y-%m-%d')
            if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
                return dt.strftime('%d/%m/%Y')
            return dt.strftime('%d/%m/%Y %H:%M')
        except Exception:
            return str(d)
    
    # Get transaction date range
    date_range = db.execute("""
        SELECT MIN(txn_date) as first_txn, MAX(txn_date) as last_txn, COUNT(*) as txn_count
        FROM transactions WHERE customer_id = ?
    """, (customer_id,)).fetchone()
    
    # Get KYC data
    kyc = db.execute("SELECT * FROM kyc_profile WHERE customer_id = ?", (customer_id,)).fetchone()
    
    # Get rationale data
    rationale = db.execute("""
        SELECT * FROM ai_rationales WHERE customer_id = ? ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()

    nature_of_business = safe_get(rationale, 'nature_of_business') or safe_get(kyc, 'nature_of_business', 'Not specified')
    est_income = safe_get(rationale, 'est_income') or safe_get(kyc, 'expected_monthly_in')
    est_expenditure = safe_get(rationale, 'est_expenditure') or safe_get(kyc, 'expected_monthly_out')
    rationale_text = safe_get(rationale, 'rationale_text', '')
    # Strip Q&A section from rationale — it's shown separately in Customer Outreach
    _qa_marker = "--- Outreach Questions & Responses ---"
    if rationale_text and _qa_marker in rationale_text:
        rationale_text = rationale_text[:rationale_text.index(_qa_marker)].rstrip()
    reviewer_confirmed = safe_get(rationale, 'reviewer_confirmed', 0)
    reviewer_confirmed_by = safe_get(rationale, 'reviewer_confirmed_by', '')
    reviewer_confirmed_at = safe_get(rationale, 'reviewer_confirmed_at', '')
    reviewer_confirmed_type = safe_get(rationale, 'reviewer_confirmed_type', '')
    
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
            SUM(CASE WHEN direction='in' AND lower(COALESCE(channel,''))='cash' THEN base_amount ELSE 0 END) as cash_in,
            SUM(CASE WHEN direction='out' AND lower(COALESCE(channel,''))='cash' THEN base_amount ELSE 0 END) as cash_out,
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
        except Exception:
            pass
    
    total_alerts = sum(r['cnt'] for r in severity_counts)
    
    # Get outreach Q&A
    case = db.execute("""
        SELECT * FROM ai_cases WHERE customer_id = ? ORDER BY updated_at DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    answers = []
    if case:
        answers = db.execute("""
            SELECT tag, question, answer, not_required, not_required_rationale
            FROM ai_answers WHERE case_id = ? ORDER BY id
        """, (case['id'],)).fetchall()

    answered_count = sum(1 for a in answers if (a['answer'] or '').strip() and not a.get('not_required')) if answers else 0
    not_required_count = sum(1 for a in answers if a.get('not_required')) if answers else 0
    active_answers = [a for a in answers if not a.get('not_required')]

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
        not_required_count=not_required_count,
        outstanding_count=len(active_answers) - answered_count if active_answers else 0,
        # Rationale
        rationale_text=rationale_text,
        reviewer_confirmed=reviewer_confirmed,
        reviewer_confirmed_by=reviewer_confirmed_by,
        reviewer_confirmed_at=reviewer_confirmed_at,
        reviewer_confirmed_type=reviewer_confirmed_type,
    )


if __name__ == "__main__":
    # All DB init/seed must run inside the Flask app context
    with app.app_context():
        init_db()
        ensure_default_parameters()
        ensure_ai_tables()
        ensure_ai_rationale_table()
        ensure_users_table()      # Create users table and seed admin user
        ensure_manager_roles()    # Migrate role constraint for manager roles
        ensure_password_reset_tokens()
        ensure_customers_table()  # Create customers table
        ensure_statements_table() # Create statements table
        ensure_audit_log_table()  # Create audit log table for security events
        
        # PostgreSQL connection is secure with credentials in environment
        print("✓ PostgreSQL database initialized successfully")
        
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