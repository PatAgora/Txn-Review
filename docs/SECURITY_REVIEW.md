# Security, Logging & Error Handling Review
**Application**: Transaction Review Tool  
**Review Date**: February 21, 2026  
**Reviewer Level**: Senior Developer

---

## CRITICAL ISSUES 🔴

### 1. **Open Redirect Vulnerability (CWE-601)**
**Location**: `app.py` lines 2809, 2879  
**Severity**: CRITICAL

```python
next_url = request.args.get("next") or url_for("dashboard")
return redirect(next_url)
```

**Risk**: Attacker can craft `/login?next=https://evil.com` to redirect authenticated users to malicious site.

**Fix Required**:
```python
from urllib.parse import urlparse, urljoin

def is_safe_url(url):
    """Validate redirect URL is relative or same origin."""
    if not url:
        return False
    parsed = urlparse(url)
    return not parsed.netloc or parsed.netloc == request.host

# In login function:
next_url = request.args.get("next")
if next_url and is_safe_url(next_url):
    return redirect(next_url)
return redirect(url_for("dashboard"))
```

---

### 2. **Database Error Logging with Sensitive Data (CWE-215)**
**Location**: `app.py` lines 62-64, 75-77

```python
except psycopg2.Error as e:
    print(f"Database error: {e}\nSQL: {sql}\nParams: {params}")
    raise
```

**Risk**: 
- SQL queries may contain customer names, transaction amounts, personal data
- Parameter arrays could expose secrets
- Prints to stdout visible in logs

**Fix Required**:
```python
except psycopg2.Error as e:
    # Log error without exposing data
    import logging
    logging.error(f"Database error occurred", exc_info=True)
    # Don't include SQL or params
    raise
```

---

### 3. **Silent Exception Swallowing (CWE-390)**
**Location**: `app.py` lines 215-243 (bootstrap function)

```python
@app.before_request
def _bootstrap_db_once():
    try:
        ensure_ai_tables()
    except Exception:
        pass  # ❌ Silent failure
```

**Risk**:
- Database initialization failures go unnoticed
- App may operate in broken state
- Impossible to debug issues
- Compliance/audit trail incomplete

**Fix Required**:
```python
@app.before_request
def _bootstrap_db_once():
    try:
        ensure_ai_tables()
    except Exception as e:
        app.logger.error(f"Failed to initialize AI tables: {e}", exc_info=True)
        # Optionally: raise or set app state flag
```

---

## HIGH SEVERITY ISSUES 🟠

### 4. **Incomplete Login Flow - Missing Return Statement**
**Location**: `app.py` line 2849

```python
def complete_login(user):
    # ... login setup code ...
    log_audit_event("LOGIN_SUCCESS", user["id"], user["username"])
    flash(f"Welcome, {user['username']}!")
    # ❌ Missing redirect!
```

**Impact**: Login flow doesn't redirect after setting session. Flow falls through to None return.

**Fix**: Add after line 2849:
```python
    return None  # Caller handles redirect, or restructure
```

---

### 5. **No Rate Limiting on Sensitive Operations**
**Location**: Login, password reset, 2FA setup  
**Severity**: HIGH

**Risk**:
- No brute force protection beyond account lockout
- Password reset could be abused
- No rate limiting per IP
- No API rate limiting

**Recommendation**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # ...
```

---

### 6. **Inadequate CSRF Protection Validation**
**Location**: `app.py` line 207

```python
form_token = request.form.get('csrf_token')
# ❌ Token is retrieved but no validation shown
```

**Risk**: CSRF token validation appears incomplete. Need to verify:
- Token exists before form processing
- Token is properly validated via Flask-WTF

**Recommendation**: Use Flask-WTF consistently:
```python
from flask_wtf.csrf import generate_csrf, validate_csrf

@app.route("/data", methods=["POST"])
def process_data():
    try:
        validate_csrf(request.form.get('csrf_token'))
    except Exception:
        abort(403)
```

---

## MEDIUM SEVERITY ISSUES 🟡

### 7. **Inconsistent Parameter Validation**
**Location**: Multiple routes throughout app.py

```python
# No consistent validation of input parameters
customer_id = request.args.get("customer_id", "").strip()
period = request.args.get("period", "all")  # ❌ Not whitelist validated
sev = request.args.get("severity").strip().upper()  # ❌ Still allows arbitrary values
```

**Risk**: SQL injection through unvalidated parameters (even with parameterized queries, business logic can break)

**Fix**:
```python
VALID_PERIODS = {"all", "1m", "3m", "6m", "1y"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

period = request.args.get("period", "all")
if period not in VALID_PERIODS:
    period = "all"  # Default to safe value

severity = request.args.get("severity", "").strip().upper()
if severity not in VALID_SEVERITIES:
    abort(400, "Invalid severity")
```

---

### 8. **Missing Logging Context**
**Location**: Throughout app.py  
**Severity**: MEDIUM

**Issues**:
- `log_audit_event()` is used inconsistently
- Some critical operations not logged (e.g., report generation, data exports)
- No structured logging (JSON formatted logs)
- No correlation IDs for request tracing

**Recommendation**:
```python
import logging
from logging.handlers import RotatingFileHandler

# Setup structured logging
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s'
)

handler = RotatingFileHandler('app.log', maxBytes=10485760, backupCount=10)
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# Add request context
@app.before_request
def before_request():
    g.request_id = uuid.uuid4().hex
    app.logger.info(f"Request started: {request.method} {request.path}")

@app.after_request
def after_request(response):
    app.logger.info(f"Request completed: {response.status_code}")
    return response
```

---

### 9. **Insufficient Error Handling in Async/Background Operations**
**Location**: SMTP operations, PDF generation  
**Severity**: MEDIUM

```python
def send_welcome_email(username, email, temp_password):
    try:
        msg = MIMEText(body)
        # ... smtp code ...
    except Exception as e:
        return False, str(e)  # ❌ Generic exception handling
```

**Risk**:
- SMTP exceptions could leak configuration details
- No timeout specification
- No retry logic
- Failed emails not tracked for re-delivery

---

### 10. **Default Credentials Hardcoded in Environment**
**Location**: `docker-compose.yml`  
**Severity**: MEDIUM

```yaml
POSTGRES_PASSWORD=tx_password  # ❌ Default password
```

**Risk**:
- Same credentials in all environments
- Configuration visible in source control
- No rotation mechanism

**Fix**:
```yaml
# Use .env file (added to .gitignore)
POSTGRES_PASSWORD=${DB_PASSWORD}  # Must be set externally
```

---

### 11. **No Input Sanitization for Display**
**Location**: Templates and dynamic content  
**Severity**: MEDIUM (XSS Risk)

```html
<!-- alerts.html and other templates -->
<td>{{ a.reasons }}</td>  <!-- If 'reasons' contains HTML, it would render -->
```

**While Jinja2 auto-escapes by default, explicit sanitization is better:**
```html
<td>{{ a.reasons | escape }}</td>
<!-- Or use dedicated XSS filter -->
```

---

## LOW SEVERITY ISSUES 🟢

### 12. **Hardcoded Salt in Encryption**
**Location**: `app.py` line 118

```python
salt=b'tx_review_tool_salt_v1',  # ❌ Static salt
```

**Impact**: Low (key_source provides entropy), but not best practice

**Better Approach**: Use random salt per key derivation or use a key management service

---

### 13. **No Session Security Configuration**
**Location**: Flask session configuration missing  
**Severity**: LOW

**Recommendation**:
```python
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JS access
    SESSION_COOKIE_SAMESITE='Strict', # CSRF protection
    PERMANENTLY_EXPIRES_AFTER=timedelta(hours=8)  # Session timeout
)
```

---

### 14. **Missing Security Headers Enhancements**
**Location**: `app.py` lines 273-308

**Missing Headers**:
- `Expect-CT`: Cert transparency
- `Content-Security-Policy-Report-Only`: For monitoring CSP violations
- `Vary: Accept-Encoding`: Cache optimization

---

## LOGGING GAPS 📋

### Critical Events NOT Logged:
- ❌ Report generation (audit trail requirement)
- ❌ Data exports/downloads
- ❌ Configuration changes
- ❌ Rule modifications
- ❌ 2FA disable
- ❌ Session timeout events
- ❌ Invalid CSRF attempts
- ❌ Permission denials

### Recommendation - Add Logging For:
```python
@login_required
@require_role("admin")
def download_report(customer_id):
    log_audit_event(
        "REPORT_DOWNLOADED",
        session["user_id"],
        session["username"],
        f"Downloaded report for customer {customer_id}"
    )
    # ... rest of function
```

---

## ERROR HANDLING SUMMARY 📊

### Current State:
- ✅ Database errors caught and logged
- ✅ Authentication failures logged
- ❌ Bootstrap errors silently swallowed
- ❌ Template rendering errors not captured
- ❌ File operation errors (CSV, PDF) not properly handled
- ❌ Network timeouts unhandled

### Recommendation - Global Error Handler:
```python
@app.errorhandler(Exception)
def handle_unexpected_error(error):
    app.logger.error(f"Unexpected error: {error}", exc_info=True)
    return render_template("error.html", 
        code=500, 
        message="An unexpected error occurred"
    ), 500

@app.errorhandler(404)
def handle_404(error):
    app.logger.warning(f"Page not found: {request.path}")
    return render_template("error.html", code=404), 404
```

---

## RECOMMENDATIONS PRIORITY

### Immediate (Next Release):
1. ✅ Fix open redirect vulnerability (lines 2809, 2879)
2. ✅ Remove database error logging with sensitive data (lines 62-64)
3. ✅ Add proper exception logging in bootstrap (lines 215-243)
4. ✅ Fix missing return in complete_login (line 2849)

### Short Term (Next Sprint):
5. Implement rate limiting on auth endpoints
6. Add proper CSRF validation with Flask-WTF
7. Add input validation whitelist for parameters
8. Add structured JSON logging
9. Set SESSION_COOKIE_SECURE and other session configs
10. Add security headers: Expect-CT, CSP-Report-Only

### Longer Term:
11. Implement request correlation IDs
12. Add security monitoring/alerting
13. Security audit logging dashboard
14. Secrets rotation mechanism
15. Key management service integration

---

## COMPLIANCE NOTES

**Current Status**:
- ✅ HSTS implemented (31536000 seconds)
- ✅ CSP headers set
- ✅ Password policy (CREST compliant)
- ✅ Audit logging for critical events
- ❌ **OPEN REDIRECT** must be fixed for PCI/GDPR compliance
- ❌ **SILENT FAILURES** violate audit requirements

---

## Testing Recommendations

```bash
# Run security scanner
zaproxy -cmd -quickurl http://localhost:8000
bandit -r app/

# Test open redirect
curl -i http://localhost:8000/login?next=https://evil.com

# Test rate limiting
for i in {1..10}; do curl -X POST http://localhost:8000/login; done
```

---

**Review Complete** | Critical fixes required before production deployment
