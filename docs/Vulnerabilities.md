# DVBank Lab - Vulnerability Documentation

This document details the intentional security vulnerabilities implemented in DVBank Lab for educational purposes.

⚠️ **WARNING**: These vulnerabilities are for educational purposes only. Never implement these patterns in production code.

## Table of Contents
1. [Authentication Issues](#1-authentication-issues)
2. [SQL Injection Vulnerabilities](#2-sql-injection-vulnerabilities)
3. [Input Validation Issues](#3-input-validation-issues)
4. [Information Disclosure](#4-information-disclosure)
5. [Authorization Flaws](#5-authorization-flaws)
6. [Session Management](#6-session-management)
7. [API Security Issues](#7-api-security-issues)
8. [Transaction Security](#8-transaction-security)
9. [Configuration Issues](#9-configuration-issues)
10. [Dependency Issues](#10-dependency-issues)
11. [Business Logic Flaws](#11-business-logic-flaws)
12. [Cross-Site Request Forgery (CSRF)](#12-cross-site-request-forgery-csrf)
13. [Clickjacking / Missing Security Headers](#13-clickjacking--missing-security-headers)
14. [Stored XSS via Receipt Page](#14-stored-xss-via-receipt-page)
15. [Unrestricted File Upload](#15-unrestricted-file-upload)
16. [JWT Algorithm-Confusion / none Bypass](#16-jwt-algorithm-confusion--none-bypass)
17. [Insecure Password Reset](#17-insecure-password-reset)
18. [Broken Access Control in Money Transfers](#18-broken-access-control-in-money-transfers)

## 1. Authentication Issues

### 1.1 Weak JWT Implementation
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: Using hardcoded secret and weak algorithm
token = jwt.encode(
    {'user_id': user[0]},
    'secret',  # Hardcoded secret
    algorithm='HS256'  # Weak algorithm choice
)

# Missing expiration time
# Missing algorithm enforcement
```

**Impact**: 
- Token forgery possible due to weak secret
- Tokens never expire
- Potential algorithm confusion attacks

### 1.2 Weak Password Storage
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: Using MD5 for password hashing
password_hash = hashlib.md5(password.encode()).hexdigest()
insert_query = f"INSERT INTO user (username, password_hash) VALUES ('{username}', '{password_hash}')"
```

**Impact**:
- MD5 is cryptographically broken
- Fast hash allows quick brute-force attacks
- No salt used in password hashing

## 2. SQL Injection Vulnerabilities

### 2.1 Login Query
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: Direct string interpolation
query = f"SELECT * FROM user WHERE username = '{username}'"
user = db.session.execute(query).fetchone()
```

### 2.2 User Registration
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: String concatenation in query
insert_query = f"INSERT INTO user (username, password_hash, balance) VALUES ('{username}', '{password_hash}', 0000.00)"
db.session.execute(insert_query)
```

**Impact**:
- Unauthorized data access
- Data manipulation
- Potential system compromise

## 3. Input Validation Issues

### 3.1 Transfer Amount Validation
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: Missing proper validation
@app.route('/api/transfer', methods=['POST'])
def transfer_money():
    amount = request.json.get('amount')
    to_user_id = request.json.get('to_user_id')
    # No validation on amount or user_id
    make_transfer(current_user.id, to_user_id, amount)
```

### 3.2 Profile Data Validation
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: No input sanitization
@app.route('/api/profile', methods=['PUT'])
def update_profile():
    data = request.get_json()
    current_user.set_profile(data)  # Raw data directly stored
```

**Impact**:
- Negative amount transfers possible

## 4. Information Disclosure

### 4.1 Stack Trace Exposure
**Location**: `backend/app.py`
```python
# Vulnerable: Exposing stack traces
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc()  # Exposing stack trace
    }), 500
```

### 4.2 Verbose Error Messages
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: Revealing sensitive information in errors
except InsufficientFundsError as e:
    return jsonify({
        'error': f'Insufficient funds. Current balance: {current_user.balance}'  # Exposing balance
    }), 400
```

**Impact**:
- Technical details exposed
- System information leaked
- Account information disclosed
- Attack surface information revealed

## 5. Authorization Flaws

### 5.1 IDOR in Profile Access
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: No ownership check
@app.route('/api/profile/<user_id>')
def get_profile(user_id):
    user = User.query.get(user_id)  # Any profile can be accessed
    return jsonify(user.get_profile())
```

### 5.2 Missing Transaction Authorization
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: Missing ownership validation
@app.route('/api/transactions/<transaction_id>')
def get_transaction(transaction_id):
    transaction = Transaction.query.get(transaction_id)  # No ownership check
    return jsonify(transaction.to_dict())
```

**Impact**:
- Unauthorized data access
- Horizontal privilege escalation
- Privacy violations
- Data leakage

## 6. Session Management

### 6.1 Insecure Token Storage
**Location**: `frontend/src/App.js`
```javascript
// Vulnerable: Using localStorage for token storage
localStorage.setItem('token', data.token);

// Token retrieval without validation
const token = localStorage.getItem('token');
```

### 6.2 Missing Session Controls
**Location**: `backend/auth.py`
```python
# Vulnerable: No session invalidation
@app.route('/api/logout')
def logout():
    # Token still valid after logout
    return jsonify({'message': 'Logged out'})
```

**Impact**:
- Token theft through XSS
- Session hijacking
- Persistent sessions after logout
- No protection against token reuse

## 7. API Security Issues

### 7.1 Missing Rate Limiting
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable: No rate limiting
@app.route('/api/login', methods=['POST'])
def login():
    # Can be called unlimited times
    username = request.json.get('username')
    password = request.json.get('password')
```

### 7.2 Missing Security Headers
**Location**: `backend/app.py`
```python
# Vulnerable: Missing security headers
app = Flask(__name__)
# No CSP, HSTS, or other security headers
```

**Impact**:
- Brute force attacks possible
- DoS vulnerability
- Missing browser protections
- Security policy bypass

## 8. Transaction Security

### 8.1 Race Conditions
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: Race condition in transfer
def transfer_money(from_user, to_user, amount):
    if from_user.balance >= amount:  # Race condition here
        from_user.balance -= amount
        to_user.balance += amount
        db.session.commit()
```

### 8.2 Missing Atomicity
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: No transaction atomicity
def process_transfer(from_id, to_id, amount):
    from_account = Account.query.get(from_id)
    from_account.balance -= amount  # Can fail after this
    to_account = Account.query.get(to_id)
    to_account.balance += amount
    db.session.commit()
```

**Impact**:
- Double spending possible
- Lost transactions
- Inconsistent balances
- Financial losses

## 9. Configuration Issues

### 9.1 Debug Mode
**Location**: `backend/app.py`
```python
# Vulnerable: Debug mode in production
app.run(debug=True)  # Exposing debug information
```

### 9.2 Hardcoded Credentials
**Location**: `backend/config.py`
```python
# Vulnerable: Hardcoded credentials
DATABASE_URL = "postgresql://admin:password@localhost/dvbank"
SECRET_KEY = "development-key-123"
```

**Impact**:
- Sensitive information exposure
- System compromise
- Configuration leaks
- Credential exposure

## 10. Dependency Issues

Current vulnerable dependencies identified by safety scan:

```
-> Vulnerability found in pyyaml version 5.3.1
   CVE-2020-14343: Arbitrary code execution
   
-> Vulnerability found in flask version 2.0.1
   CVE-2023-30861: Response data leakage
   
-> Vulnerability found in werkzeug version 2.0.1
   Multiple vulnerabilities including CVE-2024-34069
   
-> Vulnerability found in pyjwt version 2.1.0
   CVE-2024-53861: Issuer verification bypass
```

**Impact**:
- Known vulnerabilities
- Potential exploits
- Security bypasses
- System compromise

## 11. Business Logic Flaws

### 11.1 Transfer Validation
**Location**: `backend/routes/transaction_routes.py`
```python
# Vulnerable: Insufficient transfer validation
@app.route('/api/transfer', methods=['POST'])
def transfer():
    amount = float(request.json.get('amount'))
    recipient_id = request.json.get('to_user_id')
    
    # Missing validations:
    # - No minimum/maximum amount check
    # - No daily limit check
    # - No recipient validation
    # - No fraud detection
```

### 11.2 Balance Checks
**Location**: `backend/models.py`
```python
# Vulnerable: Missing balance validations
class Account(db.Model):
    def withdraw(self, amount):
        self.balance -= amount  # No minimum balance check
        # No overdraft protection
        # No transaction limits
```

**Impact**:
- Financial fraud possible
- Business rule bypass
- Monetary losses
- Regulatory compliance issues

## 12. Cross-Site Request Forgery (CSRF)

### 12.1 Cookie-Authenticated Transfer with No CSRF Token
**Location**: `backend/auth.py` (`cookie_auth`), `backend/routes/transaction_routes.py` (`/api/quickpay`), `backend/routes/auth_routes.py` (login cookie)
```python
# Login mirrors the JWT into a cookie with no SameSite/HttpOnly/Secure:
resp.set_cookie('session_token', token, httponly=False, secure=False)

# /api/quickpay authenticates from that cookie only and takes no CSRF token:
@transaction_bp.route('/api/quickpay', methods=['POST'])
@cookie_auth
def quickpay(current_user):
    to_user_id = request.form.get('to_user_id', ...)   # form-urlencoded -> cross-site form works
```
**Impact**:
- A malicious page can transfer money from any logged-in victim (no token theft).
- PoC: `docs/exploits/csrf_transfer.html`.

## 13. Clickjacking / Missing Security Headers

### 13.1 No X-Frame-Options / CSP
**Location**: `backend/app.py` (`after_request`)
```python
# Permissive CORS is set, but no X-Frame-Options, no Content-Security-Policy,
# no X-Content-Type-Options are ever sent.
```
**Impact**:
- The app can be framed and UI-redressed. PoC: `docs/exploits/clickjacking.html`.

## 14. Stored XSS via Receipt Page

### 14.1 Unescaped Memo in Server-Rendered Receipt
**Location**: `backend/routes/transaction_routes.py` (`/api/transactions/<id>/receipt`)
```python
def transaction_receipt(transaction_id):     # no auth, no ownership check (also IDOR)
    html = f"""... <p><b>Memo:</b> {transaction.description or ''}</p> ..."""
    return html                               # user-controlled memo interpolated raw
```
**Impact**:
- Stored XSS executes in any viewer; steals the non-HttpOnly cookie / localStorage token.
- IDOR: any receipt id is viewable without authentication.

## 15. Unrestricted File Upload

### 15.1 No Type/Size Validation, Raw Filename, Served Inline
**Location**: `backend/routes/upload_routes.py`
```python
filename = uploaded.filename or 'upload.bin'   # raw client name -> ../ traversal
dest = os.path.join(UPLOAD_DIR, filename)      # no extension/type/size checks
uploaded.save(dest)
return Response(data, content_type=mimetypes.guess_type(full_path)[0] or '...')  # SVG/HTML runs
```
**Impact**:
- Uploaded SVG/HTML becomes stored XSS on the app origin; traversal via `../`.

## 16. JWT Algorithm-Confusion / none Bypass

### 16.1 Verification Fails Open
**Location**: `backend/auth.py` (`_decode_token`)
```python
try:
    return jwt.decode(token, 'secret', algorithms=['HS256'])
except Exception:
    return jwt.decode(token, options={'verify_signature': False, 'verify_exp': False},
                      algorithms=['HS256', 'none'])   # accepts forged/unsigned tokens
```
**Impact**:
- Forge `{"alg":"none","user_id":1}` to impersonate any user. PoC: `docs/exploits/jwt_forge.py`.

## 17. Insecure Password Reset

### 17.1 Predictable Token + Host-Header Poisoning
**Location**: `backend/routes/auth_routes.py` (`/api/forgot-password`, `/api/reset-password`)
```python
token = hashlib.md5(username.encode()).hexdigest()        # predictable from public username
reset_link = f"http://{request.headers.get('Host')}/...token={token}"  # host injection
if token != hashlib.md5(username.encode()).hexdigest():   # no expiry, no ownership proof
    ...
```
**Impact**:
- Account takeover with no email access; reset links can be poisoned to an attacker host.

## 18. Broken Access Control in Money Transfers

### 18.1 Client-Controlled Payer + Unvalidated Amounts + Race Condition
**Location**: `backend/routes/transaction_routes.py` (`/api/split-bill`, `/api/transfer`)
```python
from_user_id = data.get('from_user_id')   # payer taken from request -> pull from any account
payer.balance -= amount                    # negative/overflow amounts unvalidated
# /api/transfer check-then-act is non-atomic under SQLite autocommit (app.py) -> double-spend
```
**Impact**:
- Theft from arbitrary accounts, money creation via negative amounts, overdraft via the
  race condition. PoC: `docs/exploits/race_double_spend.py`.

## Remediation Summary

For secure implementations and fixes, refer to:
1. [Module 3: Auth & Authz](../course/modules/03_auth_and_authz.md)
2. [Module 4: SQL Injection](../course/modules/04_sql_injection.md)
3. [Module 5: Input Validation](../course/modules/05_input_validation.md)
4. [Module 6: API Security](../course/modules/06_api_security.md)
5. [Module 7: Secure Coding](../course/modules/07_secure_coding.md)
6. [Module 9: CSRF & Clickjacking](../course/modules/09_csrf_and_clickjacking.md)
7. [Module 10: Stored XSS & File Upload](../course/modules/10_xss_and_file_upload.md)
8. [Module 11: Auth Bypass & Business Logic](../course/modules/11_auth_bypass_and_business_logic.md)

⚠️ **Remember**: This is a deliberately vulnerable application for educational purposes. Never use these patterns in production code. 
