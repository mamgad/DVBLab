# Module 8: Automated Static Analysis with Semgrep

## Overview
Static analysis inspects source code without running it, flagging security bugs and bad patterns by matching code structure and data flow. It catches issues that manual review and dynamic testing often miss.

## What is Semgrep?
Semgrep (Semantic Grep) is a fast, open-source static analysis tool. It is language-aware: rules look like the code you are searching for, but match on structure rather than raw text, so it finds vulnerabilities that plain `grep` cannot.

## Installation
```bash
pip install semgrep
```

## Basic Usage
```bash
# Scan a directory with a ruleset
semgrep --config "p/python" backend/

# Machine-readable output
semgrep --config "p/python" backend/ --json > results.json
semgrep --config "p/python" backend/ --sarif > results.sarif
```

## Real-World Example: Scanning Our Banking Application
Running `semgrep --config "p/python" backend/` from the repo root produces (numbers below are from this repo and will drift as code changes):

```
Ran 151 rules on 8 files: 38 findings.
```

The findings below are the highest-impact ones, each tied to the real file and the Semgrep rule id that flags it.

### 1. Weak Password Hashing (MD5)
**Location**: `backend/models.py:26-30`
**Rule**: `python.lang.security.audit.md5-used-as-password.md5-used-as-password`, `python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5` (CWE-327/CWE-916)
```python
# ❌ Vulnerable Code (backend/models.py)
def set_password(self, password):
    self.password_hash = hashlib.md5(password.encode()).hexdigest()

def check_password(self, password):
    return self.password_hash == hashlib.md5(password.encode()).hexdigest()

# ✅ Secure Fix — use a salted, slow password hash
from werkzeug.security import generate_password_hash, check_password_hash

def set_password(self, password):
    self.password_hash = generate_password_hash(password)  # PBKDF2 + salt

def check_password(self, password):
    return check_password_hash(self.password_hash, password)
```

**Risk**: MD5 is fast and unsalted, so stolen hashes fall to GPU brute force and precomputed rainbow tables. A purpose-built hash (`werkzeug.security`, or `bcrypt`) adds a per-user salt and a tunable work factor.

### 2. Insecure YAML Deserialization
**Location**: `backend/routes/auth_routes.py:218`
**Rule**: `python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load` (CWE-502)
```python
# ❌ Vulnerable Code (backend/routes/auth_routes.py)
profile_data = yaml.load(profile_yaml, Loader=yaml.Loader)

# ✅ Secure Fix — only construct plain data types
profile_data = yaml.safe_load(profile_yaml)
```

**Risk**: `yaml.Loader` constructs arbitrary Python objects, so attacker-supplied YAML (e.g. `!!python/object/apply:os.system`) runs commands on the server. `yaml.safe_load` parses only basic types.

### 3. JWT Security Issues
**Location**: `backend/auth.py:20-29`
**Rules**: `python.jwt.security.jwt-none-alg.jwt-python-none-alg`, `python.jwt.security.unverified-jwt-decode.unverified-jwt-decode`, `python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret` (CWE-347)
```python
# ❌ Vulnerable Code (backend/auth.py)
def _decode_token(token):
    try:
        # hardcoded secret
        return jwt.decode(token, 'secret', algorithms=['HS256'])
    except Exception:
        # INSECURE FALLBACK: accepts unsigned / alg:none tokens
        return jwt.decode(
            token,
            options={'verify_signature': False},
            algorithms=['HS256', 'none'],
        )

# ✅ Secure Fix — no fallback, secret from env, algorithm pinned
import os
JWT_SECRET = os.environ['JWT_SECRET']

def _decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
```

**Risk**: This is worse than a hardcoded secret. The `except` branch re-decodes the token with `verify_signature` off and `none` allowed, so an attacker can forge any payload (e.g. `{"user_id": 1, "alg": "none"}`) and impersonate any user. The fix must remove the fallback, pin `algorithms=['HS256']`, and load the secret from the environment.

### 4. SQL Injection
**Location**: `backend/routes/transaction_routes.py:93` (also `backend/routes/auth_routes.py:36`)
**Rule**: `python.flask.security.injection.tainted-sql-string.tainted-sql-string` (CWE-89)
```python
# ❌ Vulnerable Code (backend/routes/transaction_routes.py)
query = f"SELECT * FROM \"transaction\" WHERE ... description LIKE '%{search_term}%'"

# ✅ Secure Fix — parameterized query
from sqlalchemy import text
query = text("SELECT * FROM \"transaction\" WHERE description LIKE :term")
db.session.execute(query, {'term': f'%{search_term}%'})
```

**Risk**: User input concatenated into SQL lets an attacker read or modify the whole database.

### 5. Hardcoded Secret Key
**Location**: `backend/app.py:18`
```python
# ❌ Vulnerable Code (backend/app.py)
app.config['SECRET_KEY'] = 'supersecret'

# ✅ Secure Fix
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
```

**Risk**: A secret committed to source control is readable by anyone with repo access and enables session/token forgery.

### 6. Debug Mode in Production
**Location**: `backend/app.py:232`
**Rule**: `python.flask.security.audit.debug-enabled.debug-enabled` (CWE-489)
```python
# ❌ Vulnerable Code (backend/app.py)
app.run(host='0.0.0.0', debug=True, port=5000)

# ✅ Secure Fix
debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
app.run(host='0.0.0.0', debug=debug, port=5000)
```

**Risk**: Flask debug mode exposes stack traces and the Werkzeug interactive debugger (remote code execution if the PIN is bypassed).

### Also worth noting
- **Reflected-origin CORS** — `backend/app.py:49-58` reflects any `Origin` back in `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true` (CWE-942). Confirmed by manual review; `p/python` does not ship a dedicated rule for it. Fix: allow-list specific origins.

## Understanding Semgrep Results
From the scan above (`semgrep --config "p/python" backend/`):

- Files scanned: 8 (git-tracked Python files under `backend/`)
- Rules run: 151
- Findings: 38 (all blocking)

Note: counts depend on the ruleset, the Semgrep version, and which files are tracked by git, so treat them as a snapshot, not a fixed figure. By rule, the headline issues include MD5 password hashing, JWT `none`-algorithm decode, PyYAML insecure load, tainted-string SQL injection, and Flask `debug=True` (**1 instance**, at `app.py:232`).

## Remediation
Each finding above includes its own **Secure Fix** block — apply those directly. The recurring theme: load secrets from the environment, use parameterized queries / ORM, use `safe_load` and salted password hashes, and never disable signature verification.

## Additional Resources
1. [Semgrep Official Documentation](https://semgrep.dev/docs/)
2. [Semgrep Rule Registry](https://semgrep.dev/explore)
3. [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
