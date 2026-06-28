# Module 11: Authentication Bypass & Business-Logic Flaws

## Understanding the Attacks

This module covers four flaws that let an attacker either *become* another user
or *abuse the rules* of the banking workflow:

1. **JWT `none`-algorithm bypass** — forging identity by exploiting lax token
   verification.
2. **Insecure password reset** — account takeover via predictable tokens and
   host-header poisoning.
3. **No rate limiting** — unlimited online password guessing.
4. **Money-handling logic flaws** — negative amounts, paying *from* someone
   else's account, and race-condition double-spend.

## Overview

JWTs are only as strong as their verification. Password resets are only as strong
as their token. Auth endpoints need rate limiting. And money endpoints are only
correct if they validate inputs and update balances atomically. DVBank gets all
of these wrong.

## Vulnerable Endpoints

### 1. JWT `none`-algorithm / unverified-signature bypass
**Location**: `backend/auth.py` (`_decode_token`)
```python
try:
    return jwt.decode(token, 'secret', algorithms=['HS256'])
except Exception:
    # INSECURE FALLBACK: accept unsigned / 'none' tokens
    return jwt.decode(token, options={'verify_signature': False, 'verify_exp': False},
                      algorithms=['HS256', 'none'])
```
Any forged token is accepted because verification "fails open."

> 🤔 **Challenge Note**: a JWT is `base64url(header).base64url(payload).signature`.
> For `alg:none` the signature is empty — what does the third segment look like?

**Attack Vector** — `docs/exploits/jwt_forge.py`:
```python
header  = b64url('{"alg":"none","typ":"JWT"}')
payload = b64url('{"user_id":1,"username":"forged"}')
token   = f"{header}.{payload}."        # empty signature -> impersonate user 1
```

### 2. Insecure password reset (predictable token + host-header poisoning)
**Location**: `backend/routes/auth_routes.py`
(`/api/forgot-password`, `/api/reset-password`)
```python
token = hashlib.md5(username.encode()).hexdigest()       # predictable from public username
reset_link = f"http://{request.headers.get('Host')}/reset-password?...token={token}"  # host-injection
...
if token != hashlib.md5(username.encode()).hexdigest():  # no expiry, no ownership proof
    return jsonify({'error': 'Invalid reset token'}), 403
user.set_password(new_password)
```

**Attack Vector** — `docs/exploits/README.md`:
```bash
TOKEN=$(python3 -c "import hashlib;print(hashlib.md5(b'bob').hexdigest())")
curl -X POST .../api/reset-password -d '{"username":"bob","token":"'$TOKEN'","new_password":"pwned123"}'
```

### 3. No login rate limiting / lockout
**Location**: `backend/routes/auth_routes.py` (`/api/login`) — every attempt is
recorded in `LoginAttempt` but nothing throttles or locks the account.

**Attack Vector** — `docs/exploits/brute_force.py` sprays a wordlist; unsalted
MD5 hashing (`models.py`) makes offline cracking trivial too.

### 4. Money-handling business-logic flaws
**Location**: `backend/routes/transaction_routes.py`
```python
# /api/split-bill : payer is taken from the request body, never checked
from_user_id = data.get('from_user_id')          # pull money OUT of any account
payer = User.query.get(from_user_id)
payer.balance -= amount; payee.balance += amount

# /api/transfer : amount is never validated (negative / zero), and the
# check-then-act is non-atomic under SQLite autocommit (app.py isolation_level=None)
if current_user.balance < amount:                 # negative amount bypasses this
    return jsonify({'error': 'Insufficient balance'}), 400
```

> 💡 **Hints for the Challenge**: a *negative* transfer reverses the direction of
> money flow. What does sending `amount: -1000` to `bob` do to *your* balance?

**Attack Vector** — `docs/exploits/race_double_spend.py` fires concurrent
transfers; multiple pass the balance check before any commit, so more transfers
"complete" than the balance could fund.

## Impact Analysis
- Full **account takeover** (JWT forgery, password reset, brute force).
- **Theft from arbitrary accounts** (`split-bill` with someone else's id).
- **Money minted** only by the race condition (lost updates). A *negative*
  transfer is net-zero — it reverses the flow, stealing from / overdrawing the
  **receiver** rather than creating money. Both are direct financial loss.

## Detection Techniques
- Alert on spikes of failed `LoginAttempt` rows per IP/username (brute force).
- Flag inbound JWTs whose header is `alg:none` or whose signature segment is
  empty before trusting the claims.
- Alert when the `Host` header doesn't match the configured domain
  (reset-link poisoning).
- Check ledger invariants: total debits should equal total credits and no balance
  should go negative — violations expose the race condition; transfers where the
  payer ≠ the authenticated user expose the `split-bill` flaw.

## Prevention Methods
- `jwt.decode(token, key, algorithms=['HS256'])` only; reject `none`; rotate to a
  strong secret / asymmetric keys.
- Reset tokens: `secrets.token_urlsafe(32)`, stored hashed, short TTL, one-time;
  build links from a configured `APP_BASE_URL`, not the `Host` header.
- Rate-limit and lock out auth endpoints; hash passwords with bcrypt/argon2.
- Validate amounts (`> 0`, max bound), derive the payer from the *session*, and
  wrap debit+credit in one DB transaction (`SELECT ... FOR UPDATE` / serializable
  isolation).

## Exercises
1. Run `jwt_forge.py` to read `/api/me` as user 1. Then pin
   `algorithms=['HS256']` with no fallback and show the forged token is rejected.
2. Take over `charlie` via the predictable reset token; replace it with
   `secrets.token_urlsafe` + expiry and re-test.
3. Run `race_double_spend.py` and observe more transfers "complete" than the
   balance allows. Wrap the transfer in an atomic transaction and re-run.
4. Send `amount: -1000` via `/api/transfer` and explain the balance change; add
   `if amount <= 0: reject`.

## Additional Resources
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

### Related Tools
- `jwt_tool`, Burp Suite Intruder, `hydra`

### Industry Standards
- CWE-347 (Improper Signature Verification), CWE-640 (Weak Password Recovery),
  CWE-330 (Predictable Value), CWE-644 (Host Header Injection), CWE-307
  (Improper Restriction of Auth Attempts), CWE-362 (Race Condition), CWE-639
  (Authorization Bypass Through User-Controlled Key — the `split-bill` payer),
  CWE-840 (Business Logic Errors)
