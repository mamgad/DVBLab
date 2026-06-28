# Module 0: Secure Code Review Methodology

## 1. Introduction to Secure Code Review

### 1.1 What is Secure Code Review?
Secure code review is a systematic examination of source code to find security vulnerabilities before they reach production. In DVBank we focus the review on the security-critical paths: authentication (`auth.py`), money movement (`routes/transaction_routes.py`), and data access (`models.py`, raw SQL in the route files).

### 1.2 Types of Code Review Approaches
- **Manual review**: line-by-line reading of critical code (JWT verification in `auth.py`, balance updates in `transaction_routes.py`, the raw-SQL login query in `auth_routes.py`).
- **Automated analysis (SAST)**: tools flag patterns such as SQL injection, unverified JWT decode, and command injection. DVBank's inline comments cite the matching Semgrep rule IDs for each planted bug.
- **Hybrid review**: SAST surfaces candidates; the reviewer manually confirms exploitability and reachability.

## 2. Code Review Methodology

### 2.1 Pre-Review Phase
Understand the architecture (React frontend, Flask backend, SQLite via SQLAlchemy) and define scope. Prioritize the highest-impact components: fund transfer (`/api/transfer`, `/api/split-bill`, `/api/quickpay`) and authentication (`/api/login`, `/api/forgot-password`, the `token_required`/`cookie_auth` decorators).

### 2.2 Review Phase
Examine each critical path for:
- Transaction tampering through parameter manipulation
- Authentication bypass through token/session flaws
- Unauthorized account access (IDOR)
- SQL injection in financial and auth queries
- Stored XSS in transaction/receipt rendering and uploaded files

### 2.3 Exploitation and Verification
Confirm each finding with a concrete PoC and assess impact, for example:
- Move funds out of another user's account
- Forge a token to impersonate any user
- Read any user's transaction history
- Reset another user's password without owning the account

## 3. Source-Sink Analysis

### 3.1 Understanding Source-Sink Methodology
Source-sink analysis tracks untrusted input (sources) to security-sensitive operations (sinks). Key questions: how does data flow across layers, where are the trust boundaries, and where can manipulation affect money or auth?

### 3.2 Identifying Sources (Entry Points)
1. **Transaction sources**
   - `amount` (transfer / split-bill / quickpay request bodies)
   - `to_user_id` and `from_user_id` (split-bill takes the payer from the body)
   - `description` / memo (rendered into the receipt HTML)
   - `user_id` query parameter on `/api/transactions`

2. **Authentication sources**
   - Login credentials (`username`, `password`)
   - JWT in the `Authorization` header and the `session_token` cookie
   - Password-reset `username` / `token`

3. **Profile sources**
   - Profile JSON and the YAML profile import
   - Avatar upload filename

4. **Hidden sources**
   - HTTP `Host` header (used to build the reset link)
   - `Origin` header (reflected by CORS)
   - URL parameters

> Not implemented in DVBank: security questions, MFA codes, and currency selection. Do not look for them — the app has no such fields.

### 3.3 Critical Sinks (Impact Points)
1. **Financial sinks**
   - Balance modifications (`current_user.balance -= amount`, etc.)
   - `Transaction` row inserts / `db.session.commit()`

2. **Authentication sinks**
   - JWT decode/verify (`_decode_token`)
   - Cookie session resolution (`cookie_auth`)
   - Password check (`check_password`, MD5)

3. **Data-operation sinks**
   - Raw SQL passed to `db.session.execute(...)`
   - File read/write (uploads, admin path traversal)
   - `subprocess` / `eval` / `pickle` in admin routes

### 3.4 Attack Paths (Real DVBank Code)
Each path below is keyed to a confirmed source file and CWE.

1. **Negative-amount transfer** — `routes/transaction_routes.py:14,30`
   `amount = Decimal(str(data.get('amount', 0)))` and the only guard is `if current_user.balance < amount`. A negative amount passes the check and inverts the transfer, pulling money from the receiver to the sender. (CWE-840 business-logic flaw.)

2. **Arbitrary-payer split-bill** — `routes/transaction_routes.py:199-213`
   `from_user_id` is read from the request body and never compared to `current_user`, so any authenticated user can debit any account. No amount validation; the balance update is non-atomic. (CWE-639 / CWE-840.)

3. **`user_id` SQLi + IDOR** — `routes/transaction_routes.py:47-49`
   `user_id` from the query string is interpolated straight into the SQL string and is not authorization-checked, giving both SQL injection and an IDOR over other users' transactions. (CWE-89 / CWE-639.) The same f-string pattern appears in `search_transactions` (line 93).

4. **JWT verification bypass** — `auth.py:20-29`
   On any verification error `_decode_token` falls back to decoding with `verify_signature: False` and `none` allowed, so a forged token (e.g. `{"alg":"none"}`) impersonates any `user_id`. (CWE-347.)

5. **CSRF on cookie-authed money movement** — `auth.py:60-88` + `routes/transaction_routes.py:122-148`
   The login response sets `session_token` with no SameSite/HttpOnly (`auth_routes.py:74`), and `cookie_auth` accepts that ambient cookie with no CSRF token, so a cross-site form can drive `/api/quickpay`. (CWE-352.)

6. **Race / double-spend** — non-atomic balance updates in `transaction_routes.py` combined with `app.py:25` (`isolation_level: None`, autocommit). (CWE-362.)

7. **Predictable password reset** — `routes/auth_routes.py` `forgot_password`/`reset_password`
   The reset token is `md5(username)` (CWE-330, guessable, no expiry) and the reset link is built from the client-controlled `Host` header (CWE-644).

8. **Login SQL injection** — `routes/auth_routes.py:36`
   `SELECT * FROM user WHERE username = '{username}'` is built by string interpolation. (CWE-89.)

### 3.5 Research Methodology
1. **Map sources**: enumerate every request body / query / header field that reaches a route.
2. **Map sinks**: list the balance writes, SQL executes, token decodes, and file/process operations.
3. **Trace paths**: connect each source to a sink and note the missing validation or authorization check.
4. **Recognize patterns**: f-string SQL, unverified decode fallbacks, body-supplied identifiers, ambient-cookie auth.

## 4. Security Control Assessment

### 4.1 Authentication Review
- MD5 password hashing (`models.py:26-30`)
- JWT generation with a hardcoded `'secret'` and the unverified-decode fallback (`auth.py`)
- Insecure `session_token` cookie (no SameSite/HttpOnly/Secure)
- Password reset (`auth_routes.py` `forgot_password`/`reset_password`)

> Not implemented in DVBank: multi-factor authentication and account-recovery questions.

### 4.2 Authorization Review
- Missing ownership checks (split-bill payer, `user_id` on `/api/transactions`)
- Admin endpoints with no role check (`routes/admin_routes.py`)
- Token-vs-session decorator coverage (`token_required` vs `cookie_auth`)

### 4.3 Data Validation Review
- Transaction `amount` validation (negative/zero accepted)
- Raw SQL construction in transaction and auth queries
- YAML / file upload handling
- API parameter validation

## 5. Common Application Vulnerabilities

### 5.1 Transaction Security
- Negative-amount transfer (only `balance < amount` is checked) — `transaction_routes.py:14,30`
- Arbitrary-payer split-bill (`from_user_id` from body) — `transaction_routes.py:199-213`
- Race conditions in non-atomic balance updates (`isolation_level=None`)
- CSRF on cookie-authed `/api/quickpay`

> Decimal precision / type-confusion is NOT a DVBank issue: the money path uses `Decimal` and `Numeric(10, 2)` (`models.py:14,53`, `transaction_routes.py:14`). The real money bugs are logic/authorization flaws, listed above.

### 5.2 Data Security
- Sensitive data exposure (SSN in profiles, password hashes in admin responses)
- Insecure direct object references (transactions, admin user routes)
- SQL injection in financial and auth queries
- Cross-site scripting in the receipt page and uploaded files
- Information leakage in error messages

## 6. Documentation and Reporting
For each finding record: a clear description, the affected file/line, a PoC, the impact on banking operations, and a code-level fix. Rate risk by financial impact, data exposure, and exploitation complexity.

## 7. Secure Development Guidelines
Build security in: validate and bound transaction amounts, derive the payer from the authenticated identity, use parameterized queries, verify JWT signatures (no `none` fallback), set secure cookie flags, and add CSRF protection. Back this with security unit/integration tests and SAST in CI.

## 8. Remediation Strategies
Fix at the code level (input validation, authorization checks, parameterized SQL, atomic balance updates), harden configuration (cookie flags, CORS, DB isolation), and re-test each fix with the original PoC to confirm closure.

## 9. Practical Code Review Techniques

### 9.1 Source Code Analysis Tools
- **SAST**: Semgrep (the rule IDs referenced throughout DVBank's inline `# Semgrep rules:` comments) and Bandit for Python.
- **Dynamic analysis**: OWASP ZAP against the React frontend for XSS/CSRF.
- **Dependency scanning**: `npm audit` (frontend) and `safety` (backend).

### 9.2 Manual Review Patterns
**Source code tracing**: follow a value such as `amount` or `user_id` from the request into the balance write or SQL string.

**Critical function analysis**: review the security-critical functions in the real backend files:
- `auth.py` — JWT decode/verify (`_decode_token`, lines 6-31) and cookie session auth (`cookie_auth`, lines 60-88)
- `routes/auth_routes.py` — `login` / `register` (raw-SQL queries) and `forgot_password` / `reset_password`
- `routes/transaction_routes.py` — `transfer`, `split_bill`, `quickpay`, `get_transactions`
- `models.py` — `User` and `Transaction` (MD5 hashing, `Numeric(10, 2)` balances)

**Pattern recognition**:
- Unvalidated input reaching balance writes or SQL strings
- Identifiers taken from the request body instead of the session
- Unverified token decode fallbacks
- Weak crypto (MD5) in authentication

## 10. Closing Checklist
Map each category to the real DVBank code and CWE before signing off:

| Category | Where | CWE |
|----------|-------|-----|
| Negative-amount / no amount validation | `transaction_routes.py:14,30`, `199-213` | CWE-840 |
| Arbitrary-payer business-logic / IDOR | `transaction_routes.py:203`, `47` | CWE-639 |
| SQL injection | `transaction_routes.py:49`, `auth_routes.py:36` | CWE-89 |
| JWT verification bypass | `auth.py:20-29` | CWE-347 |
| CSRF on cookie auth | `auth.py:60-88`, `auth_routes.py:74` | CWE-352 |
| Race / double-spend | `transaction_routes.py` + `app.py:25` (`isolation_level=None`) | CWE-362 |
| Predictable reset token / Host-header link | `auth_routes.py` `forgot_password`/`reset_password` | CWE-330 / CWE-644 |
| Weak password hashing | `models.py:26-30` | CWE-328 |

## Additional Resources
1. [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
2. [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
3. [CWE (MITRE)](https://cwe.mitre.org/)
4. [Semgrep](https://semgrep.dev/) — the SAST tool referenced in DVBank's inline rule comments
5. [Bandit](https://bandit.readthedocs.io/) — Python security linter

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments.
