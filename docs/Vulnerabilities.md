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

## Remediation Summary

For secure implementations and fixes, refer to:
1. [Module 3: Auth & Authz](../course/modules/03_auth_and_authz.md)
2. [Module 4: SQL Injection](../course/modules/04_sql_injection.md)
3. [Module 5: Input Validation](../course/modules/05_input_validation.md)
4. [Module 6: API Security](../course/modules/06_api_security.md)
5. [Module 7: Secure Coding](../course/modules/07_secure_coding.md)

⚠️ **Remember**: This is a deliberately vulnerable application for educational purposes. Never use these patterns in production code. 
