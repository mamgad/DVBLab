# Module 7: Secure Coding Practices

## Understanding Secure Coding
Secure coding is the practice of writing code that resists attack and protects data confidentiality, integrity, availability, and user privacy. The core principles:

- **Input validation** - never trust user input; validate type and range at every layer.
- **Output encoding** - escape data for the context it lands in (HTML, SQL, shell).
- **Authentication & authorization** - strong auth, least privilege, enforced access control.
- **Data protection** - encrypt secrets at rest and in transit; minimize what you store.

Common mistakes that introduce vulnerabilities include hardcoding secrets, trusting client-side validation, and leaking stack traces or debug output in error responses. The DVBank examples below show each of these in real code.

## DVBank Secure Coding Issues
Let's examine real security vulnerabilities in DVBank that arise from insecure coding practices. These examples demonstrate how seemingly minor coding decisions can lead to significant security issues.

### 1. Insecure Transaction Processing
**Location**: `backend/routes/transaction_routes.py:9-37`
```python
@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    amount = Decimal(str(data.get('amount', 0)))

    receiver = User.query.get(to_user_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404

    # Builds the record, then checks balance, then mutates -- minimal
    # validation (no amount/atomicity checks), classic read-then-write race.
    transaction = Transaction(sender_id=current_user.id, receiver_id=receiver.id,
                              amount=amount, status='completed')
    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    current_user.balance -= amount
    receiver.balance += amount
    db.session.add(transaction)
    db.session.commit()
```

**Impact**:
- The balance check and the balance update are not atomic, so concurrent transfers can each pass the check before either commits (TOCTOU race / double-spend).
- `amount` is never validated: a negative value `-= amount` increases the sender's balance and decreases the receiver's, so a user can drain other accounts or mint money.
- Minimal validation (no amount/atomicity checks). The receiver 404 check exists, but there is no positive-amount or numeric-bounds check.

**Exploitation**:
```python
# Race condition attack
def exploit_race_condition():
    # Login as attacker
    token = login('attacker', 'password123')
    
    # Start multiple concurrent transfers
    def make_transfer():
        requests.post('/api/transfer', 
            json={
                'to_user_id': VICTIM_ID,
                'amount': 100
            },
            headers={'Authorization': f'Bearer {token}'}
        )
    
    # Execute transfers concurrently
    threads = []
    for _ in range(10):
        t = Thread(target=make_transfer)
        t.start()
        threads.append(t)
```

### 2. Unsafe Transaction History Query
**Location**: `backend/routes/transaction_routes.py`
```python
@transaction_bp.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    user_id = request.args.get('user_id', current_user.id)
    
    # Direct string interpolation - SQL Injection
    query = f'SELECT * FROM "Transaction" WHERE sender_id = {user_id} OR receiver_id = {user_id} ORDER BY created_at DESC'
    result = db.session.execute(query)
    transactions = result.fetchall()
```

**Impact**:
- SQL injection vulnerability enables unauthorized access
- Potential exposure of all transaction records
- Risk of transaction history manipulation
- Compromise of financial data privacy

**Exploitation**:
```python
# /api/transactions is @token_required, so a valid Bearer token is needed.
headers = {'Authorization': f'Bearer {token}'}

# Boolean injection: view all transactions, not just your own
payload = "1 OR 1=1 -- "
response = requests.get(f'/api/transactions?user_id={payload}', headers=headers)

# UNION attack: the base query is SELECT * FROM "Transaction" (8 columns),
# so the UNION must also select 8 columns. The table `user` is lowercase.
# balance lands at t[3], which the handler runs through float(t[3]).
payload = "1 UNION SELECT id,username,password_hash,balance,NULL,NULL,NULL,NULL FROM user-- "
response = requests.get(f'/api/transactions?user_id={payload}', headers=headers)
```

### 3. Hardcoded JWT Secret + No Authorization Check
**Location**: `backend/routes/auth_routes.py:48`, `backend/auth.py:22`
```python
# auth_routes.py - tokens are signed with the literal 'secret' (no constant,
# it is inlined at the encode call):
token = jwt.encode({'user_id': user[0], 'username': username, ...},
                   'secret', algorithm='HS256')

# auth.py - the same literal is used to verify:
return jwt.decode(token, 'secret', algorithms=['HS256'])
```

**Impact**:
- The signing key is in source (and version control), so anyone can forge a valid token for any `user_id`.
- The admin endpoints in `admin_routes.py` have NO role check ("any authenticated user has access"), so any forged token reaches them.
- `auth.py:_decode_token` (lines 20-29) also falls back to decoding **without** verifying the signature when HS256 verification fails, enabling an additional `alg:none` bypass even if the secret were unknown.

**Exploitation**:
```python
import jwt, requests

# Forge a token for any user; user_id 1 is alice (role 'user' -- there is no
# seeded admin, but no endpoint checks the role anyway).
token = jwt.encode({'user_id': 1}, 'secret', algorithm='HS256')

# Reach a real admin endpoint -- /api/admin/users dumps every user including
# password hashes; /api/admin/dashboard-data leaks the hardcoded API/AWS keys.
headers = {'Authorization': f'Bearer {token}'}
response = requests.get('/api/admin/users', headers=headers)
```

### 4. Debug Mode and Leaky Error Messages
**Location**: `backend/app.py:232` and `backend/app.py:74-77`
```python
# app.py:232 - debug mode is on (CWE-489): exposes the interactive Werkzeug
# debugger, which allows arbitrary code execution via its console on any
# unhandled exception.
app.run(host='0.0.0.0', debug=True, port=5000)

# app.py:74-77 - the 500 handler returns the raw exception string (CWE-209).
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': str(error)}), 500   # str(error) can leak internals
```

**Impact**:
- `debug=True` enables the Werkzeug debugger; reaching it on an unhandled error gives an attacker a Python console (RCE) on the server.
- The 500 handler echoes `str(error)`, so internal details (SQL fragments, file paths, type errors) can leak into responses. The 404 handler does the same with `str(error)`.

**Exploitation**:
```python
# Send input that triggers an unhandled exception in a handler (e.g. a body
# that breaks Decimal()/SQL parsing) to surface the raw error string, or -- in
# debug mode -- the interactive Werkzeug traceback/console page.
# Note: /api/transactions/<int:...> 404s at routing for non-integer ids
# (the <int:> converter rejects them), so that path does not reach a 500.
```

## Prevention Methods
Implementing secure coding practices helps prevent vulnerabilities. Here are examples of proper implementations:

### 1. Secure Transaction Processing
```python
from sqlalchemy import and_
from contextlib import contextmanager

@contextmanager
def atomic_transaction():
    """Ensure transaction atomicity with proper rollback"""
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise TransactionError(str(e))

def validate_transfer(sender, receiver, amount):
    """Validate transfer parameters"""
    if not isinstance(amount, Decimal):
        raise ValidationError("Invalid amount type")
    if amount <= 0:
        raise ValidationError("Amount must be positive")
    if sender.balance < amount:
        raise InsufficientFunds("Insufficient balance")
    if not receiver:
        raise ValidationError("Invalid receiver")

@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    try:
        data = request.get_json()
        amount = Decimal(str(data.get('amount', 0)))
        receiver = User.query.get(data.get('to_user_id'))
        
        # Validate transfer
        validate_transfer(current_user, receiver, amount)
        
        # Execute transfer atomically
        with atomic_transaction():
            # Lock accounts for update.
            # NOTE: with_for_update() is a NO-OP on SQLite (DVBank's DB) -- it
            # has no row-level locking. It only works on a backend that supports
            # it, e.g. PostgreSQL. On SQLite, prevent the race with a conditional
            # UPDATE that fails atomically when funds are short, e.g.
            #   UPDATE user SET balance = balance - :amt
            #   WHERE id = :sender AND balance >= :amt
            # and check rowcount, or serialize writes (single writer / queue).
            sender = User.query.with_for_update().get(current_user.id)
            receiver = User.query.with_for_update().get(receiver.id)
            
            # Perform transfer
            sender.balance -= amount
            receiver.balance += amount
            
            # Create transaction record
            transaction = Transaction(
                sender_id=sender.id,
                receiver_id=receiver.id,
                amount=amount,
                status='completed',
                completed_at=datetime.utcnow()
            )
            db.session.add(transaction)
            
        return jsonify({
            'message': 'Transfer successful',
            'transaction': transaction.to_dict()
        })
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        log_error(e)  # Secure error logging
        return jsonify({'error': 'Transfer failed'}), 500
```

### 2. Secure Transaction Query
```python
from sqlalchemy import or_

@transaction_bp.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    # Use SQLAlchemy ORM instead of raw SQL
    transactions = Transaction.query.filter(
        or_(
            Transaction.sender_id == current_user.id,
            Transaction.receiver_id == current_user.id
        )
    ).order_by(Transaction.created_at.desc()).all()
    
    return jsonify([t.to_dict() for t in transactions])
```

### 3. Secure Configuration
```python
# config.py
import os
from datetime import timedelta

class Config:
    # Load secrets from environment variables, never hardcode them.
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SIGNING_KEY = os.getenv('JWT_SIGNING_KEY')   # used to sign/verify JWTs
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')

    # Security settings
    TOKEN_EXPIRES = timedelta(hours=1)
    DEBUG = False
    TESTING = False

    def __init__(self):
        if not all([self.SECRET_KEY, self.JWT_SIGNING_KEY, self.SQLALCHEMY_DATABASE_URI]):
            raise EnvironmentError("Missing required environment variables")

# Example .env file
"""
SECRET_KEY=your-secure-secret-key
JWT_SIGNING_KEY=your-secure-jwt-key
DATABASE_URL=sqlite:///production.db
"""
```

### 4. Secure Error Handling
```python
import logging

# Run with debug OFF in production -- never expose the Werkzeug debugger.
app.run(host='0.0.0.0', debug=False, port=5000)

# Fix the 404/500 handlers to log details server-side and return a
# generic message, instead of echoing str(error) to the client.
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logging.error("Unhandled 500", exc_info=True)   # full details to logs only
    return jsonify({'error': 'An internal error occurred'}), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404
```

## Practice Exercises
These hands-on exercises will help you understand and implement secure coding practices:

1. **Transaction Security**
   - Implement proper transaction atomicity
   - Add comprehensive input validation
   - Handle potential race conditions
   - Implement secure audit logging

2. **Query Security**
   - Convert raw SQL to ORM queries
   - Implement parameterized queries
   - Add proper access controls
   - Implement result filtering

3. **Configuration Security**
   - Move secrets to environment variables
   - Implement secret rotation mechanism
   - Add configuration validation
   - Configure secure HTTP headers

4. **Error Handling**
   - Implement secure logging practices
   - Add error message sanitization
   - Create error categorization
   - Set up monitoring alerts

## Additional Resources
1. [OWASP Secure Coding Practices Quick Reference](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
2. [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
3. [SQLAlchemy Security Considerations](https://docs.sqlalchemy.org/en/14/core/security.html)
4. [Bandit](https://bandit.readthedocs.io/) - Python security linter for catching these patterns

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments.
