# Module 7: Secure Coding Practices

## Understanding Secure Coding

### What is Secure Coding?
Secure coding is the practice of writing code that is resistant to attack and protects:
- Data confidentiality
- System integrity
- Service availability
- User privacy
- Business logic

### Core Secure Coding Principles

1. **Input Validation**
   - Never trust user input
   - Validate at all layers
   - Use whitelisting
   - Type checking

2. **Output Encoding**
   - Context-specific encoding
   - Character escaping
   - Safe rendering
   - Content security

3. **Authentication & Authorization**
   - Strong authentication
   - Proper session management
   - Least privilege
   - Access controls

4. **Data Protection**
   - Encryption at rest
   - Secure transmission
   - Key management
   - Data minimization

### Common Secure Coding Mistakes

1. **Security Through Obscurity**
   - Hidden functionality
   - Hardcoded secrets
   - Custom encryption
   - Undocumented features

2. **Implicit Trust**
   - Client-side validation
   - Internal requests
   - System files
   - Environment variables

3. **Poor Error Handling**
   - Stack traces exposed
   - Sensitive data in logs
   - Inconsistent errors
   - Debug information

## DVBank Secure Coding Issues

### 1. Insecure Transaction Processing
**Location**: `backend/routes/transaction_routes.py`
```python
@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer():
    # No transaction atomicity
    # No balance validation
    # No rollback handling
    
    from_account.balance -= amount
    db.session.commit()
    
    to_account.balance += amount
    db.session.commit()
```

**Impact**:
- Race conditions
- Inconsistent state
- Balance manipulation
- Lost transactions

**Exploitation**:
```python
# Race condition attack
def race_attack():
    balance = 100
    for _ in range(10):
        Thread(target=lambda: transfer(
            from_account='victim',
            to_account='attacker',
            amount=balance
        )).start()
```

### 2. Unsafe Password Reset
**Location**: `backend/routes/auth_routes.py`
```python
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    # No rate limiting
    # No token expiration
    # No secure token
    
    token = generate_reset_token()  # Predictable
    send_reset_email(email, token)
```

**Impact**:
- Token prediction
- Email enumeration
- Rate limit bypass
- Account takeover

**Exploitation**:
```python
# Token prediction attack
import time

def predict_token():
    email = 'victim@example.com'
    timestamp = int(time.time())
    predicted = f"{email}:{timestamp}"
    return md5(predicted.encode()).hexdigest()
```

### 3. Unsafe File Operations
**Location**: `backend/routes/document_routes.py`
```python
@app.route('/api/export', methods=['POST'])
@login_required
def export_data():
    filename = request.json.get('filename')
    data = get_user_data()
    
    # Unsafe file operations
    with open(f'exports/{filename}', 'w') as f:
        f.write(data)
```

**Impact**:
- Path traversal
- File overwrite
- Data exposure
- System access

**Exploitation**:
```python
# Path traversal attack
payload = {
    'filename': '../../../etc/passwd'
}

# File overwrite
payload = {
    'filename': '../config.py'
}
```

## Prevention Methods

### 1. Secure Transaction Handling
```python
from sqlalchemy import and_
from contextlib import contextmanager

@contextmanager
def atomic_transaction():
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise TransactionError(str(e))

def transfer_money(from_account, to_account, amount):
    with atomic_transaction():
        # Lock accounts for update
        from_acc = Account.query.with_for_update().get(from_account)
        to_acc = Account.query.with_for_update().get(to_account)
        
        # Validate balances
        if from_acc.balance < amount:
            raise InsufficientFunds("Insufficient balance")
            
        # Update balances
        from_acc.balance -= amount
        to_acc.balance += amount
        
        # Create transaction record
        Transaction.create(
            from_account=from_account,
            to_account=to_account,
            amount=amount,
            status='completed'
        )
```

### 2. Secure Password Reset
```python
from secrets import token_urlsafe
from datetime import datetime, timedelta

def generate_reset_token():
    return token_urlsafe(32)

def store_reset_token(user_id, token):
    expiry = datetime.utcnow() + timedelta(hours=1)
    ResetToken.create(
        user_id=user_id,
        token=token,
        expires_at=expiry
    )

@limiter.limit("3 per hour")
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        
        # Don't reveal if email exists
        if not user:
            return jsonify({'message': 'If email exists, reset link sent'})
            
        token = generate_reset_token()
        store_reset_token(user.id, token)
        send_reset_email(email, token)
        
        return jsonify({'message': 'If email exists, reset link sent'})
    except Exception as e:
        log_error(e)  # Log for monitoring
        return jsonify({'message': 'If email exists, reset link sent'})
```

### 3. Safe File Operations
```python
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'secure_uploads'
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'csv'}

def safe_file_operation(filename, data, operation='write'):
    # Secure the filename
    safe_name = secure_filename(filename)
    
    # Ensure path is within allowed directory
    full_path = os.path.join(UPLOAD_FOLDER, safe_name)
    if not os.path.abspath(full_path).startswith(
        os.path.abspath(UPLOAD_FOLDER)
    ):
        raise SecurityError("Invalid path")
        
    # Perform operation
    if operation == 'write':
        with open(full_path, 'w') as f:
            f.write(data)
    elif operation == 'read':
        with open(full_path, 'r') as f:
            return f.read()
            
    return safe_name

@app.route('/api/export', methods=['POST'])
@login_required
def export_data():
    try:
        filename = request.json.get('filename')
        data = get_user_data()
        
        safe_name = safe_file_operation(filename, data)
        return jsonify({'filename': safe_name})
    except SecurityError as e:
        return jsonify({'error': str(e)}), 400
```

## Practice Exercises

1. **Transaction Security**
   - Implement atomicity
   - Add deadlock handling
   - Test race conditions
   - Add audit logging

2. **Password Management**
   - Secure reset flow
   - Token generation
   - Rate limiting
   - Expiry handling

3. **File Security**
   - Path validation
   - Safe operations
   - Access control
   - Upload security

## Additional Resources

1. [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
2. [Python Security Guide](https://python-security.readthedocs.io/)
3. [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.0.x/security/)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 