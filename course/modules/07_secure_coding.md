# Module 7: Secure Coding Practices

## Overview

This module covers essential secure coding practices for banking applications, focusing on password security, secure logging practices, and maintaining transaction integrity.

## Password Security

### Secure Password Storage

```python
# ❌ Insecure password storage
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# ✅ Secure password storage using modern hashing
from werkzeug.security import generate_password_hash

def store_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256:260000')
```

### Password Validation

```python
# ❌ Weak password requirements
def is_valid_password(password):
    return len(password) >= 8

# ✅ Strong password requirements
import re

def is_valid_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True
```

## Secure Logging

### Sensitive Data Handling

```python
# ❌ Insecure logging
def log_transaction(user, amount, account):
    logging.info(f"Transfer: {user.username}, Amount: {amount}, Account: {account}")

# ✅ Secure logging
def log_transaction(user, amount, account):
    logging.info(f"Transfer by user ID: {user.id}")
    logging.debug(f"Details: Amount: {mask_amount(amount)}, Account: {mask_account(account)}")

def mask_account(account):
    return f"****{account[-4:]}"

def mask_amount(amount):
    return f"Amount: {len(str(amount)) * '*'}"
```

### Audit Logging

```python
# ✅ Comprehensive audit logging
class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('audit')
        
    def log_action(self, user_id, action, status, details=None):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'action': action,
            'status': status,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        }
        if details:
            log_entry['details'] = self.sanitize_details(details)
        
        self.logger.info(json.dumps(log_entry))
    
    def sanitize_details(self, details):
        sensitive_fields = ['password', 'token', 'account_number']
        return {k: '****' if k in sensitive_fields else v 
                for k, v in details.items()}
```

## Transaction Integrity

### Atomic Transactions

```python
# ❌ Non-atomic transaction
def transfer_money(from_account, to_account, amount):
    from_account.balance -= amount
    to_account.balance += amount
    db.session.commit()

# ✅ Atomic transaction with rollback
from sqlalchemy import transaction

def transfer_money(from_account, to_account, amount):
    try:
        with db.session.begin_nested():
            from_account.balance -= amount
            to_account.balance += amount
            
            if from_account.balance < 0:
                raise ValueError("Insufficient funds")
                
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise TransactionError(f"Transfer failed: {str(e)}")
```

### Race Condition Prevention

```python
# ❌ Vulnerable to race conditions
def process_payment(account_id, amount):
    account = Account.query.get(account_id)
    if account.balance >= amount:
        account.balance -= amount
        db.session.commit()
        return True
    return False

# ✅ Race condition safe
from sqlalchemy import and_, update

def process_payment(account_id, amount):
    result = db.session.execute(
        update(Account)
        .where(and_(
            Account.id == account_id,
            Account.balance >= amount
        ))
        .values(balance=Account.balance - amount)
        .returning(Account.id)
    )
    db.session.commit()
    return result.rowcount > 0
```

## Error Handling

### Secure Exception Handling

```python
# ❌ Insecure error handling
def api_endpoint():
    try:
        # ... operation ...
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ✅ Secure error handling
class SecureAPIError(Exception):
    def __init__(self, message, code=500):
        self.message = message
        self.code = code

def api_endpoint():
    try:
        # ... operation ...
    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        raise SecureAPIError("Invalid input", 400)
    except Exception as e:
        logger.error(f"Internal error: {str(e)}")
        raise SecureAPIError("An internal error occurred")
```

## Secure Configuration

### Environment Variables

```python
# ❌ Hardcoded configuration
DATABASE_URL = "postgresql://user:password@localhost/db"
SECRET_KEY = "your-secret-key"

# ✅ Secure configuration
from os import environ
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = environ.get('DATABASE_URL')
SECRET_KEY = environ.get('SECRET_KEY')

if not all([DATABASE_URL, SECRET_KEY]):
    raise EnvironmentError("Missing required environment variables")
```

## Input Sanitization

### XSS Prevention

```python
# ❌ Vulnerable to XSS
def save_comment(user_input):
    return f"<div>{user_input}</div>"

# ✅ XSS prevention
import bleach

def save_comment(user_input):
    allowed_tags = ['p', 'br', 'strong', 'em']
    allowed_attrs = {}
    return bleach.clean(
        user_input,
        tags=allowed_tags,
        attributes=allowed_attrs
    )
```

## Security Headers

### Implementation

```python
# ✅ Security headers middleware
class SecurityHeaders:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def security_headers(status, headers, exc_info=None):
            headers.extend([
                ('Content-Security-Policy', 
                 "default-src 'self'; script-src 'self'"),
                ('X-Content-Type-Options', 'nosniff'),
                ('X-Frame-Options', 'DENY'),
                ('X-XSS-Protection', '1; mode=block'),
                ('Strict-Transport-Security',
                 'max-age=31536000; includeSubDomains')
            ])
            return start_response(status, headers, exc_info)
        
        return self.app(environ, security_headers)
```

## Secure File Operations

### Safe File Handling

```python
# ❌ Unsafe file operations
def save_user_file(filename, content):
    with open(filename, 'wb') as f:
        f.write(content)

# ✅ Secure file operations
import os
from werkzeug.utils import secure_filename

def save_user_file(filename, content):
    safe_filename = secure_filename(filename)
    allowed_extensions = {'.pdf', '.txt', '.doc', '.docx'}
    
    if not os.path.splitext(safe_filename)[1].lower() in allowed_extensions:
        raise ValueError("Invalid file type")
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    # Prevent path traversal
    if not os.path.abspath(file_path).startswith(
        os.path.abspath(app.config['UPLOAD_FOLDER'])
    ):
        raise ValueError("Invalid file path")
        
    with open(file_path, 'wb') as f:
        f.write(content)
```

## Best Practices

### 1. Code Organization
- Follow separation of concerns
- Use proper error handling
- Implement input validation
- Apply principle of least privilege

### 2. Database Security
- Use parameterized queries
- Implement proper access controls
- Maintain data integrity
- Regular backups

### 3. Authentication
- Implement MFA where possible
- Use secure session management
- Apply proper password policies
- Regular security audits

### 4. Logging and Monitoring
- Implement comprehensive logging
- Monitor suspicious activities
- Regular security reviews
- Incident response planning

## Conclusion

### Key Takeaways
1. Always validate and sanitize input
2. Use secure password storage
3. Implement proper error handling
4. Maintain transaction integrity
5. Follow security best practices

### Next Steps
1. Review existing codebase
2. Implement security improvements
3. Add security testing
4. Monitor and log security events
5. Keep dependencies updated

### Additional Resources
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Python Security Documentation](https://docs.python.org/3/library/security.html)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.0.x/security/)
- [Web Security Cheat Sheet](https://cheatsheetseries.owasp.org/) 