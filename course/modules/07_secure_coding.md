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
@transaction_bp.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    amount = Decimal(str(data.get('amount', 0)))
    
    # No transaction atomicity
    # No proper error handling
    # No input validation
    # Race condition vulnerability
    
    receiver = User.query.get(to_user_id)
    if current_user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400  
    
    current_user.balance -= amount
    receiver.balance += amount
    
    db.session.add(transaction)
    db.session.commit()
```

**Impact**:
- Race conditions in balance updates
- Transaction atomicity issues
- Potential balance manipulation
- Missing validation checks

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
- SQL injection vulnerability
- Unauthorized data access
- Transaction history manipulation
- Privacy breach

**Exploitation**:
```python
# SQL injection attack
payload = "1 OR 1=1 --"  # View all transactions
response = requests.get(f'/api/transactions?user_id={payload}')

# Union attack
payload = "1 UNION SELECT id,username,password_hash,balance FROM user--"
response = requests.get(f'/api/transactions?user_id={payload}')
```

### 3. Hardcoded Credentials
**Location**: `backend/app.py`
```python
# Configuration
app.config['SECRET_KEY'] = 'supersecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable_bank.db'

# JWT secret in auth_routes.py
JWT_SECRET = 'secret'
```

**Impact**:
- Credential exposure in source code
- Same secrets across deployments
- No secret rotation
- Version control exposure

**Exploitation**:
```python
# Forge admin JWT token
import jwt
token = jwt.encode(
    {'user_id': 1},  # Admin user ID
    'secret',        # Known JWT secret
    algorithm='HS256'
)

# Use forged token
headers = {'Authorization': f'Bearer {token}'}
response = requests.get('/api/admin', headers=headers)
```

### 4. Debug Mode in Production
**Location**: `backend/app.py`
```python
# Debug mode enabled
app.run(host='0.0.0.0', debug=True, port=5000)

# Stack traces exposed
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc()  # Exposing stack trace
    }), 500
```

**Impact**:
- Stack trace exposure
- Sensitive error details
- Debug information leak
- Security control bypass

**Exploitation**:
```python
# Trigger error to get stack trace
response = requests.get('/api/transactions/invalid')
print(response.json()['traceback'])  # View application internals
```

## Prevention Methods

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
            # Lock accounts for update
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
    # Load from environment variables
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    
    # Security settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    DEBUG = False
    TESTING = False
    
    def __init__(self):
        if not all([self.SECRET_KEY, self.JWT_SECRET_KEY, self.SQLALCHEMY_DATABASE_URI]):
            raise EnvironmentError("Missing required environment variables")

# Example .env file
"""
SECRET_KEY=your-secure-secret-key
JWT_SECRET_KEY=your-secure-jwt-key
DATABASE_URL=sqlite:///production.db
"""
```

### 4. Secure Error Handling
```python
import logging
from werkzeug.exceptions import HTTPException

# Configure secure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@app.errorhandler(Exception)
def handle_error(error):
    # Log error details securely
    if not isinstance(error, HTTPException):
        logging.error(f"Unhandled error: {str(error)}", exc_info=True)
        return jsonify({
            'error': 'An internal error occurred'
        }), 500
    
    # Handle known HTTP errors
    return jsonify({
        'error': error.description
    }), error.code
```

## Practice Exercises

1. **Transaction Security**
   - Implement proper atomicity
   - Add input validation
   - Handle race conditions
   - Add audit logging

2. **Query Security**
   - Convert raw SQL to ORM
   - Add parameterized queries
   - Implement access controls
   - Add result filtering

3. **Configuration Security**
   - Move secrets to environment
   - Implement secret rotation
   - Add validation checks
   - Configure secure headers

4. **Error Handling**
   - Implement secure logging
   - Add error sanitization
   - Create error categories
   - Add monitoring alerts

## Additional Resources

1. [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
2. [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode/SEI+CERT+Coding+Standards)
3. [Python Security Best Practices](https://snyk.io/blog/python-security-best-practices/)
4. [Flask Security Documentation](https://flask.palletsprojects.com/en/2.0.x/security/)
5. [SQLAlchemy Security Considerations](https://docs.sqlalchemy.org/en/14/core/security.html)
6. [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
7. [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html)
8. [Python Secure Development Guide](https://python-security.readthedocs.io/)
9. [Banking Application Security Guidelines](https://www.ffiec.gov/cybersecurity.htm)
10. [OWASP Financial Services Guidelines](https://owasp.org/www-pdf-archive/OWASP_Financial_Services_Guide_July_2013.pdf)

### Related Tools
1. [Bandit](https://bandit.readthedocs.io/) - Python security linter
2. [Safety](https://pyup.io/safety/) - Python dependency checker
3. [PyT](https://github.com/python-security/pyt) - Python security static analysis
4. [Pylint Security Plugin](https://pylint.pycqa.org/en/latest/technical_reference/extensions.html#pylint-security)
5. [SonarQube](https://www.sonarqube.org/) - Code quality and security scanner

### Academic Papers
1. [Secure Coding Practices in Python](https://dl.acm.org/doi/10.1145/3183440.3183441)
2. [Security Code Smells in Banking Applications](https://ieeexplore.ieee.org/document/8445916)
3. [Automated Detection of Security Vulnerabilities](https://link.springer.com/chapter/10.1007/978-3-030-58793-1_18)

### Industry Standards
1. [PCI DSS Secure Coding Requirements](https://www.pcisecuritystandards.org/documents/PCI_Secure_Software_Standard_v1.1.pdf)
2. [ISO/IEC 27034 Application Security](https://www.iso.org/standard/44378.html)
3. [NIST SP 800-53 Security Controls](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)

### Practice Resources
1. [OWASP Security Knowledge Framework](https://www.securityknowledgeframework.org/)
2. [Secure Code Warrior](https://www.securecodewarrior.com/)
3. [PyCQA Security Tools](https://github.com/PyCQA)

### Banking-Specific Resources
1. [FFIEC Information Security Booklet](https://ithandbook.ffiec.gov/it-booklets/information-security.aspx)
2. [Banking Grade Security Framework](https://www.openbanking.org.uk/wp-content/uploads/Security-Profile-Version-1.1.2.pdf)
3. [Financial API Security](https://openid.net/specs/openid-financial-api-part-2-1_0.html)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 