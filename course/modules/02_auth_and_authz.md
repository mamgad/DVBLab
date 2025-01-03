# Module 2: Authentication & Authorization Vulnerabilities

## Overview
This module covers authentication and authorization vulnerabilities in our banking application, focusing on JWT implementation, session management, and access control issues.

## Vulnerable Code Examples

### 1. Weak JWT Implementation
From our `auth_routes.py`:

```python
token = jwt.encode(
    {
        'user_id': user[0],
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=1)
    },
    'secret',  # Hardcoded secret key
    algorithm='HS256'
)
```

Issues:
1. Hardcoded secret key
2. Long expiration time
3. Minimal token claims
4. No token refresh mechanism

### 2. Insecure Access Control
From our `transaction_routes.py`:

```python
@transaction_bp.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    user_id = request.args.get('user_id', current_user.id)
    
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | 
        (Transaction.receiver_id == user_id)
    ).order_by(Transaction.created_at.desc()).all()
```

Issues:
1. No proper authorization check
2. IDOR vulnerability
3. No rate limiting

## Proof of Concept (PoC)

### Attack 1: JWT Token Manipulation
```python
import jwt

# Decode existing token
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
decoded = jwt.decode(token, options={"verify_signature": False})

# Modify claims
decoded['user_id'] = 1  # Admin user ID
decoded['role'] = 'admin'

# Create new token with same signature
new_token = jwt.encode(decoded, 'secret', algorithm='HS256')
```

### Attack 2: IDOR Exploitation
```bash
# Legitimate user's transactions
curl http://localhost:5000/api/transactions?user_id=1 \
  -H "Authorization: Bearer <valid_token>"

# Accessing another user's transactions
curl http://localhost:5000/api/transactions?user_id=2 \
  -H "Authorization: Bearer <valid_token>"
```

## Impact
1. Account takeover
2. Privilege escalation
3. Data privacy breach
4. Financial fraud
5. Regulatory compliance issues

## Secure Implementation

### 1. Proper JWT Configuration
```python
# Config file
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)

# JWT Creation
token = jwt.encode(
    {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRES,
        'iat': datetime.utcnow(),
        'jti': str(uuid.uuid4())
    },
    JWT_SECRET_KEY,
    algorithm='HS256'
)
```

### 2. Proper Access Control
```python
@transaction_bp.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    user_id = request.args.get('user_id', current_user.id)
    
    # Proper authorization check
    if int(user_id) != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | 
        (Transaction.receiver_id == user_id)
    ).order_by(Transaction.created_at.desc()).all()
```

## Prevention Techniques
1. JWT Security:
   - Use strong, environment-specific secrets
   - Short token expiration times
   - Implement token refresh mechanism
   - Include necessary claims
   - Use proper algorithms

2. Access Control:
   - Implement Role-Based Access Control (RBAC)
   - Always verify user permissions
   - Use secure session management
   - Implement proper logout mechanism

3. Additional Security:
```python
# Rate limiting
@limiter.limit("5 per minute")
@auth_bp.route('/api/login', methods=['POST'])

# Request validation
def validate_transaction_request(user_id, amount):
    if not user_id or not isinstance(user_id, int):
        return False
    if not amount or not isinstance(amount, (int, float)):
        return False
    return True
```

## Practice Exercise
1. Implement a JWT refresh token mechanism
2. Add role-based access control
3. Create tests for authorization checks
4. Implement proper session management

## Additional Resources
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [OWASP ASVS - Authentication Verification Requirements](https://owasp.org/www-project-application-security-verification-standard/) 